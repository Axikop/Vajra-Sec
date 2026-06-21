"""
Local LLM enrichment via Ollama (Qwen 2.5 3B, Q4_K_M quantized).

Module name is kept as `groq_enricher` for backwards compatibility — the
project originally used Groq's hosted API and the file name stuck. All
calls are now to a local Ollama instance; no data leaves the machine.
Public API is unchanged:

    enrich_cve(cve_id, search_context) -> dict | None
    generate_fofa_query(enriched)      -> str  | None

Setup (one-time):
    1. Install Ollama:  https://ollama.com/download
    2. Pull the model:  ollama pull qwen2.5:7b
    3. Make sure the Ollama service is running (it auto-starts on Windows).

The Q4_K_M quantization is Ollama's default for the 7B tag and gives
the best size/quality trade-off for CPU inference on a 12th gen i7(my laptop).

Endpoint used:  POST {OLLAMA_BASE_URL}/api/chat
"""

import json
import logging
import re
from typing import Optional

import requests

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

logger = logging.getLogger(__name__)

OLLAMA_CHAT_URL = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
MAX_TOKENS      = 600      
KEEP_ALIVE      = "30m"      
NUM_CTX         = 4096
EXTRACTION_PROMPT = """You are a cybersecurity analyst. Given a CVE ID and raw search snippets below, extract structured information about THAT SPECIFIC CVE ONLY.

CRITICAL RULES:
1. Extract data ONLY for the requested CVE ID. If the snippets mention OTHER CVE IDs (e.g. CVE-2024-55591 when you were asked about CVE-2024-21762), IGNORE those — they are unrelated.
2. Output a SINGLE FLAT JSON object. Do NOT nest under keys like "vulnerabilities" or "affected_products".
3. Use EXACTLY these top-level keys: cve_id, affected_versions, fixed_versions, products, severity, description, mitigation. No others.

What to extract:
1. Affected versions — exact strings or ranges from the snippets
2. Fixed/patched versions — look hard for "fixed in", "upgrade to", "resolved in", "addressed in", "Fixed Release", KB numbers
3. Products / vendors affected
4. Severity — Critical / High / Medium / Low / Unknown
5. A one-sentence description of the vulnerability
6. Mitigation advice (or null if none)

OEM-specific hints for fixed_versions:
- Fortinet: "FortiOS 7.x.x and above" or "upgrade to 7.x.x"
- Cisco: "Fixed Release" or "First Fixed Release" columns
- Microsoft: KB article numbers or security update version numbers

If a field has no information, use null or an empty list. Never invent values.

Respond ONLY with the JSON object — no markdown, no commentary."""


ENRICHMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "cve_id":            {"type": "string"},
        "affected_versions": {"type": "array", "items": {"type": "string"}},
        "fixed_versions":    {"type": "array", "items": {"type": "string"}},
        "products":          {"type": "array", "items": {"type": "string"}},
        "severity":          {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Unknown"]},
        "description":       {"type": "string"},
        "mitigation":        {"type": ["string", "null"]},
    },
    "required": [
        "cve_id", "affected_versions", "fixed_versions",
        "products", "severity", "description", "mitigation",
    ],
}


def _ollama_chat(
    system_prompt: str,
    user_message:  str,
    json_mode:     bool = False,
    json_schema:   Optional[dict] = None,
    temperature:   float = 0.1,
    max_tokens:    int = MAX_TOKENS,
) -> Optional[str]:

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ],
        "stream": False,
        "keep_alive": KEEP_ALIVE,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "num_ctx":     NUM_CTX,
        },
    }
    if json_schema is not None:
        payload["format"] = json_schema
    elif json_mode:
        payload["format"] = "json"

    try:
        resp = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "").strip()

    except requests.exceptions.ConnectionError:
        logger.error(
            "[Ollama] Cannot reach %s — is the Ollama service running? "
            "Install from https://ollama.com and run: ollama pull %s",
            OLLAMA_CHAT_URL, OLLAMA_MODEL,
        )
        return None
    except requests.exceptions.Timeout:
        logger.error(
            "[Ollama] Request timed out after %ds. CPU inference of a 7B model "
            "is slow — consider increasing OLLAMA_TIMEOUT in config.py or "
            "switching to a smaller model (e.g. qwen2.5:3b).",
            OLLAMA_TIMEOUT,
        )
        return None
    except requests.RequestException as e:
        logger.error("[Ollama] HTTP error: %s", e)
        return None
    except (KeyError, ValueError) as e:
        logger.error("[Ollama] Bad response shape: %s", e)
        return None


def enrich_cve(
    cve_id: str,
    search_context: str,
    api_key: str = "",  
) -> Optional[dict]:
    
    user_message = (
        f"CVE ID: {cve_id}\n\n"
        f"Search Results:\n{search_context}\n\n"
        f"Extract structured data about {cve_id} ONLY. "
        f"The cve_id field in your output must be exactly '{cve_id}'."
    )

    raw = _ollama_chat(
        system_prompt = EXTRACTION_PROMPT,
        user_message  = user_message,
        json_schema   = ENRICHMENT_SCHEMA,
    )
    if raw is None:
        return None

    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        parsed = json.loads(text)
        logger.info(f"[Ollama] Successfully enriched {cve_id}")
        return parsed
    except json.JSONDecodeError as e:
        logger.error(f"[Ollama] JSON parse failed for {cve_id}: {e}\nRaw: {raw[:500]}")
        return None


def batch_enrich(
    cve_search_pairs: list[tuple[str, str]],
    api_key: str = "",
    delay:   float = 0.0,
) -> list[dict]:
    """
    Enrich multiple CVEs sequentially (Ollama serves one request at a time).

    Args:
        cve_search_pairs: list of (cve_id, formatted_search_context) tuples
        api_key:          unused; preserved for API compatibility
        delay:            optional sleep between requests

    Returns:
        List of enriched dicts (failed ones are skipped)
    """
    import time
    results = []
    for cve_id, context in cve_search_pairs:
        enriched = enrich_cve(cve_id, context)
        if enriched:
            results.append(enriched)
        if delay > 0:
            time.sleep(delay)
    return results


# Public: FOFA query generation 
# Product → verified FOFA clause mapping now lives in core/fofa_catalog.py


def _validate_fofa_query(q: str) -> bool:
    """
    Reject obviously malformed queries before sending them to FOFA.
    Catches LLM hallucinations and bad catalog edits.
    """
    if not q or len(q) > 500:
        return False
    if not re.search(r'\b(app|product(\.\w+)?|banner|body|title|host|server|cert|domain|protocol)\*?=', q):
        return False
    if 'country="IN"' not in q:
        return False
    if q.count('"') % 2 != 0:
        return False
    if any(marker in q.lower() for marker in ("xxx", "todo", "<", ">", "{", "}")):
        return False
    return True


def generate_fofa_query(enriched: dict, api_key: str = "") -> Optional[str]:
    """
    Build a validated FOFA search query from an enriched CVE dict.

    Strategy:
        1. For each product in `enriched["products"]`, look up the verified
           FOFA `app=` value in the curated catalog.
        2. If at least one match → emit `app="X"` (or `app="X" || app="Y"`).
        3. Otherwise fall back to `title*="<product>"` fuzzy match — `body`
           does not support fuzzy search on FOFA (error 820134), so the
           fallback uses `title` instead.
        4. Always anchor with `country="IN"`.
        5. Validate before returning. Return None if the result is malformed
           or no usable signal could be extracted.

    Args:
        enriched: output from enrich_cve()
        api_key:  unused; preserved for API compatibility.

    Returns:
        FOFA query string, or None if no valid query could be built.
    """
    if not enriched:
        return None

    from core import fofa_catalog

    products = [p for p in (enriched.get("products") or []) if p and p.strip()]
    cve_id   = enriched.get("cve_id", "?")

    if not products:
        logger.warning(f"[FOFA] {cve_id}: no products in enriched data")
        return None

    # Precision-first: map each product to a VERIFIED tag (app=/product=/server*=).
    # fuzzy title*= guess (the old behaviour), which produced false positives. products with no verified fingerprint
    atoms: list[str] = []
    unmapped: list[str] = []
    for p in products:
        entry = fofa_catalog.lookup(p)
        if entry:
            if entry["clause"] not in atoms:
                atoms.append(entry["clause"])
        else:
            unmapped.append(p)

    if not atoms:
        logger.warning(
            f"[FOFA] {cve_id}: no verified FOFA fingerprint for {products} — "
            f"refusing to emit a fuzzy guess"
        )
        return None

    clause = atoms[0] if len(atoms) == 1 else "(" + " || ".join(atoms) + ")"
    query  = f'{clause} && country="IN"'

    if unmapped:
        logger.info(f"[FOFA] {cve_id}: unmapped products omitted (no verified tag): {unmapped}")

    

    if not _validate_fofa_query(query):
        logger.error(f"[FOFA] {cve_id}: built query failed validation: {query!r}")
        return None

    logger.info(f"[FOFA] {cve_id}: {query}")
    return query


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    fake_context = """
[Source 1] Cisco NX-OS Software CLI Command Injection Vulnerability
URL: https://sec.cloudapps.cisco.com/security/advisory/cisco-sa-nxos-cmd-injection-12345
Snippet: A vulnerability in Cisco NX-OS allows authenticated local attackers to
execute arbitrary commands as root. Affects NX-OS versions 9.3(x) before 9.3(13),
10.2(x) before 10.2(7), 10.3(x) before 10.3(5). Fixed in 9.3(13), 10.2(7), 10.3(5).

[Source 2] CVE-2024-20399 Detail - NVD
URL: https://nvd.nist.gov/vuln/detail/CVE-2024-20399
Snippet: CVSS Score 6.7 Medium. Cisco NX-OS Software CLI injection. Affects
Nexus 3000, 5500, 6000, 7000 Series. No workaround available, update recommended.
"""

    print(f"Calling Ollama at {OLLAMA_CHAT_URL} with model {OLLAMA_MODEL}...")
    print("(First call may take a while as the model is loaded into memory.)\n")

    result = enrich_cve("CVE-2024-20399", fake_context)
    if result:
        print(json.dumps(result, indent=2))
        print("\n--- FOFA query ---")
        print(generate_fofa_query(result))
    else:
        print(
            "Enrichment failed. Checklist:\n"
            "  1. Ollama installed?  https://ollama.com/download\n"
            f"  2. Model pulled?      ollama pull {OLLAMA_MODEL}\n"
            "  3. Service running?   ollama list  (should show the model)\n"
        )
        sys.exit(1)