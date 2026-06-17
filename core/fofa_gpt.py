"""
core/fofa_gpt.py
-----------------
FofaGPT — natural-language to FOFA query, inspired by Censys' CensysGPT.

CensysGPT works because Censys fine-tuned an internal model on millions of
(prompt, query) pairs they own. We can't replicate that, but we can do
something pragmatic that works well in practice:

    1. Few-shot prompt the local Ollama LLM (Qwen 2.5 3B) with curated
       (natural-language description, FOFA query) examples sourced from
       fofabot's own tweets — these queries are hand-vetted by experts.
    2. Constrain the model output to a strict JSON schema so it can never
       emit malformed structures.
    3. Run the candidate query through the same `_validate_fofa_query`
       used by the deterministic generator, so anything broken is rejected
       before it reaches the user.

Public API:
    nl_to_fofa(prompt) -> dict with keys:
        query           : FOFA query string, or None on failure
        confidence      : "high" | "medium" | "low"
        examples_used   : the few-shot examples that primed the model
        rationale       : one-sentence explanation from the LLM
        valid           : bool — whether the query passed validation

    get_fofabot_examples(limit=20) -> list of {nl, query, cve_id} dicts
"""

import json
import logging
import re
from typing import Optional

import requests

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT
from core.groq_enricher import _validate_fofa_query

logger = logging.getLogger(__name__)

OLLAMA_CHAT_URL = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"


# Words that should never be the value inside a FOFA field=value pair.
# These are syntax placeholders or generic English the model might echo
# from the prompt instead of identifying a real product.
_BANNED_VALUE_TOKENS = {
    "query", "value", "field", "syntax", "example",
    "find", "exposed", "search", "result", "results",
    "thing", "device", "devices", "server", "servers",
    "anything", "everything", "stuff", "data",
    "test", "todo", "xxx", "placeholder",
    "product", "app", "banner", "host", "domain",
}


def _has_banned_value(q: str) -> bool:
    """
    Return True if any FOFA field=value pair uses a banned generic word
    as its value. Catches LLM hallucinations like body*="query".
    """
    # Match field="value" and field*="value*"
    for m in re.finditer(r'\w+\*?="([^"]+)"', q):
        val = m.group(1).strip().strip("*").lower()
        if not val:
            return True
        if val in _BANNED_VALUE_TOKENS:
            return True
        # Single-character or super-short non-numeric values
        if len(val) <= 2 and not val.isdigit() and val != "in":
            return True
    return False


def _validate_fofa_query_lenient(q: str) -> bool:
    """
    Lenient validator for FofaGPT — same checks as the strict one, except
    `country="IN"` is allowed to be missing (user may explicitly want a
    global query). All other safety checks still apply.
    """
    if not q or len(q) > 500:
        return False
    if not re.search(r'\b(app|product|banner|body|title|host|server|cert|domain|protocol)\*?=', q):
        return False
    if q.count('"') % 2 != 0:
        return False
    if any(marker in q.lower() for marker in (
        "xxx", "todo", "<", ">", "{", "}",
        "tool_call", "im_start", "im_end",
        '!country', '!app', '!banner',
        'rationale', 'confidence',
    )):
        return False
    # Reject obviously garbage tail (Chinese characters, non-ASCII bracket noise)
    if re.search(r"[\u4e00-\u9fff]", q):
        return False
    # Reject queries whose values are generic English placeholders
    if _has_banned_value(q):
        return False
    return True

# ── Static seed examples (always present, supplemented by live fofabot) ──────
# Hand-picked to cover the common shapes a user might ask for.
SEED_EXAMPLES: list[dict] = [
    {
        "nl":     "find Roundcube webmail servers in India",
        "query":  'app="Roundcube-Webmail" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "all ERPNext instances exposed on the internet in India",
        "query":  'app="ERPNext" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "FortiGate SSL VPN devices",
        "query":  '(app="FortiOS" || app="Fortinet-SSL-VPN") && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Palo Alto GlobalProtect portals in India",
        "query":  '(app="PAN-OS" || app="Palo-Alto-GlobalProtect") && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Cisco IOS XE devices running version 17.9",
        "query":  'app="Cisco-IOS-XE" && country="IN" && banner*="17.9.*"',
        "cve_id": None,
    },
    {
        "nl":     "Microsoft Exchange servers in India",
        "query":  'app="Microsoft-Exchange" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "TYPO3 CMS instances on Indian infrastructure",
        "query":  'app="TYPO3" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "FreePBX servers in India",
        "query":  'app="FreePBX" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Apache Tomcat instances",
        "query":  'app="Apache-Tomcat" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Citrix NetScaler ADC devices in India",
        "query":  'app="Citrix-ADC" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Ivanti Connect Secure VPN gateways",
        "query":  'app="Ivanti-Connect-Secure" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "VMware vCenter servers running version 7.x",
        "query":  'app="VMware-vCenter" && country="IN" && banner*="7.*"',
        "cve_id": None,
    },
]

# ── System prompt (kept tight; the heavy lifting is in the examples) ─────────
SYSTEM_PROMPT = """[unused — kept only for backward compat. Stage 1 uses EXTRACTION_PROMPT.]"""


# ── Stage 1: intent extraction ───────────────────────────────────────────────
# This is a pure NLP task — read messy human input, identify the real
# entities (product, version, country). The 3B model is reliable at this
# because the output space is small and structured.

EXTRACTION_PROMPT = """You are a security analyst extracting search intent from a user's natural-language question about FOFA reconnaissance. Your only job is to identify the REAL product/technology and any version or country mentioned.

Rules:
- IGNORE filler English: "find", "exposed", "vulnerable", "query", "search", "show me", "for", "the", "any", "all".
- products: list of actual products / technologies. Use canonical names (e.g. "Apache HTTP Server" not just "apache", "FortiOS" not "fortigate firewall", "Microsoft Exchange" not "exchange"). Empty list if none.
- version_patterns: list of major.minor version numbers mentioned in dotted form (e.g. "7.4", "17.9"). Empty list if none.
- country: ISO 2-letter country code if mentioned. Use "IN" if India is mentioned or implied. Use "ANY" if user explicitly says global/worldwide/everywhere. Default "IN".
- is_actionable: true ONLY if you identified at least one concrete product/technology. False if the prompt is too vague ("find anything", "show me stuff") or non-product ("default credentials", "open ports").
- summary: one-line plain-English restatement of what the user wants.

Examples:
"find me exposed query for apache"          -> products=["Apache HTTP Server"], country="IN", is_actionable=true
"FortiGate firewalls in India"               -> products=["FortiOS"], country="IN", is_actionable=true
"Cisco IOS XE devices running 17.9"          -> products=["Cisco IOS XE"], version_patterns=["17.9"], country="IN", is_actionable=true
"Apache Tomcat instances globally"           -> products=["Apache Tomcat"], country="ANY", is_actionable=true
"Microsoft Exchange ProxyShell servers"      -> products=["Microsoft Exchange"], country="IN", is_actionable=true
"find anything"                              -> products=[], is_actionable=false
"devices with default SSH credentials"       -> products=[], is_actionable=false (no concrete product)
"MikroTik routers in BSNL network"           -> products=["MikroTik RouterOS"], country="IN", is_actionable=true
"roundcube webmail exposed"                  -> products=["Roundcube Webmail"], country="IN", is_actionable=true
"Palo Alto GlobalProtect VPN"                -> products=["PAN-OS","Palo Alto GlobalProtect"], country="IN", is_actionable=true

Respond with JSON matching the schema."""


EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "products":         {"type": "array",   "items": {"type": "string"}},
        "version_patterns": {"type": "array",   "items": {"type": "string"}},
        "country":          {"type": "string"},
        "is_actionable":    {"type": "boolean"},
        "summary":          {"type": "string"},
    },
    "required": ["products", "version_patterns", "country", "is_actionable", "summary"],
}


# ── JSON schema for stage 2 (deprecated, kept for backward compat) ──────────
# Stage 2 architecture composes queries deterministically and no longer
# round-trips through this schema. EXTRACTION_SCHEMA above is the active one.
RESPONSE_SCHEMA = EXTRACTION_SCHEMA


# ── Live example fetch (best-effort, fast) ───────────────────────────────────
def _fetch_fofabot_examples(limit: int = 8) -> list[dict]:
    """
    Pull a handful of live fofabot tweets and turn them into NL/query pairs.
    Cached at module level for the process lifetime to avoid hammering Nitter
    on every call.
    """
    global _CACHED_LIVE_EXAMPLES
    if _CACHED_LIVE_EXAMPLES is not None:
        return _CACHED_LIVE_EXAMPLES[:limit]

    try:
        from scrapers.fofabot_scraper import scrape_fofabot
        tweets = scrape_fofabot(max_tweets=limit)
        examples = []
        for t in tweets:
            cve_id = t.get("cve_id")
            query  = t.get("fofa_query")
            desc   = t.get("description") or ""
            if not cve_id or not query:
                continue
            # Construct an NL prompt from the description if present
            if desc:
                nl = f"find devices vulnerable to {cve_id} ({desc[:80]})"
            else:
                nl = f"find devices vulnerable to {cve_id}"
            examples.append({"nl": nl, "query": query, "cve_id": cve_id})
        _CACHED_LIVE_EXAMPLES = examples
        logger.info(f"[FofaGPT] Loaded {len(examples)} live fofabot examples")
        return examples
    except Exception as e:
        logger.warning(f"[FofaGPT] Live example fetch failed: {e}")
        _CACHED_LIVE_EXAMPLES = []
        return []


_CACHED_LIVE_EXAMPLES: Optional[list[dict]] = None


def get_fofabot_examples(limit: int = 12) -> list[dict]:
    """
    Examples for the UI's inspiration panel — newest archive entries first.
    Combines fofabot tweets, PDF-derived rows, and seeds in priority order.
    """
    from core.fofa_archive import init_archive_table
    from database.db import get_connection

    init_archive_table()
    sql = """
        SELECT cve_id, nl, query, source
        FROM fofa_archive
        ORDER BY
            CASE source WHEN 'fofabot' THEN 0 WHEN 'pdf' THEN 1 ELSE 2 END,
            id DESC
        LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (max(1, min(50, limit)),)).fetchall()
    return [dict(r) for r in rows]


# ── Build the few-shot user message (kept for legacy callers) ────────────────
# Stage 2 architecture doesn't use few-shot anymore — this function is
# retained only because nothing should silently break if it's still imported
# elsewhere. Do NOT use for new code.
def _build_few_shot(prompt: str) -> tuple[str, list[dict]]:
    from core.fofa_rag import retrieve
    return prompt, retrieve(prompt, k=6)


# ── Ollama call ──────────────────────────────────────────────────────────────
def _call_ollama(system: str, user_message: str, schema: Optional[dict] = None,
                 max_tokens: int = 400) -> Optional[dict]:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_message},
        ],
        "stream":     False,
        "keep_alive": "30m",
        "options": {
            "temperature": 0.1,
            "num_predict": max_tokens,
            "num_ctx":     4096,
        },
    }
    if schema is not None:
        payload["format"] = schema
    try:
        r = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        content = r.json().get("message", {}).get("content", "").strip()
    except requests.exceptions.ConnectionError:
        logger.error("[FofaGPT] Cannot reach Ollama. Is the service running?")
        return None
    except requests.exceptions.Timeout:
        logger.error("[FofaGPT] Ollama timed out")
        return None
    except Exception as e:
        logger.error(f"[FofaGPT] Ollama error: {e}")
        return None

    # Strip stray markdown fences
    content = content.strip().strip("`").strip()
    if content.startswith("json"):
        content = content[4:].strip()

    # Some models continue rambling after the closing brace. Extract just
    # the first JSON object using a balanced-brace scan.
    if content.startswith("{"):
        depth = 0
        end = -1
        in_string = False
        escape = False
        for i, ch in enumerate(content):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > 0:
            content = content[:end]

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"[FofaGPT] JSON parse failed: {e}\nRaw: {content[:300]}")
        return None


# ── Public entrypoint (two-stage pipeline) ───────────────────────────────────
def nl_to_fofa(prompt: str) -> dict:
    """
    Translate a natural-language reconnaissance prompt into a validated
    FOFA query using a two-stage architecture:

        Stage 1 (LLM)    : extract structured intent from messy English
                           → products, versions, country, is_actionable
        Stage 2 (Python) : compose the FOFA query deterministically from
                           the curated FOFA app catalog. No hallucinations
                           possible — if a product isn't in the catalog
                           we fall back to a fuzzy `body*=` match against
                           the literal product name (NOT against random
                           English words from the prompt).

    Returns a dict with:
        query         : FOFA query string, or None
        confidence    : "high" | "medium" | "low"
        rationale     : one-sentence explanation
        examples_used : RAG-retrieved similar examples (for transparency)
        valid         : bool — whether the query passed validation
        intent        : the extracted intent dict (debugging / UI display)
    """
    prompt = (prompt or "").strip()
    if not prompt:
        return _empty_response("Empty prompt.")
    if len(prompt) > 500:
        return _empty_response("Prompt too long. Keep it under 500 characters.")

    # Stage 1 — LLM extracts intent
    intent_msg, hits = _build_extraction_message(prompt)
    intent_raw = _call_ollama(
        EXTRACTION_PROMPT, intent_msg, schema=EXTRACTION_SCHEMA, max_tokens=300,
    )
    examples_used = [
        {"nl": h["nl"], "query": h["query"], "cve_id": h.get("cve_id"),
         "source": h.get("source"), "similarity": round(h.get("similarity", 0.0), 3)}
        for h in hits
    ]

    if not intent_raw:
        return {
            "query":         None,
            "confidence":    "low",
            "rationale":     "LLM call failed. Check that Ollama is running.",
            "examples_used": examples_used,
            "valid":         False,
            "intent":        None,
        }

    intent = _normalize_intent(intent_raw)

    if not intent["is_actionable"] or not intent["products"]:
        return {
            "query":         None,
            "confidence":    "low",
            "rationale":     intent.get("summary") or
                             "Could not identify a concrete product to search for. "
                             "Try naming the product, vendor, or technology explicitly.",
            "examples_used": examples_used,
            "valid":         False,
            "intent":        intent,
        }

    # Stage 2 — deterministic query composition
    query, confidence, rationale = _compose_query_from_intent(intent)

    valid = bool(query) and _validate_fofa_query_lenient(query)
    if not valid and query:
        logger.warning(f"[FofaGPT] Validation failed for: {query!r}")
        query = None

    logger.info(
        f"[FofaGPT] {prompt[:60]!r} -> "
        f"intent={intent['products']} ver={intent['version_patterns']} country={intent['country']} "
        f"-> {query!r} (valid={valid})"
    )

    return {
        "query":         query,
        "raw_query":     query,
        "confidence":    confidence,
        "rationale":     rationale,
        "examples_used": examples_used,
        "valid":         valid,
        "intent":        intent,
    }


def _empty_response(reason: str) -> dict:
    return {
        "query":         None,
        "confidence":    "low",
        "rationale":     reason,
        "examples_used": [],
        "valid":         False,
        "intent":        None,
    }


def _normalize_intent(raw: dict) -> dict:
    products = [p.strip() for p in (raw.get("products") or []) if isinstance(p, str) and p.strip()]
    versions = [v.strip() for v in (raw.get("version_patterns") or []) if isinstance(v, str) and v.strip()]
    country  = (raw.get("country") or "IN").strip().upper()
    if country not in {"IN", "ANY"}:
        # Pass through arbitrary 2-letter codes the model returns
        if not re.fullmatch(r"[A-Z]{2}", country):
            country = "IN"
    return {
        "products":         products,
        "version_patterns": versions,
        "country":          country,
        "is_actionable":    bool(raw.get("is_actionable")) and bool(products),
        "summary":          (raw.get("summary") or "").strip(),
    }


def _build_extraction_message(prompt: str) -> tuple[str, list[dict]]:
    """
    Build the user message for the extraction stage. RAG-retrieved
    examples are included as prior-context only — they help the model
    recognize products it's seen before, but the prompt instructs it to
    extract intent, not copy queries.
    """
    from core.fofa_rag import retrieve
    hits = retrieve(prompt, k=4)

    lines = []
    if hits:
        lines.append(
            "Reference: here are some past queries that involved similar products. "
            "Use them only to recognize product names. Do NOT copy their syntax — "
            "your job is to extract intent.\n"
        )
        for ex in hits:
            lines.append(f"  - past prompt: {ex['nl'][:80]}")
            lines.append(f"    query was : {ex['query'][:100]}")
        lines.append("")

    lines.append(f"User prompt: {prompt.strip()}")
    lines.append("")
    lines.append("Extract the structured intent as JSON.")
    return "\n".join(lines), hits


# ── Stage 2: deterministic query composition ─────────────────────────────────
def _compose_query_from_intent(intent: dict) -> tuple[Optional[str], str, str]:
    """
    Build a FOFA query from extracted intent using the same curated
    catalog the CVE pipeline uses. Falls back to fuzzy body*= match
    when a product isn't in the catalog.

    Returns (query, confidence, rationale).
    """
    from core.groq_enricher import _lookup_fofa_app, _sanitize_for_fofa_value

    products = intent["products"]
    versions = intent["version_patterns"]
    country  = intent["country"]

    # Map products to FOFA app= values via the catalog
    fofa_apps: list[str] = []
    fuzzy_terms: list[str] = []
    for p in products:
        mapped = _lookup_fofa_app(p)
        if mapped:
            if mapped not in fofa_apps:
                fofa_apps.append(mapped)
        else:
            # Use the product name itself as the fuzzy term — never random
            # English words from the prompt, since intent extraction already
            # filtered those out.
            term = _sanitize_for_fofa_value(p)
            if term and term not in fuzzy_terms:
                fuzzy_terms.append(term)

    confidence = "high"
    rationale_bits: list[str] = []

    # Primary product clause
    if fofa_apps and not fuzzy_terms:
        if len(fofa_apps) == 1:
            clause = f'app="{fofa_apps[0]}"'
        else:
            inner  = " || ".join(f'app="{a}"' for a in fofa_apps)
            clause = f"({inner})"
        rationale_bits.append(
            f"Matched {len(fofa_apps)} product(s) in the FOFA catalog: "
            + ", ".join(fofa_apps)
        )
    elif fofa_apps and fuzzy_terms:
        # Mix: catalog hits plus fuzzy fallback for unknown products
        cat_clause = (
            f'app="{fofa_apps[0]}"' if len(fofa_apps) == 1
            else "(" + " || ".join(f'app="{a}"' for a in fofa_apps) + ")"
        )
        fuz_clause = (
            f'body*="{fuzzy_terms[0]}"' if len(fuzzy_terms) == 1
            else "(" + " || ".join(f'body*="{t}"' for t in fuzzy_terms) + ")"
        )
        clause = f"({cat_clause} || {fuz_clause})"
        confidence = "medium"
        rationale_bits.append(
            f"Catalog match for: {', '.join(fofa_apps)}. "
            f"Fuzzy fallback for: {', '.join(fuzzy_terms)}."
        )
    elif fuzzy_terms:
        if len(fuzzy_terms) == 1:
            clause = f'body*="{fuzzy_terms[0]}"'
        else:
            inner  = " || ".join(f'body*="{t}"' for t in fuzzy_terms)
            clause = f"({inner})"
        confidence = "medium"
        rationale_bits.append(
            "No catalog match — using fuzzy body match against: "
            + ", ".join(fuzzy_terms)
        )
    else:
        return None, "low", "No product extracted from the prompt."

    # Country clause
    if country == "ANY":
        query = clause
        rationale_bits.append("Global scope (no country filter).")
    else:
        query = f'{clause} && country="{country}"'
        rationale_bits.append(f'Restricted to country="{country}".')

    # Optional version narrowing — only when we have a high-confidence app=
    # match AND clean major.minor patterns. Same operator (banner*=) the
    # CVE pipeline uses.
    if versions and fofa_apps and not fuzzy_terms:
        clean = []
        for v in versions:
            m = re.fullmatch(r"\d{1,2}\.\d{1,3}", v)
            if m and v not in clean:
                clean.append(v)
            if len(clean) >= 4:
                break
        if clean:
            if len(clean) == 1:
                ver_clause = f'banner*="{clean[0]}.*"'
            else:
                inner = " || ".join(f'banner*="{c}.*"' for c in clean)
                ver_clause = f"({inner})"
            query = f"{query} && {ver_clause}"
            rationale_bits.append(f"Version filter: {', '.join(clean)}.")

    rationale = " ".join(rationale_bits)
    return query, confidence, rationale


# ── Self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    tests = [
        "find all FortiGate firewalls in India",
        "exposed roundcube webmail servers",
        "Cisco IOS XE devices running 17.9",
        "Apache Tomcat instances globally",
        "find anything",   # too vague
        "Microsoft Exchange servers vulnerable to ProxyShell",
    ]
    for t in tests:
        r = nl_to_fofa(t)
        print(f"\nQ: {t}")
        print(f"  query     : {r['query']}")
        print(f"  confidence: {r['confidence']}")
        print(f"  rationale : {r['rationale']}")
        print(f"  valid     : {r['valid']}")
