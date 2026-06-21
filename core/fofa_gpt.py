"""
Trying to make a custom FOFA GPT than turns natural language query into FOFA structured query.
(inspired by censysGPT)

CensysGPT works because Censys fine-tuned an internal model on millions of
(prompt, query) pairs they own. ofc I can't replicate that, but a makeshift i found:

    1. Few-shot prompt the local Ollama LLM (Qwen 2.5 3B) with curated
       (natural-language description, FOFA query) examples sourced from
       fofabot's own tweets(from X)
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



_BANNED_VALUE_TOKENS = {
    "query", "value", "field", "syntax", "example",
    "find", "exposed", "search", "result", "results",
    "thing", "device", "devices", "server", "servers",
    "anything", "everything", "stuff", "data",
    "test", "todo", "xxx", "placeholder",
    "product", "app", "banner", "host", "domain",
    "any", "all", "some", "various", "none", "null", "n/a", "na",
}


def _has_banned_value(q: str) -> bool:
    """
    Return True if any FOFA field=value pair uses a banned generic word
    as its value. Catches LLM hallucinations like title*="query".
    """

    for m in re.finditer(r'[\w.]+\*?="([^"]+)"', q):
        val = m.group(1).strip().strip("*").lower()
        if not val:
            return True
        if val in _BANNED_VALUE_TOKENS:
            return True
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
    if not re.search(
        r'\b(app|product|banner|body|title|host|server|cert\.[a-z.]+|domain|protocol'
        r'|asn|port|ip|os|cloud_name|is_cloud|org)\*?=',
        q,
    ):
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
    if re.search(r"[\u4e00-\u9fff]", q):
        return False
    if _has_banned_value(q):
        return False
    return True

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
        "query":  '(app="FortiOS" || app="SSL-VPN") && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Palo Alto GlobalProtect portals in India",
        "query":  'title*="GlobalProtect" && country="IN"',
        "cve_id": None,
    },
    {
        "nl":     "Cisco IOS XE devices running version 17.9",
        "query":  'product="Cisco-IOS-XE" && product.version="17.9" && country="IN"',
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
        "query":  'app="APACHE-Tomcat" && country="IN"',
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
        "query":  'app="VMware-vCenter" && country="IN"',
        "cve_id": None,
    },
]

SYSTEM_PROMPT = """[unused — kept only for backward compat. Stage 1 uses EXTRACTION_PROMPT.]"""


#Stage 1: intent extraction
# This is a pure NLP task — read messy human input, identify the real
#

EXTRACTION_PROMPT = """You are a security analyst extracting search intent from a user's natural-language question about FOFA reconnaissance. Your job is to identify every concrete, queryable attribute mentioned: product/technology, version, country, ASN, port(s), operating system, server software, cloud provider, certificate details, organization, and page content terms.

Rules:
- IGNORE filler English: "find", "exposed", "vulnerable", "query", "search", "show me", "for", "the", "any", "all", "services", "devices", "running".
- products: list of actual products / technologies for FOFA's app= rule matching. Use canonical names (e.g. "Apache HTTP Server" not "apache", "FortiOS" not "fortigate firewall"). Empty list if none mentioned.
- version_patterns: list of major.minor version numbers in dotted form (e.g. "7.4", "17.9"). Empty list if none.
- country: ISO 2-letter country code if mentioned. Use "IN" if India is mentioned or implied. Use "ANY" if explicitly global/worldwide, OR if an ASN is given. Default "IN" otherwise.
- asn: autonomous system number as plain digits, no "AS" prefix. Null if not mentioned.
- ports: list of port numbers as strings. Empty list if none mentioned. List explicit numbers only, never invent a range.
- os: operating system name if explicitly mentioned (e.g. "CentOS", "Windows Server", "Ubuntu"). Null if not mentioned. Do NOT infer an OS from a product name (e.g. don't assume Linux just because nginx was mentioned).
- server_software: web/app server software if explicitly distinct from the main product (e.g. "Microsoft-IIS/10", "nginx" when asked as the server, not the target product). Null if not mentioned or redundant with products.
- cloud_provider: cloud provider name if mentioned (e.g. "AWS", "Azure", "Alibaba Cloud", "Aliyundun"). Null if not mentioned.
- is_cloud: true if user wants ONLY cloud-hosted assets, false if user wants ONLY non-cloud/on-prem assets, null if not specified.
- cert_org: organization name if user asks about certificate subject/issuer organization (e.g. "certs issued to X", "SSL cert for organization Y"). Null if not mentioned.
- org: organization/ISP name if user asks generically about an organization's assets (NOT certificate-specific) (e.g. "assets belonging to BSNL"). Null if not mentioned.
- content_terms: list of literal words/phrases the user wants matched in page title or body content (e.g. "title says login", "pages mentioning admin panel"). Empty list if none.
- is_actionable: true if at least one concrete attribute was identified (product, asn, port, os, server_software, cloud_provider, cert_org, org, or content_terms). False only if NOTHING concrete was found.
- summary: one-line plain-English restatement of what the user wants.

Examples:
"find me exposed query for apache"                          -> products=["Apache HTTP Server"], country="IN", is_actionable=true
"FortiGate firewalls in India"                                -> products=["FortiOS"], country="IN", is_actionable=true
"Cisco IOS XE devices running 17.9"                           -> products=["Cisco IOS XE"], version_patterns=["17.9"], country="IN", is_actionable=true
"show me all the services with apps running apache in asn 9829" -> products=["Apache HTTP Server"], country="ANY", asn="9829", is_actionable=true
"show me nginx running on port 8080, 8443"                    -> products=["nginx"], country="IN", ports=["8080","8443"], is_actionable=true
"everything in ASN 13335"                                     -> products=[], country="ANY", asn="13335", is_actionable=true
"CentOS servers running Microsoft IIS in India"                -> products=[], country="IN", os="CentOS", server_software="Microsoft-IIS", is_actionable=true
"nginx servers on AWS in India"                                -> products=["nginx"], country="IN", cloud_provider="AWS", is_cloud=true, server_software=null, os=null, is_actionable=true
"assets hosted on AWS in India"                                -> products=[], country="IN", cloud_provider="AWS", is_cloud=true, is_actionable=true
"non-cloud servers in ASN 9829"                                -> products=[], country="ANY", asn="9829", is_cloud=false, is_actionable=true
"certificates issued to Oracle Corporation"                    -> products=[], country="ANY", cert_org="Oracle Corporation", is_actionable=true
"BSNL network assets running nginx"                            -> products=["nginx"], country="IN", org="BSNL", is_actionable=true
"pages with title containing login panel"                      -> products=[], country="IN", content_terms=["login panel"], is_actionable=true
"find anything"                                               -> products=[], is_actionable=false
"devices with default SSH credentials"                         -> products=[], is_actionable=false

CRITICAL: os, server_software, cloud_provider, cert_org, and org are each
INDEPENDENT signals. Only fill a field when the prompt contains a clear,
specific signal for THAT field. Do not fill server_software just because
the prompt mentions a product, an OS, or "in India" — those are unrelated.
A prompt with NO server/OS keyword anywhere in it must have
server_software=null and os=null, even if a past example you've seen used
those fields for a superficially similar-looking prompt.

Respond with JSON matching the schema."""


EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "products":         {"type": "array",   "items": {"type": "string"}},
        "version_patterns": {"type": "array",   "items": {"type": "string"}},
        "country":          {"type": "string"},
        "asn":              {"type": ["string", "null"]},
        "ports":            {"type": "array",   "items": {"type": "string"}},
        "os":               {"type": ["string", "null"]},
        "server_software":  {"type": ["string", "null"]},
        "cloud_provider":   {"type": ["string", "null"]},
        "is_cloud":         {"type": ["boolean", "null"]},
        "cert_org":         {"type": ["string", "null"]},
        "org":              {"type": ["string", "null"]},
        "content_terms":    {"type": "array",   "items": {"type": "string"}},
        "is_actionable":    {"type": "boolean"},
        "summary":          {"type": "string"},
    },
    "required": [
        "products", "version_patterns", "country", "asn", "ports",
        "os", "server_software", "cloud_provider", "is_cloud",
        "cert_org", "org", "content_terms", "is_actionable", "summary",
    ],
}


# ── JSON schema for stage 2 (deprecated, kept for backward compat) ──────────
RESPONSE_SCHEMA = EXTRACTION_SCHEMA


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



def _build_few_shot(prompt: str) -> tuple[str, list[dict]]:
    from core.fofa_rag import retrieve
    return prompt, retrieve(prompt, k=6)


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

    content = content.strip().strip("`").strip()
    if content.startswith("json"):
        content = content[4:].strip()

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


def nl_to_fofa(prompt: str) -> dict:
    """
    Translate a natural-language reconnaissance prompt into a validated
    FOFA query using a two-stage architecture:

        Stage 1 (LLM)    : extract structured intent from messy English
                           → products, versions, country, is_actionable
        Stage 2 (Python) : compose the FOFA query deterministically from
                           the curated FOFA app catalog. No hallucinations
                           possible — if a product isn't in the catalog
                           we fall back to a fuzzy `title*=` match against
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
    intent = _ground_intent(intent, prompt)

    has_any_attribute = bool(
        intent["products"] or intent["asn"] or intent["ports"]
        or intent["os"] or intent["server_software"] or intent["cloud_provider"]
        or intent["is_cloud"] is not None or intent["cert_org"] or intent["org"]
        or intent["content_terms"]
    )
    if not intent["is_actionable"] or not has_any_attribute:
        return {
            "query":         None,
            "confidence":    "low",
            "rationale":     intent.get("summary") or
                             "Could not identify a concrete attribute to search for. "
                             "Try naming a product, ASN, port, OS, server, cloud provider, "
                             "certificate organization, or page content term explicitly.",
            "examples_used": examples_used,
            "valid":         False,
            "intent":        intent,
        }

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


def _ground_intent(intent: dict, prompt: str) -> dict:
    """
    Precision guard against Stage-1 hallucination: drop any inferred attribute
    field whose value has no basis in the user's prompt. The 3B model
    occasionally invents e.g. server_software="Microsoft-IIS" for a prompt that
    never mentions IIS, which would silently add false positives. A field is
    kept only if a distinctive token (len>=3) of its value appears in the
    prompt text. Products are NOT grounded — the catalog lookup is their gate,
    and the model legitimately canonicalizes product names.
    """
    text = re.sub(r"[-_/]+", " ", (prompt or "").lower())

    def grounded(value: str) -> bool:
        toks = [t for t in re.split(r"[^a-z0-9.]+", value.lower()) if len(t) >= 3]
        return any(t in text for t in toks) if toks else True

    for f in ("server_software", "os", "cloud_provider", "cert_org", "org"):
        v = intent.get(f)
        if isinstance(v, str) and v and not grounded(v):
            logger.info(f"[FofaGPT] dropping ungrounded {f}={v!r} (not in prompt)")
            intent[f] = None

    # Org/cert names: the model often hyphenates multi-word names ("Reliance
    # Jio" -> "Reliance-Jio") which won't match the real cert/org string. Real
    # org names are space-separated, so un-hyphenate.
    for f in ("cert_org", "org"):
        v = intent.get(f)
        if isinstance(v, str) and "-" in v:
            intent[f] = v.replace("-", " ").strip()


    ct = intent.get("content_terms") or []
    if ct:
        signals = ("title", "body", "page", "header", "says", "contain",
                   "reads", "label", "heading", "text")
        if not any(s in text for s in signals):
            logger.info(f"[FofaGPT] dropping descriptor content_terms {ct} (no content-match signal in prompt)")
            intent["content_terms"] = []
        else:
            cleaned = []
            for t in ct:
                t2 = t.strip().strip('"\'').lower()
                t2 = re.sub(r"^(the\s+)?(title|page|body|header)\s*(says|reads|contains?|containing|with|:)?\s*", "", t2).strip()
                t2 = re.sub(r"^(says|reads|contains?|containing|with|that|of)\s+", "", t2).strip()
                t2 = re.sub(r"\s+in\s+(the\s+)?(title|body|page|header)$", "", t2).strip()
                if t2 and len(t2) >= 2 and t2 not in cleaned:
                    cleaned.append(t2)
            intent["content_terms"] = cleaned
    return intent


def _normalize_intent(raw: dict) -> dict:
    products = [
        p.strip() for p in (raw.get("products") or [])
        if isinstance(p, str) and p.strip() and p.strip().lower() not in _BANNED_VALUE_TOKENS
    ]
    versions = [v.strip() for v in (raw.get("version_patterns") or []) if isinstance(v, str) and v.strip()]
    country  = (raw.get("country") or "IN").strip().upper()
    if country not in {"IN", "ANY"}:
        if not re.fullmatch(r"[A-Z]{2}", country):
            country = "IN"

    # ASN — must be plain digits only. Strip a leading "AS"/"as"
    asn_raw = raw.get("asn")
    asn = None
    if isinstance(asn_raw, str) and asn_raw.strip():
        cleaned = re.sub(r"^(AS|as)", "", asn_raw.strip())
        if cleaned.isdigit():
            asn = cleaned

    # Ports-keep only valid 1-65535 integers, deduplicated, capped at 8
    ports_raw = raw.get("ports") or []
    ports: list[str] = []
    if isinstance(ports_raw, list):
        for p in ports_raw:
            p = str(p).strip()
            if p.isdigit() and 0 < int(p) <= 65535 and p not in ports:
                ports.append(p)
            if len(ports) >= 8:
                break

    def _clean_str_field(value, max_len: int = 80) -> Optional[str]:
        """Generic cleaner for free-text fields the LLM extracts. Rejects
        empty/placeholder values and caps length so a runaway generation
        can't blow up the query string."""
        if not isinstance(value, str):
            return None
        v = value.strip()
        if not v or v.lower() in _BANNED_VALUE_TOKENS:
            return None
        return v[:max_len]

    os_name         = _clean_str_field(raw.get("os"))
    server_software = _clean_str_field(raw.get("server_software"))
    cloud_provider  = _clean_str_field(raw.get("cloud_provider"))
    cert_org        = _clean_str_field(raw.get("cert_org"), max_len=120)
    org             = _clean_str_field(raw.get("org"), max_len=120)

    is_cloud_raw = raw.get("is_cloud")
    is_cloud = is_cloud_raw if isinstance(is_cloud_raw, bool) else None

    content_terms_raw = raw.get("content_terms") or []
    content_terms: list[str] = []
    if isinstance(content_terms_raw, list):
        for t in content_terms_raw:
            cleaned = _clean_str_field(t, max_len=60)
            if cleaned and cleaned not in content_terms:
                content_terms.append(cleaned)
            if len(content_terms) >= 5:
                break

    has_any_attribute = bool(
        products or asn or ports or os_name or server_software
        or cloud_provider or is_cloud is not None or cert_org or org
        or content_terms
    )
    is_actionable = bool(raw.get("is_actionable")) and has_any_attribute

    return {
        "products":         products,
        "version_patterns": versions,
        "country":          country,
        "asn":              asn,
        "ports":            ports,
        "os":               os_name,
        "server_software":  server_software,
        "cloud_provider":   cloud_provider,
        "is_cloud":         is_cloud,
        "cert_org":         cert_org,
        "org":              org,
        "content_terms":    content_terms,
        "is_actionable":    is_actionable,
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


def _compose_query_from_intent(intent: dict) -> tuple[Optional[str], str, str]:
    """
    Build a FOFA query from extracted intent using the VERIFIED catalog
    (core/fofa_catalog.py — every tag confirmed live against this plan).

    Precision-first: each product maps to a verified app=/product= tag, or to
    server*= for products FOFA fingerprints via the server banner (IIS, Apache
    httpd). Products with NO verified fingerprint are NOT turned into fuzzy
    title*= guesses — that fuzzy fallback is the main false-positive source.
    They are dropped and reported instead; if nothing queryable remains, the
    query is refused (None) rather than emitting a noisy guess.

    Composes independent clause builders (product, asn, port, os, server,
    cloud, cert_org, org, content, country) joined with &&.

    Returns (query, confidence, rationale).
    """
    from core import fofa_catalog

    products        = intent["products"]
    versions        = intent["version_patterns"]
    country         = intent["country"]
    asn             = intent.get("asn")
    ports           = intent.get("ports") or []
    os_name         = intent.get("os")
    server_software = intent.get("server_software")
    cloud_provider  = intent.get("cloud_provider")
    is_cloud        = intent.get("is_cloud")
    cert_org        = intent.get("cert_org")
    org             = intent.get("org")
    content_terms   = intent.get("content_terms") or []

    #Map each product to a VERIFIED FOFA tag 
    product_atoms: list[str] = []     # app="X" / product="X" / server*="X"
    matched: list[str] = []           
    unmapped: list[str] = []          # products with no verified fingerprint
    for p in products:
        entry = fofa_catalog.lookup(p)
        if entry:
            atom = entry["clause"]
            if atom not in product_atoms:
                product_atoms.append(atom)
                matched.append(atom)
            continue
        unmapped.append(p)

    confidence = "high"
    rationale_bits: list[str] = []
    clauses: list[str] = []

    product_clause: Optional[str] = None
    if product_atoms:
        product_clause = (product_atoms[0] if len(product_atoms) == 1
                          else "(" + " || ".join(product_atoms) + ")")
        rationale_bits.append(
            f"Matched {len(matched)} verified FOFA fingerprint(s): {', '.join(matched)}."
        )
    if unmapped:
        confidence = "medium" if product_atoms else "low"
        rationale_bits.append(
            "No verified FOFA fingerprint for: " + ", ".join(unmapped)
            + " — omitted rather than emitting a fuzzy guess (would add false positives). "
            "Look the product up in FOFA's web-UI TOP PRODUCTS facet to add a verified tag."
        )

    if product_clause:
        clauses.append(product_clause)

    if asn:
        clauses.append(f'asn="{asn}"')
        rationale_bits.append(f'Restricted to asn="{asn}".')

    if ports:
        if len(ports) == 1:
            clauses.append(f'port="{ports[0]}"')
        else:
            inner = " || ".join(f'port="{p}"' for p in ports)
            clauses.append(f"({inner})")
        rationale_bits.append(f"Restricted to port(s): {', '.join(ports)}.")

    if os_name:
        clauses.append(f'os="{os_name}"')
        rationale_bits.append(f'Restricted to os="{os_name}".')

 
    if server_software:
        clauses.append(f'server*="{server_software}"')
        rationale_bits.append(f'Restricted to server*="{server_software}".')

    if cloud_provider:
        clauses.append(f'cloud_name="{cloud_provider}"')
        rationale_bits.append(f'Restricted to cloud_name="{cloud_provider}".')
    elif is_cloud is not None:
        
        clauses.append(f'is_cloud={"true" if is_cloud else "false"}')
        rationale_bits.append(f'Restricted to is_cloud={"true" if is_cloud else "false"}.')

    if cert_org:
        clauses.append(f'cert.subject.org="{cert_org}"')
        rationale_bits.append(f'Restricted to cert.subject.org="{cert_org}".')

    if org:
        clauses.append(f'org="{org}"')
        rationale_bits.append(f'Restricted to org="{org}".')

  
    for term in content_terms:
        clauses.append(f'title*="{term}"')
        rationale_bits.append(f'Content match: title*="{term}".')

    if not clauses:
        return None, "low", "No queryable attribute extracted from the prompt."

    if country != "ANY" and not asn:
        clauses.append(f'country="{country}"')
        rationale_bits.append(f'Restricted to country="{country}".')
    elif country == "ANY":
        rationale_bits.append("Global scope (no country filter).")


    _seen: set = set()
    clauses = [c for c in clauses if not (c in _seen or _seen.add(c))]

    query = " && ".join(clauses)

    # NOTE: no version narrowing. On this plan `product.version=` is denied
    # (820021, Business+/F-point) and `banner*=` fuzzy is rejected (820134);
    # the only option, exact `banner="7.4"`, matches almost nothing (the
    # version must BE the entire banner) 
    if versions and product_atoms:
        rationale_bits.append(
            "Affected version(s) " + ", ".join(versions[:4]) + " noted — not "
            "added as a filter (FOFA version search needs Business+/F-points; "
            "review results manually)."
        )

    rationale = " ".join(rationale_bits)
    return query, confidence, rationale


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    tests = [
        "find all FortiGate firewalls in India",
        "exposed roundcube webmail servers",
        "Cisco IOS XE devices running 17.9",
        "Apache Tomcat instances globally",
        "find anything",   # too vague
        "Microsoft Exchange servers vulnerable to ProxyShell",
        "show me all the services with apps running apache in asn 9829",
        "show me nginx running on port 8080, 8443",
        # asn/port edge cases
        "everything in ASN 13335",          
        "what's running on port 3389 in India", 
        "CentOS servers running Microsoft IIS in India",
        "assets hosted on AWS in India",
        "non-cloud servers in ASN 9829",
        "certificates issued to Oracle Corporation",
        "BSNL network assets running nginx",
        "pages with title containing login panel",
    ]
    for t in tests:
        r = nl_to_fofa(t)
        print(f"\nQ: {t}")
        print(f"  query     : {r['query']}")
        print(f"  confidence: {r['confidence']}")
        print(f"  rationale : {r['rationale']}")
        print(f"  valid     : {r['valid']}")