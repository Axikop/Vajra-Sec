"""
Scraper for the NIST National Vulnerability Database (NVD) CVE 2.0 API.

API Docs : https://nvd.nist.gov/developers/vulnerabilities
Lag       : 2-3 days behind OEM advisories (by design — NVD enriches manually)

What we fetch:
    - CVEs modified/published in the last N days (default: 2 days, runs every 6h)
    - Full CVSS v3 scores, CWE, CPE affected configurations
    - Version ranges extracted from CPE match strings

Usage:
    from scrapers.nvd import scrape_nvd
    cves = scrape_nvd()                    # last 2 days
    cves = scrape_nvd(days_back=7)         # last week
    cves = scrape_nvd(keyword="cisco")     # keyword filter
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

NVD_API_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME     = "nvd"
PAGE_SIZE       = 2000       
REQUEST_DELAY   = 0.7           
REQUEST_TIMEOUT = 30

RELEVANT_KEYWORDS = [
    "cisco", "fortinet", "juniper", "palo alto", "f5",
    "microsoft windows", "microsoft exchange", "microsoft iis",
    "vmware", "siemens", "apache", "openssl", "linux kernel",
    "oracle", "sap", "atlassian", "citrix", "pulse secure",
    "ivanti", "sonicwall", "checkpoint", "barracuda",
]

_CVSS_SEVERITY = {
    (9.0, 10.0): "CRITICAL",
    (7.0,  8.9): "HIGH",
    (4.0,  6.9): "MEDIUM",
    (0.1,  3.9): "LOW",
}


def _make_session(api_key: str = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "CVE-Monitor/1.0",
    })
    if api_key:
        s.headers.update({"apiKey": api_key})
    return s


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    for (low, high), label in _CVSS_SEVERITY.items():
        if low <= score <= high:
            return label
    return "UNKNOWN"


def _fmt_nvd_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_version_range(cpe_match: dict) -> Optional[str]:
    """
    Extract a human-readable version range from a CPE match object.

    NVD CPE match examples:
        {"versionStartIncluding": "15.0", "versionEndExcluding": "17.9.4a"}
        {"versionEndIncluding": "7.2.3"}
        {"versionStartIncluding": "16.0", "versionEndIncluding": "16.12"}
    """
    vsi = cpe_match.get("versionStartIncluding")
    vse = cpe_match.get("versionStartExcluding")
    vei = cpe_match.get("versionEndIncluding")
    vee = cpe_match.get("versionEndExcluding")

    if vsi and vee:
        return f">= {vsi}, < {vee}"
    if vsi and vei:
        return f">= {vsi}, <= {vei}"
    if vse and vee:
        return f"> {vse}, < {vee}"
    if vse and vei:
        return f"> {vse}, <= {vei}"
    if vee:
        return f"< {vee}"
    if vei:
        return f"<= {vei}"
    if vsi:
        return f">= {vsi}"
    return None


def _extract_cpe_product(cpe_uri: str) -> Optional[str]:
    """
    Extract vendor:product from a CPE 2.3 URI.

    cpe:2.3:a:cisco:ios_xe:17.6.1:*:*:*:*:*:*:*
                    ^^^^^^  ^^^^^^
                    vendor  product  → "cisco ios_xe"
    """
    parts = cpe_uri.split(":")
    if len(parts) >= 5:
        vendor  = parts[3].replace("_", " ")
        product = parts[4].replace("_", " ")
        return f"{vendor} {product}".strip()
    return None


def _parse_cve_item(item: dict) -> list[dict]:
    """
    Parse a single NVD CVE item into one or more DB-ready records.

    One NVD item can affect multiple products (CPE configurations).
    We emit one record per unique affected product to maximise matcher coverage.
    If no CPE data, we emit one record with product_raw from description.
    """
    cve_data = item.get("cve", {})
    cve_id   = cve_data.get("id", "UNKNOWN")

    published = (cve_data.get("published", "") or "")[:10]   # YYYY-MM-DD
    modified  = (cve_data.get("lastModified", "") or "")[:10]

    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    if description.startswith("** REJECT") or description.startswith("** DISPUTED"):
        logger.debug("Skipping %s — rejected/disputed", cve_id)
        return []

    cvss_score = None
    severity   = "UNKNOWN"
    metrics    = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m          = metrics[key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            severity   = m.get("baseSeverity", _cvss_to_severity(cvss_score))
            severity   = severity.upper() if severity else _cvss_to_severity(cvss_score)
            break

    if cvss_score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m          = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_score = m.get("baseScore")
        severity   = _cvss_to_severity(cvss_score)

    weaknesses = cve_data.get("weaknesses", [])
    cwe_ids    = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                cwe_ids.append(d["value"])

    refs        = cve_data.get("references", [])
    advisory_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    for ref in refs:
        tags = ref.get("tags", [])
        if "Vendor Advisory" in tags or "Patch" in tags:
            advisory_url = ref.get("url", advisory_url)
            break

    configurations = cve_data.get("configurations", [])
    affected       = []   # list of {product_raw, version_range, oem}

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe_uri     = cpe_match.get("criteria", "")
                product_raw = _extract_cpe_product(cpe_uri) or ""
                ver_range   = _parse_version_range(cpe_match)

                # Extract OEM from CPE vendor field
                parts = cpe_uri.split(":")
                oem   = parts[3].replace("_", " ").title() if len(parts) >= 4 else "Unknown"

                if product_raw:
                    affected.append({
                        "product_raw":   product_raw,
                        "version_range": ver_range,
                        "oem":           oem,
                    })

    seen     = set()
    deduped  = []
    for a in affected:
        key = (a["product_raw"], a["version_range"])
        if key not in seen:
            seen.add(key)
            deduped.append(a)
    affected = deduped

    records = []

    if affected:
        for a in affected:
            records.append({
                "cve_id":         cve_id,
                "source":         SOURCE_NAME,
                "product_raw":    a["product_raw"],
                "product_norm":   None,          # normalizer fills this
                "version_range":  a["version_range"],
                "oem":            a["oem"],
                "severity":       severity,
                "cvss_score":     cvss_score,
                "description":    description[:2000],
                "mitigation":     _build_mitigation(refs),
                "advisory_url":   advisory_url,
                "published_date": published,
                "_modified":      modified,
                "_cwe":           ", ".join(cwe_ids) if cwe_ids else None,
            })
    else:
        records.append({
            "cve_id":         cve_id,
            "source":         SOURCE_NAME,
            "product_raw":    _infer_product_from_desc(description),
            "product_norm":   None,
            "version_range":  None,
            "oem":            _infer_oem_from_desc(description),
            "severity":       severity,
            "cvss_score":     cvss_score,
            "description":    description[:2000],
            "mitigation":     _build_mitigation(refs),
            "advisory_url":   advisory_url,
            "published_date": published,
            "_modified":      modified,
            "_cwe":           ", ".join(cwe_ids) if cwe_ids else None,
        })

    return records


def _build_mitigation(refs: list[dict]) -> str:
    """Build a mitigation string from NVD references."""
    patch_urls = []
    for ref in refs:
        tags = ref.get("tags", [])
        if any(t in tags for t in ("Patch", "Vendor Advisory", "Mitigation")):
            patch_urls.append(ref.get("url", ""))
    if patch_urls:
        return "Apply vendor patches: " + " | ".join(patch_urls[:3])
    return "Refer to vendor advisory."


def _infer_product_from_desc(desc: str) -> str:
    """Best-effort product extraction from description when CPE unavailable."""
    desc_lower = desc.lower()
    for keyword in RELEVANT_KEYWORDS:
        if keyword in desc_lower:
            return keyword
    return desc[:80] if desc else "unknown"


_OEM_DESC_MAP = [
    ("cisco",      "Cisco"),
    ("fortinet",   "Fortinet"),
    ("juniper",    "Juniper"),
    ("microsoft",  "Microsoft"),
    ("vmware",     "VMware"),
    ("palo alto",  "Palo Alto"),
    ("f5",         "F5"),
    ("siemens",    "Siemens"),
    ("oracle",     "Oracle"),
    ("sap",        "SAP"),
    ("apache",     "Apache"),
    ("google",     "Google"),
    ("apple",      "Apple"),
    ("linux",      "Linux"),
]

def _infer_oem_from_desc(desc: str) -> str:
    desc_lower = desc.lower()
    for keyword, oem in _OEM_DESC_MAP:
        if keyword in desc_lower:
            return oem
    return "Unknown"


def _fetch_nvd_page(
    session: requests.Session,
    params:  dict,
    start_index: int = 0,
) -> Optional[dict]:
    """Fetch a single page from NVD API. Returns raw JSON or None on failure."""
    params = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}

    for attempt in range(3):
        try:
            resp = session.get(NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT)

            if resp.status_code == 403:
                logger.error("NVD API key rejected (403). Check config.py NVD_API_KEY.")
                return None

            if resp.status_code == 429:
                wait = 35  
                logger.warning("NVD rate limited (429). Waiting %ds...", wait)
                time.sleep(wait)
                continue

            if resp.status_code == 503:
                wait = 60
                logger.warning("NVD API unavailable (503). Waiting %ds...", wait)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.Timeout:
            logger.warning("NVD request timeout (attempt %d/3)", attempt + 1)
            time.sleep(5 * (attempt + 1))
        except requests.exceptions.RequestException as e:
            logger.warning("NVD request error (attempt %d/3): %s", attempt + 1, e)
            time.sleep(5 * (attempt + 1))

    logger.error("NVD fetch failed after 3 attempts for params: %s", params)
    return None


def scrape_nvd(
    api_key:    str  = None,
    days_back:  int  = 2,
    keyword:    str  = None,
    severity:   str  = None,
    max_results: int = 10000,
) -> list[dict]:
    """
    Fetch CVEs from NVD modified/published in the last `days_back` days.

    Args:
        api_key:     NVD API key. If None, reads from config.py.
        days_back:   How many days back to fetch. Default 2 (runs every 6h).
        keyword:     Optional keyword filter (e.g. "cisco"). Fetches all if None.
        severity:    Optional severity filter: "CRITICAL", "HIGH", "MEDIUM", "LOW"
        max_results: Safety cap on total results.

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    if api_key is None:
        try:
            from config import NVD_API_KEY
            api_key = NVD_API_KEY
        except ImportError:
            logger.error("No NVD_API_KEY found in config.py")
            return []

    if not api_key:
        logger.error("NVD_API_KEY is empty in config.py")
        return []

    session = _make_session(api_key)

    now       = datetime.now(timezone.utc)
    start_dt  = now - timedelta(days=days_back)
    pub_start = _fmt_nvd_time(start_dt)
    pub_end   = _fmt_nvd_time(now)

    params: dict = {
        "lastModStartDate": pub_start,
        "lastModEndDate":   pub_end,
    }
    if keyword:
        params["keywordSearch"] = keyword
    if severity:
        params["cvssV3Severity"] = severity.upper()

    logger.info(
        "Fetching NVD CVEs modified between %s and %s%s",
        pub_start, pub_end,
        f" (keyword={keyword})" if keyword else ""
    )

    all_records  = []
    start_index  = 0
    total_results = None

    while True:
        data = _fetch_nvd_page(session, params, start_index)
        if data is None:
            logger.error("NVD fetch returned None at startIndex=%d", start_index)
            break

        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info("NVD reports %d total CVEs in range", total_results)

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            records = _parse_cve_item(item)
            all_records.extend(records)

        fetched_so_far = start_index + len(vulnerabilities)
        logger.info(
            "Fetched %d/%d CVEs (%d records so far)",
            fetched_so_far, total_results, len(all_records)
        )

        if len(all_records) >= max_results:
            logger.warning("Hit max_results cap (%d). Stopping.", max_results)
            break

        if fetched_so_far >= total_results:
            break

        start_index += PAGE_SIZE
        time.sleep(REQUEST_DELAY)

    logger.info("NVD scrape complete. Total records: %d", len(all_records))
    return all_records


def scrape_nvd_by_keywords(
    api_key:   str = None,
    days_back: int = 2,
) -> list[dict]:
    """
    Scrape NVD for each keyword in RELEVANT_KEYWORDS separately.
    More targeted than a broad pull — keeps DB focused on PSU-relevant CVEs.
    Use this when you want lean, high-signal data instead of everything.
    """
    if api_key is None:
        try:
            from config import NVD_API_KEY
            api_key = NVD_API_KEY
        except ImportError:
            logger.error("No NVD_API_KEY in config.py")
            return []

    all_records = []
    seen_cves   = set()   

    for keyword in RELEVANT_KEYWORDS:
        logger.info("NVD keyword query: '%s'", keyword)
        records = scrape_nvd(api_key=api_key, days_back=days_back, keyword=keyword)

        for r in records:
            key = (r["cve_id"], r.get("product_raw", ""))
            if key not in seen_cves:
                seen_cves.add(key)
                all_records.append(r)

        time.sleep(1.0)

    logger.info("NVD keyword scrape complete. Total unique records: %d", len(all_records))
    return all_records


def clean_for_db(records: list[dict]) -> list[dict]:
    """Strip internal-only fields before passing to db.insert_cves_bulk()."""
    internal = {"_modified", "_cwe"}
    return [{k: v for k, v in r.items() if k not in internal} for r in records]


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  nvd.py  —  NVD Scraper Self-Test")
    print("=" * 60)

    try:
        from config import NVD_API_KEY
    except ImportError:
        print("[!] config.py not found or NVD_API_KEY not set.")
        sys.exit(1)

    if not NVD_API_KEY:
        print("[!] NVD_API_KEY is empty in config.py")
        sys.exit(1)

    print("\n[Test 1] Fetching Cisco CVEs from last 2 days...")
    results = scrape_nvd(api_key=NVD_API_KEY, days_back=2, keyword="cisco")

    if not results:
        print("[!] No results. Either no Cisco CVEs in last 2 days, or API key issue.")
    else:
        print(f"\n[+] Fetched {len(results)} records\n")
        for r in results[:3]:
            print(f"  CVE        : {r['cve_id']}")
            print(f"  Product    : {r['product_raw']}")
            print(f"  OEM        : {r['oem']}")
            print(f"  Severity   : {r['severity']} (CVSS: {r['cvss_score']})")
            print(f"  Version    : {r['version_range']}")
            print(f"  Date       : {r['published_date']}")
            print(f"  CWE        : {r.get('_cwe')}")
            print(f"  URL        : {r['advisory_url']}")
            print()

    print("[Test 2] Fetching CRITICAL CVEs from last 1 day...")
    critical = scrape_nvd(api_key=NVD_API_KEY, days_back=1, severity="CRITICAL")
    print(f"[+] Found {len(critical)} CRITICAL records in last 24h\n")

    db_ready = clean_for_db(critical[:2])
    print(f"[Test 3] DB-ready record keys: {list(db_ready[0].keys()) if db_ready else 'N/A'}")

    print("\n" + "=" * 60)
    print(f"  Done. Total records from Test 1: {len(results)}")
    print("=" * 60)