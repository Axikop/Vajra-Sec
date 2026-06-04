"""
Scraper for Microsoft Security Response Center (MSRC) using the
official CVRF v2.0 API — no scraping, pure JSON.

API docs: https://msrc.microsoft.com/update-guide/vulnerability (API tab)
Base URL : https://api.msrc.microsoft.com/cvrf/v2.0/

Endpoints used:
    /updates          — list all monthly security update IDs
    /cvrf/{YYYY-Mon}  — full advisory bundle for that month

Microsoft publishes Patch Tuesday every 2nd Tuesday of the month.
We fetch the current month and previous month to catch recent updates.

Usage:
    from scrapers.microsoft import scrape_microsoft
    records = scrape_microsoft()           # current + last month
    records = scrape_microsoft(months=3)   # last 3 months
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

BASE_URL        = "https://api.msrc.microsoft.com/cvrf/v2.0"
UPDATES_URL     = BASE_URL + "/updates"
CVRF_URL        = BASE_URL + "/cvrf/{month_id}"
ADVISORY_URL    = "https://msrc.microsoft.com/update-guide/en-US/vulnerability/{cve_id}"
SOURCE_NAME     = "microsoft"
REQUEST_TIMEOUT = 30

_CVSS_SEVERITY = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]

_PRODUCT_MAP = {
    "windows":              "microsoft_windows_10",
    "windows 10":           "microsoft_windows_10",
    "windows 11":           "microsoft_windows_11",
    "windows server 2022":  "microsoft_windows_server_2022",
    "windows server 2019":  "microsoft_windows_server_2019",
    "windows server 2016":  "microsoft_windows_server_2016",
    "exchange server":      "microsoft_exchange",
    "sharepoint":           "microsoft_sharepoint",
    "sql server":           "microsoft_sql_server",
    "iis":                  "microsoft_iis",
    "internet information": "microsoft_iis",
    ".net":                 "microsoft_dotnet",
    "office":               "microsoft_office",
    "microsoft 365":        "microsoft_office_365",
    "teams":                "microsoft_teams",
    "edge":                 "microsoft_edge",
    "azure active directory":"microsoft_azure_ad",
    "active directory":     "microsoft_active_directory",
    "azure":                "microsoft_azure",
    "hyper-v":              "microsoft_hyperv",
    "defender":             "microsoft_defender",
    "remote desktop":       "microsoft_rdp",
    "rdp":                  "microsoft_rdp",
    "power bi":             "microsoft_power_bi",
    "skype":                "microsoft_skype_business",
}

_SKIP_TAGS = {
    "microsoft edge for android",
    "github repo",
    "xbox",
    "mariner",
    "chromium",
}

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Accept":     "application/json",
        "User-Agent": "NTRO-CVE-Monitor/1.0",
    })
    return s


def _get_json(session: requests.Session, url: str) -> Optional[dict]:
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("GET failed for %s: %s", url, e)
        return None


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    for threshold, label in _CVSS_SEVERITY:
        if score >= threshold:
            return label
    return "UNKNOWN"


def _parse_cvss_score(vector: str) -> Optional[float]:
    """Extract base score from CVSS vector string if score not provided."""
    if not vector:
        return None
    return None  # Score comes from DocumentNotes table directly


def _normalise_product(tag: str) -> str:
    """Map Microsoft product tag to normalised product name."""
    tag_lower = tag.lower().strip()
    for keyword, norm in _PRODUCT_MAP.items():
        if keyword in tag_lower:
            return norm
    slug = re.sub(r'[^a-z0-9]+', '_', tag_lower).strip('_')
    return f"microsoft_{slug}" if slug else "microsoft"


def _should_skip(tag: str) -> bool:
    return tag.lower().strip() in _SKIP_TAGS


def _parse_cvrf(data: dict, month_id: str) -> list[dict]:
    """
    Parse a CVRF JSON document into DB-ready CVE records.

    The CVRF document structure:
        DocumentNotes[0].Value  — HTML table with all CVEs, scores, tags
        Vulnerability[]         — array of individual CVE objects
    """
    records = []


    cve_scores: dict[str, dict] = {}   # cve_id → {score, vector, tag}

    notes = data.get("DocumentNotes", [])
    for note in notes:
        html = note.get("Value", "")
        if not html or "CVE" not in html:
            continue

        rows = re.findall(
            r'<td>([^<]+)</td>\s*<td><a[^>]+>(\bCVE-\d{4}-\d{4,7}\b)</a></td>\s*<td>([\d.]+)</td>\s*<td>([^<]*)</td>',
            html, re.IGNORECASE
        )
        for tag, cve_id, score_str, vector in rows:
            tag    = tag.strip()
            cve_id = cve_id.upper()
            try:
                score = float(score_str)
            except ValueError:
                score = None

            if cve_id not in cve_scores:
                cve_scores[cve_id] = {
                    "score":  score,
                    "vector": vector.strip(),
                    "tag":    tag,
                }

    logger.info("[Microsoft] %s: found %d CVEs in release notes table", month_id, len(cve_scores))

    # ── Parse individual Vulnerability objects ────────────────────────────────
    vulnerabilities = data.get("Vulnerability", [])

    for vuln in vulnerabilities:
        cve_id = vuln.get("CVE", "").upper()
        if not cve_id or not _CVE_RE.match(cve_id):
            continue

        title = ""
        title_obj = vuln.get("Title", {})
        if isinstance(title_obj, dict):
            title = title_obj.get("Value", "")

        description = title
        for note in vuln.get("Notes", []):
            if note.get("Type") == 1 or note.get("Title", "").lower() == "description":
                description = note.get("Value", title)
                description = re.sub(r'<[^>]+>', ' ', description)
                description = re.sub(r'\s+', ' ', description).strip()[:2000]
                break

        published = ""
        disc = vuln.get("DiscoveryDateSpecified", False)
        release_dates = vuln.get("ReleaseDateSpecified", False)
        for note in vuln.get("RevisionHistory", []):
            date_str = note.get("Date", "")
            if date_str:
                published = date_str[:10]
                break
        if not published:
            published = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Remediations → mitigation text
        mitigation = "Apply Microsoft security updates via Windows Update."
        remediations = vuln.get("Remediations", [])
        patch_urls = []
        for rem in remediations:
            url = rem.get("URL", "")
            if url and "microsoft.com" in url:
                patch_urls.append(url)
        if patch_urls:
            mitigation = "Apply patches: " + " | ".join(patch_urls[:2])

        # Score + tag from release notes table
        score_info   = cve_scores.get(cve_id, {})
        cvss_score   = score_info.get("score")
        tag          = score_info.get("tag", "Microsoft Windows")
        severity     = _cvss_to_severity(cvss_score)

        # Skip irrelevant products
        if _should_skip(tag):
            continue

        product_norm = _normalise_product(tag)
        advisory_url = ADVISORY_URL.format(cve_id=cve_id)

        records.append({
            "cve_id":         cve_id,
            "source":         SOURCE_NAME,
            "product_raw":    tag,
            "product_norm":   product_norm,
            "version_range":  None,   
            "oem":            "Microsoft",
            "severity":       severity,
            "cvss_score":     cvss_score,
            "description":    description or title,
            "mitigation":     mitigation,
            "advisory_url":   advisory_url,
            "published_date": published,
            "_month":         month_id,
            "_tag":           tag,
        })

    logger.info("[Microsoft] %s: parsed %d CVE records", month_id, len(records))
    return records


def _current_month_ids(months: int = 2) -> list[str]:
    """
    Generate month IDs like '2026-Mar', '2026-Feb' for last N months.
    Microsoft uses 3-letter month abbreviations.
    """
    now    = datetime.now(timezone.utc)
    result = []
    year   = now.year
    month  = now.month

    for _ in range(months):
        dt = datetime(year, month, 1)
        result.append(dt.strftime("%Y-%b"))
        month -= 1
        if month == 0:
            month = 12
            year -= 1

    return result


def _get_valid_month_ids(session: requests.Session, months: int) -> list[str]:
    """
    Get month IDs that actually exist in the MSRC API.
    Cross-references with /updates listing to avoid 404s.
    """
    wanted   = set(_current_month_ids(months))
    data     = _get_json(session, UPDATES_URL)
    if not data:
        return list(wanted)

    available = {item["ID"] for item in data.get("value", [])}
    valid     = [m for m in _current_month_ids(months) if m in available]

    if not valid:
        logger.warning("[Microsoft] None of %s found in updates listing — using anyway", wanted)
        return list(wanted)

    return valid


def scrape_microsoft(months: int = 2) -> list[dict]:
    """
    Scrape Microsoft MSRC for the last `months` Patch Tuesday releases.

    Args:
        months: How many monthly releases to fetch. Default 2 (current + last).

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    session     = _make_session()
    all_records = []

    month_ids = _get_valid_month_ids(session, months)
    logger.info("[Microsoft] Fetching months: %s", month_ids)

    for month_id in month_ids:
        url  = CVRF_URL.format(month_id=month_id)
        logger.info("[Microsoft] Fetching CVRF: %s", url)

        data = _get_json(session, url)
        if not data:
            logger.warning("[Microsoft] Skipping %s — fetch failed", month_id)
            continue

        records = _parse_cvrf(data, month_id)
        all_records.extend(records)

    seen    = set()
    deduped = []
    for r in all_records:
        if r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            deduped.append(r)

    logger.info(
        "[Microsoft] Scrape complete. %d total → %d unique CVEs",
        len(all_records), len(deduped)
    )
    return deduped


def clean_for_db(records: list[dict]) -> list[dict]:
    """Strip internal fields before passing to db.insert_cves_bulk()."""
    internal = {"_month", "_tag"}
    return [{k: v for k, v in r.items() if k not in internal} for r in records]


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  microsoft.py  —  MSRC Scraper Self-Test")
    print("=" * 60)

    results = scrape_microsoft(months=1)

    if not results:
        print("[!] No results returned.")
        sys.exit(1)

    db_ready = clean_for_db(results)

    by_sev = {}
    for r in results:
        by_sev.setdefault(r["severity"], 0)
        by_sev[r["severity"]] += 1

    print(f"\n[+] Fetched {len(results)} unique CVEs")
    print(f"    Severity breakdown: {by_sev}\n")

    shown = 0
    for r in results:
        if r["severity"] not in ("CRITICAL", "HIGH"):
            continue
        if shown >= 5:
            break
        print(f"  CVE        : {r['cve_id']}")
        print(f"  Severity   : {r['severity']} (CVSS: {r['cvss_score']})")
        print(f"  Product    : {r['product_raw']} → {r['product_norm']}")
        print(f"  Published  : {r['published_date']}")
        print(f"  URL        : {r['advisory_url']}")
        print()
        shown += 1

    print("=" * 60)
    print(f"  DB-ready records: {len(db_ready)}")
    print("=" * 60)