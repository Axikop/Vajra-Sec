"""

Uses two endpoints:
    1. publicationService.x  — JSON listing API (fast, no scraping)
    2. Advisory detail page  — HTML page for CVEs, severity, products

The listing API returns up to 20 advisories per page with full metadata.
We filter by lastPublished date to only fetch recent advisories.

"""

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

BASE_URL        = "https://sec.cloudapps.cisco.com"
LISTING_API     = BASE_URL + "/security/center/publicationService.x"
DETAIL_URL      = BASE_URL + "/security/center/content/CiscoSecurityAdvisory/{identifier}"
SOURCE_NAME     = "cisco"
REQUEST_DELAY   = 1.0
REQUEST_TIMEOUT = 20

# Cisco severity labels → normalised
_SEVERITY_MAP = {
    "critical":      "CRITICAL",
    "high":          "HIGH",
    "medium":        "MEDIUM",
    "moderate":      "MEDIUM",
    "low":           "LOW",
    "informational": "LOW",
}

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Known Cisco product → normalised name mapping
_PRODUCT_MAP = {
    "ios xe":          "cisco_ios_xe",
    "ios xr":          "cisco_ios_xr",
    "nx-os":           "cisco_nxos",
    "asa":             "cisco_asa",
    "firepower":       "cisco_firepower",
    "ftd":             "cisco_ftd",
    "fmc":             "cisco_firepower",
    "anyconnect":      "cisco_anyconnect",
    "sd-wan":          "cisco_sdwan",
    "webex":           "cisco_webex",
    "catalyst":        "cisco_catalyst_switch",
    "meraki":          "cisco_meraki",
    "umbrella":        "cisco_umbrella",
    "identity services engine": "cisco_ise",
    "ise":             "cisco_ise",
}

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "Referer":    BASE_URL + "/security/center/publicationListing.x",
        "Accept":     "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
    })
    return s


def _get_html(session: requests.Session, url: str) -> Optional[BeautifulSoup]:
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, "html.parser")
    except requests.RequestException as e:
        logger.warning("GET failed for %s: %s", url, e)
        return None


def _fetch_listing_page(
    session:   requests.Session,
    page_num:  int,
    rows:      int = 20,
) -> Optional[list[dict]]:
    """
    POST to publicationService.x and return list of advisory dicts.
    Returns None on failure.
    """
    payload = {
        "pageNum":              page_num,
        "rowsPerPage":          rows,
        "criteria":             "exact",
        "publicationTypeIDs":   "1",    # 1 = Security Advisory
        "isRenderingBugList":   "false",
        "sortBy":               "lastPublished",
        "orderBy":              "desc",
    }
    try:
        resp = session.post(
            LISTING_API,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("Listing API page %d failed: %s", page_num, e)
        return None


def _parse_detail(
    soup:       BeautifulSoup,
    identifier: str,
    summary:    str,
) -> dict:
    """
    Parse a Cisco advisory detail HTML page.
    Extracts: severity, CVSS score, CVE IDs, affected products.
    """
    severity = "UNKNOWN"
    sev_tag  = soup.find(id="severitycirclecontent")
    if sev_tag:
        severity = _SEVERITY_MAP.get(sev_tag.get_text().strip().lower(), "UNKNOWN")

    # ── CVSS score ────────────────────────────────────────────────────────────
    cvss_score = None
    # Look for pattern like "9.8" near CVSS text
    cvss_match = re.search(
        r'CVSS(?:\s+v\d)?(?:\s+Base)?\s+Score[:\s]+(\d+\.\d+)',
        soup.get_text(), re.IGNORECASE
    )
    if not cvss_match:
        # Try finding score in the severity circle area
        cvss_match = re.search(
            r'"score"\s*:\s*(\d+\.\d+)',
            str(soup)
        )
    if cvss_match:
        try:
            cvss_score = float(cvss_match.group(1))
        except ValueError:
            pass

    # ── CVE IDs ───────────────────────────────────────────────────────────────
    cve_ids = []
    # Primary: CVEList divs
    for cve_div in soup.find_all("div", class_="CVEList"):
        for inner in cve_div.find_all("div", class_="inlineblock"):
            text = inner.get_text().strip()
            if _CVE_RE.match(text):
                cve_ids.append(text.upper())

    # Fallback: regex scan full page
    if not cve_ids:
        cve_ids = list(set(_CVE_RE.findall(soup.get_text())))

    cve_ids = list(set(cve_ids))

    # ── Affected products ─────────────────────────────────────────────────────
    products = []
    vuln_div = soup.find(id="vulnerableproducts")
    if vuln_div:
        text = vuln_div.get_text(separator=" ")
        # Extract product names from known Cisco product list
        text_lower = text.lower()
        for keyword, norm in _PRODUCT_MAP.items():
            if keyword in text_lower:
                products.append(norm)
        products = list(set(products))

    # ── Mitigation ────────────────────────────────────────────────────────────
    mitigation = ""
    fixed_div  = soup.find(id="fixedsoftware") or soup.find(id="fs")
    if fixed_div:
        mitigation = fixed_div.get_text(separator=" ")[:800].strip()
    if not mitigation:
        mitigation = "Apply Cisco software updates. See advisory for details."

    return {
        "severity":  severity,
        "cvss_score": cvss_score,
        "cve_ids":   cve_ids,
        "products":  products,
        "mitigation": mitigation,
    }


def _infer_product(title: str, products: list[str]) -> str:
    """Pick best product_raw from title or parsed product list."""
    if products:
        return products[0]
    title_lower = title.lower()
    for keyword, norm in _PRODUCT_MAP.items():
        if keyword in title_lower:
            return norm
    return "cisco"


def _build_records(
    advisory:  dict,
    detail:    dict,
) -> list[dict]:
    """
    Build DB-ready records from listing advisory + parsed detail.
    One record per CVE if CVEs found, else one record per advisory.
    """
    identifier    = advisory["identifier"]
    title         = advisory["title"]
    summary       = advisory.get("summary", "")
    advisory_url  = advisory.get("url", DETAIL_URL.format(identifier=identifier))
    published     = (advisory.get("firstPublished") or "")[:10]
    severity      = detail["severity"]
    cvss_score    = detail["cvss_score"]
    cve_ids       = detail["cve_ids"]
    products      = detail["products"]
    mitigation    = detail["mitigation"]

    product_raw = _infer_product(title, products)

    base = {
        "source":        SOURCE_NAME,
        "product_raw":   product_raw,
        "product_norm":  None,          # normalizer fills this
        "version_range": None,          # Cisco advisories rarely give ranges
        "oem":           "Cisco",
        "severity":      severity,
        "cvss_score":    cvss_score,
        "description":   _clean_html(summary)[:2000],
        "mitigation":    mitigation,
        "advisory_url":  advisory_url,
        "published_date": published,
        "_identifier":   identifier,
        "_title":        title,
        "_products":     products,
    }

    if cve_ids:
        return [{**base, "cve_id": cve_id} for cve_id in cve_ids]
    else:
        return [{**base, "cve_id": identifier}]


def _clean_html(text: str) -> str:
    """Strip HTML tags and normalise whitespace."""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def scrape_cisco(
    days_back:   int = 2,
    max_results: int = 200,
) -> list[dict]:
    """
    Scrape Cisco Security Advisories published/modified in last `days_back` days.

    Args:
        days_back:   How many days back to look. Default 2 (runs every 6h).
        max_results: Safety cap on total advisories to process.

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    session   = _make_session()
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days_back)
    cutoff    = cutoff_dt.strftime("%Y-%m-%d")

    logger.info("[Cisco] Fetching advisories modified since %s", cutoff)

    all_records  = []
    page_num     = 1
    processed    = 0

    while processed < max_results:
        data = _fetch_listing_page(session, page_num, rows=20)
        if not data:
            logger.warning("[Cisco] Listing API returned nothing on page %d", page_num)
            break

        # Filter by date
        recent = []
        stop   = False
        for adv in data:
            last_pub = (adv.get("lastPublished") or "")[:10]
            if last_pub >= cutoff:
                recent.append(adv)
            else:
                # Results are sorted by lastPublished desc — stop when too old
                stop = True
                break

        logger.info(
            "[Cisco] Page %d: %d total entries, %d recent",
            page_num, len(data), len(recent)
        )

        for advisory in recent:
            if processed >= max_results:
                break

            identifier  = advisory["identifier"]
            detail_url  = DETAIL_URL.format(identifier=identifier)

            logger.debug("[Cisco] Fetching detail: %s", detail_url)
            time.sleep(REQUEST_DELAY)

            soup = _get_html(session, detail_url)
            if soup is None:
                logger.warning("[Cisco] Skipping %s — detail fetch failed", identifier)
                continue

            detail  = _parse_detail(soup, identifier, advisory.get("summary", ""))
            records = _build_records(advisory, detail)
            all_records.extend(records)
            processed += 1

            logger.debug(
                "[Cisco] %s → severity=%s, CVEs=%d, records=%d",
                identifier, detail["severity"], len(detail["cve_ids"]), len(records)
            )

        if stop or len(data) < 20:
            break

        page_num += 1
        time.sleep(REQUEST_DELAY)

    logger.info("[Cisco] Scrape complete. %d advisories → %d records", processed, len(all_records))
    return all_records


def clean_for_db(records: list[dict]) -> list[dict]:
    """Strip internal fields before passing to db.insert_cves_bulk()."""
    internal = {"_identifier", "_title", "_products"}
    return [{k: v for k, v in r.items() if k not in internal} for r in records]


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  cisco.py  —  Cisco Advisory Scraper Self-Test")
    print("=" * 60)

    results = scrape_cisco(days_back=30, max_results=5)

    if not results:
        print("[!] No results returned.")
        sys.exit(1)

    db_ready = clean_for_db(results)
    print(f"\n[+] Fetched {len(results)} records from {len(set(r.get('_identifier','') for r in results))} advisories\n")

    seen = set()
    for r in results[:8]:
        key = r.get("_identifier", r["cve_id"])
        if key in seen:
            continue
        seen.add(key)
        print(f"  Advisory  : {r.get('_identifier', 'N/A')}")
        print(f"  CVE ID    : {r['cve_id']}")
        print(f"  Title     : {r.get('_title', '')[:60]}")
        print(f"  Severity  : {r['severity']} (CVSS: {r['cvss_score']})")
        print(f"  Product   : {r['product_raw']}")
        print(f"  Published : {r['published_date']}")
        print(f"  URL       : {r['advisory_url']}")
        print()

    print("=" * 60)
    print(f"  DB-ready records: {len(db_ready)}")
    print("=" * 60)