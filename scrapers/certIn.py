"""
Scraper for CERT-In (Indian Computer Emergency Response Team) advisories
and vulnerability notes.

Sources:
    - Advisories  : https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year=YYYY
    - Vuln Notes  : https://www.cert-in.org.in/s2cMainServlet?pageid=VLNLIST02&year=YYYY
    - Detail page : https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=<code>

Both advisory (CIAD-) and vulnerability note (CIVN-) detail pages share the
same HTML structure, so one parser handles both.

"""

import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

BASE_URL        = "https://www.cert-in.org.in"
ADV_LIST_URL    = BASE_URL + "/s2cMainServlet?pageid=PUBADVLIST02&year={year}"
VLN_LIST_URL    = BASE_URL + "/s2cMainServlet?pageid=VLNLIST02&year={year}"
DETAIL_URL      = BASE_URL + "/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE={code}"

SOURCE_NAME     = "certIn"
REQUEST_DELAY   = 1.5 
REQUEST_TIMEOUT = 20    

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "moderate": "MEDIUM",
    "low":      "LOW",
}

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

_DATE_RE = re.compile(
    r'(January|February|March|April|May|June|July|August|September|October|November|December)'
    r'\s+(\d{1,2}),?\s+(\d{4})',
    re.IGNORECASE
)
_MONTH_MAP = {
    "january": "01", "february": "02", "march": "03", "april": "04",
    "may": "05", "june": "06", "july": "07", "august": "08",
    "september": "09", "october": "10", "november": "11", "december": "12",
}


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": BASE_URL,
    })
    return s


def _get(session: requests.Session, url: str) -> Optional[BeautifulSoup]:
    """Fetch a URL and return a BeautifulSoup object, or None on failure."""
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        resp.encoding = resp.apparent_encoding or "iso-8859-1"
        return BeautifulSoup(resp.text, "html.parser")
    except requests.RequestException as e:
        logger.warning("GET failed for %s: %s", url, e)
        return None


def _parse_date(raw: str) -> Optional[str]:
    """Parse CERT-In date strings → ISO-8601 (YYYY-MM-DD)."""
    m = _DATE_RE.search(raw)
    if not m:
        return None
    month = _MONTH_MAP[m.group(1).lower()]
    day   = m.group(2).zfill(2)
    year  = m.group(3)
    return f"{year}-{month}-{day}"


def _parse_severity(raw: str) -> str:
    """Normalise 'Severity Rating: High' → 'HIGH'."""
    raw_lower = raw.lower()
    for key, val in _SEVERITY_MAP.items():
        if key in raw_lower:
            return val
    return "UNKNOWN"


def _extract_text(tag) -> str:
    if tag is None:
        return ""
    text = tag.get_text(separator=" ")
    text = text.replace("Æ", "®").replace("ô", "™").replace("©", "©")
    return re.sub(r'\s+', ' ', text).strip()


def _parse_listing(soup: BeautifulSoup) -> tuple[list[dict], Optional[str]]:
    entries = []
    for a_tag in soup.find_all("a", href=re.compile(r'VLCODE=')):
        href = a_tag.get("href", "")
        m = re.search(r'VLCODE=([A-Z0-9-]+)', href)
        if not m:
            continue
        code  = m.group(1)
        title = _extract_text(a_tag)

        date_str = ""
        parent_td = a_tag.find_parent("td")
        if parent_td:
            parent_tr = parent_td.find_parent("tr")
            if parent_tr:
                next_tr = parent_tr.find_next_sibling("tr")
                if next_tr:
                    date_str = _extract_text(next_tr)

        entries.append({
            "code":  code,
            "title": title,
            "date":  _parse_date(date_str) or "",
        })

    next_url = None
    next_link = soup.find("a", string=re.compile(r'Next', re.IGNORECASE))
    if next_link and next_link.get("href"):
        href = next_link["href"]
        if href.startswith("/"):
            next_url = BASE_URL + href
        elif href.startswith("http"):
            next_url = href
        elif not href.startswith("http"):
            next_url = BASE_URL + "/" + href.lstrip("/")

    logger.debug("Found %d entries on listing page, next=%s", len(entries), next_url)
    return entries, next_url


def _parse_detail(soup: BeautifulSoup, code: str, list_date: str) -> Optional[list]:
    """
    Parse a CERT-In advisory/vuln-note detail page into a normalised CVE dict.

    Fields extracted:
        advisory_id, title, published_date, severity, software_affected,
        description, solution/mitigation, advisory_url, cve_ids, version_range
    """
    content = soup.find("div", id="print_content")
    if not content:
        content = soup.find("body") or soup

    full_text = content.get_text(separator="\n")

    advisory_id = code
    title_tag   = content.find("span", class_=re.compile(r'subhead|ContentTD'))
    title       = _extract_text(title_tag) if title_tag else code
    bold_tag    = content.find("b")
    description_title = _extract_text(bold_tag) if bold_tag else title

    published_date = list_date
    date_match = re.search(r'Original Issue Date[:\s]+(.+)', full_text)
    if date_match:
        parsed = _parse_date(date_match.group(1))
        if parsed:
            published_date = parsed

    severity   = "UNKNOWN"
    sev_match  = re.search(r'Severity Rating[:\s]+(\w+)', full_text, re.IGNORECASE)
    if sev_match:
        severity = _parse_severity(sev_match.group(1))

    software_affected = []
    for p_tag in content.find_all("p"):
        if "software affected" in _extract_text(p_tag).lower():
            next_el = p_tag.find_next_sibling()
            if next_el:
                software_affected = [
                    _extract_text(li) for li in next_el.find_all("li")
                    if _extract_text(li)
                ]
            break

    description = ""
    desc_match  = re.search(
        r'Description\s*\n+(.*?)(?=Solution|Vendor Information|$)',
        full_text, re.DOTALL | re.IGNORECASE
    )
    if desc_match:
        description = re.sub(r'\s+', ' ', desc_match.group(1)).strip()
    if not description:
        overview_match = re.search(
            r'Overview\s*\n+(.*?)(?=Description|Solution|$)',
            full_text, re.DOTALL | re.IGNORECASE
        )
        if overview_match:
            description = re.sub(r'\s+', ' ', overview_match.group(1)).strip()
    description = description[:2000]

    mitigation = ""
    sol_match  = re.search(
        r'Solution\s*\n+(.*?)(?=Vendor Information|References|$)',
        full_text, re.DOTALL | re.IGNORECASE
    )
    if sol_match:
        mitigation = re.sub(r'\s+', ' ', sol_match.group(1)).strip()[:1000]

    cve_ids  = list(set(_CVE_RE.findall(full_text)))
    url_cves = re.findall(r'vulnerability/(CVE-\d{4}-\d{4,7})', full_text, re.IGNORECASE)
    cve_ids  = list(set(cve_ids + [c.upper() for c in url_cves]))

    version_range = None
    ver_match = re.search(
        r'versions?\s+(prior to|before|up to|through|earlier than)\s+([^\.<\n]+)',
        full_text, re.IGNORECASE
    )
    if ver_match:
        version_range = f"< {ver_match.group(2).strip()}"

    oem = _infer_oem(description_title, software_affected)

    advisory_url = DETAIL_URL.format(code=code)

    records = []

    if cve_ids:
        for cve_id in cve_ids:
            records.append(_build_record(
                cve_id        = cve_id,
                advisory_id   = advisory_id,
                title         = description_title,
                published_date= published_date,
                severity      = severity,
                software_list = software_affected,
                description   = description,
                mitigation    = mitigation,
                advisory_url  = advisory_url,
                oem           = oem,
                version_range = version_range,
            ))
    else:
        records.append(_build_record(
            cve_id        = advisory_id,
            advisory_id   = advisory_id,
            title         = description_title,
            published_date= published_date,
            severity      = severity,
            software_list = software_affected,
            description   = description,
            mitigation    = mitigation,
            advisory_url  = advisory_url,
            oem           = oem,
            version_range = version_range,
        ))

    return records


def _build_record(cve_id, advisory_id, title, published_date, severity,
                  software_list, description, mitigation, advisory_url, oem,
                  version_range=None) -> dict:
    """Construct a db.py-compatible CVE record dict."""
    product_raw  = software_list[0] if software_list else title
    product_norm = None

    return {
        "cve_id":         cve_id,
        "source":         SOURCE_NAME,
        "product_raw":    product_raw,
        "product_norm":   product_norm,
        "version_range":  version_range,
        "oem":            oem,
        "severity":       severity,
        "cvss_score":     None,
        "description":    description or title,
        "mitigation":     mitigation,
        "advisory_url":   advisory_url,
        "published_date": published_date,
        "_software_list": software_list,
        "_advisory_id":   advisory_id,
        "_title":         title,
    }


_OEM_KEYWORDS = [
    ("cisco",      "Cisco"),
    ("microsoft",  "Microsoft"),
    ("intel",      "Intel"),
    ("fortinet",   "Fortinet"),
    ("juniper",    "Juniper"),
    ("palo alto",  "Palo Alto"),
    ("vmware",     "VMware"),
    ("broadcom",   "Broadcom"),
    ("oracle",     "Oracle"),
    ("google",     "Google"),
    ("android",    "Google"),
    ("apple",      "Apple"),
    ("sap",        "SAP"),
    ("atlassian",  "Atlassian"),
    ("f5",         "F5"),
    ("siemens",    "Siemens"),
    ("linux",      "Linux"),
    ("ubuntu",     "Canonical"),
    ("red hat",    "Red Hat"),
    ("apache",     "Apache"),
]

def _infer_oem(title: str, software_list: list[str]) -> str:
    combined = (title + " " + " ".join(software_list)).lower()
    for keyword, oem in _OEM_KEYWORDS:
        if keyword in combined:
            return oem
    return "Unknown"


def scrape_certIn(
    years: list[int] = None,
    max_per_year: int = 200,
) -> list[dict]:
    """
    Scrape CERT-In advisories and vulnerability notes.

    Args:
        years:        List of years to scrape. Defaults to current year only.
        max_per_year: Max entries to fetch per year per source type (safety cap).
                      Default raised to 200 to handle full-year pagination.

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    if years is None:
        years = [datetime.now(timezone.utc).year]

    session  = _make_session()
    all_cves = []

    for year in years:
        for list_url_tmpl, source_label in [
            (ADV_LIST_URL, "advisory"),
            (VLN_LIST_URL, "vuln_note"),
        ]:
            current_url  = list_url_tmpl.format(year=year)
            page_num     = 1
            year_entries = []

            while current_url:
                logger.info(
                    "Fetching CERT-In %s list for %d (page %d): %s",
                    source_label, year, page_num, current_url
                )

                soup = _get(session, current_url)
                if soup is None:
                    logger.warning(
                        "Skipping %s %d page %d — fetch failed",
                        source_label, year, page_num
                    )
                    break

                entries, next_url = _parse_listing(soup)
                if not entries:
                    logger.info(
                        "No entries on page %d for %s %d — stopping",
                        page_num, source_label, year
                    )
                    break

                year_entries.extend(entries)
                logger.info(
                    "Page %d: %d entries (running total: %d)",
                    page_num, len(entries), len(year_entries)
                )

                if len(year_entries) >= max_per_year:
                    logger.info(
                        "Hit max_per_year cap (%d) for %s %d, stopping pagination",
                        max_per_year, source_label, year
                    )
                    year_entries = year_entries[:max_per_year]
                    break

                current_url = next_url
                page_num   += 1
                if next_url:
                    time.sleep(REQUEST_DELAY)

            if not year_entries:
                logger.info("No entries found for %s %d", source_label, year)
                continue

            logger.info(
                "Total %d %s entries for %d across %d page(s)",
                len(year_entries), source_label, year, page_num
            )

            for entry in year_entries:
                code       = entry["code"]
                detail_url = DETAIL_URL.format(code=code)

                logger.debug("Fetching detail: %s", detail_url)
                time.sleep(REQUEST_DELAY)

                detail_soup = _get(session, detail_url)
                if detail_soup is None:
                    logger.warning("Skipping %s — failed to fetch detail page", code)
                    continue

                records = _parse_detail(detail_soup, code, entry["date"])
                if records:
                    all_cves.extend(records)
                    logger.debug("Parsed %d records from %s", len(records), code)

    logger.info("CERT-In scrape complete. Total records: %d", len(all_cves))
    return all_cves


def clean_for_db(records: list[dict]) -> list[dict]:
    """
    Remove scraper-internal fields (prefixed with '_') before passing
    records to db.insert_cves_bulk().
    """
    internal_keys = {"_software_list", "_advisory_id", "_title"}
    return [{k: v for k, v in r.items() if k not in internal_keys} for r in records]


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  certIn.py  —  CERT-In Scraper Self-Test")
    print("=" * 60)

    results = scrape_certIn(years=[2026], max_per_year=3)

    if not results:
        print("\n[!] No results returned. Check network / CERT-In availability.")
        sys.exit(1)

    print(f"\n[+] Fetched {len(results)} records\n")
    for r in results[:5]:
        print(f"  CVE/ID   : {r['cve_id']}")
        print(f"  Source   : {r['source']}")
        print(f"  Title    : {r.get('_title', r['description'][:60])}")
        print(f"  Severity : {r['severity']}")
        print(f"  OEM      : {r['oem']}")
        print(f"  Product  : {r['product_raw'][:60]}")
        print(f"  Date     : {r['published_date']}")
        print(f"  URL      : {r['advisory_url']}")
        sw = r.get('_software_list', [])
        print(f"  SW count : {len(sw)} affected products")
        print()

    print("=" * 60)
    print(f"  Done. DB-ready records: {len(clean_for_db(results))}")
    print("=" * 60)