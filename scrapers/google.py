"""
scrapers/google.py
------------------
Scraper for Google / Chrome / Android vulnerabilities.

Design decision: Google Chrome CVEs are published to NVD within
24 hours of a Chrome release — faster than most OEMs. A dedicated
blog scraper adds no meaningful speed advantage over NVD for Chrome.

This module is a focused NVD query for Google products, with source
tagged as 'google' so alerts clearly identify the vendor.

Products covered:
    - Google Chrome (desktop + mobile)
    - Google Android
    - Google Chrome OS
    - V8 JavaScript engine
    - Google Pixel firmware

Usage:
    from scrapers.google import scrape_google
    records = scrape_google()
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Google product keywords to query NVD for
GOOGLE_KEYWORDS = [
    "chrome",
    "android",
    "chromeos",
    "v8 javascript",
    "google pixel",
]

SOURCE_NAME = "google"


def scrape_google(
    api_key:   Optional[str] = None,
    days_back: int = 2,
) -> list[dict]:
    """
    Fetch Google/Chrome/Android CVEs from NVD.

    Args:
        api_key:   NVD API key. If None, reads from config.py.
        days_back: How many days back to look. Default 2.

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    # ── Load API key ──────────────────────────────────────────────────────────
    if api_key is None:
        try:
            from config import NVD_API_KEY
            api_key = NVD_API_KEY
        except ImportError:
            logger.error("[Google] No NVD_API_KEY in config.py")
            return []

    from scrapers.nvd import scrape_nvd, clean_for_db

    all_records = []
    seen_cves   = set()

    for keyword in GOOGLE_KEYWORDS:
        logger.info("[Google] Querying NVD for keyword: '%s'", keyword)

        records = clean_for_db(
            scrape_nvd(api_key=api_key, days_back=days_back, keyword=keyword)
        )

        for r in records:
            if r["cve_id"] not in seen_cves:
                seen_cves.add(r["cve_id"])
                r["source"] = SOURCE_NAME   # override source tag
                all_records.append(r)

    logger.info("[Google] Scrape complete. %d unique CVE records", len(all_records))
    return all_records


def clean_for_db(records: list[dict]) -> list[dict]:
    """Pass-through — records are already DB-ready from NVD."""
    return records


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  google.py  —  Google/Chrome CVE Scraper Self-Test")
    print("=" * 60)

    results = scrape_google(days_back=30)

    if not results:
        print("[!] No results — no Google CVEs in last 30 days or API key issue.")
        sys.exit(0)

    by_sev = {}
    for r in results:
        by_sev.setdefault(r["severity"], 0)
        by_sev[r["severity"]] += 1

    print(f"\n[+] Fetched {len(results)} unique Google/Chrome CVEs")
    print(f"    Severity breakdown: {by_sev}\n")

    for r in results[:5]:
        print(f"  CVE      : {r['cve_id']}")
        print(f"  Severity : {r['severity']} (CVSS: {r['cvss_score']})")
        print(f"  Product  : {r['product_raw']}")
        print(f"  Source   : {r['source']}")
        print(f"  Date     : {r['published_date']}")
        print()

    print("=" * 60)
    print(f"  DB-ready records: {len(results)}")
    print("=" * 60)