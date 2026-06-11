"""
core/matcher.py
---------------
Matching engine for the NTRO CVE Monitoring System.

Takes CVEs from the cves table and assets from the assets table,
finds which assets are affected by which CVEs, and returns match
objects ready for alerter.py to dispatch.

Matching strategy (3 passes):
    1. Exact product_norm match          — highest confidence
    2. OEM-level match (vendor only)     — medium confidence
    3. Keyword match in description      — low confidence, last resort

Version matching:
    Uses normalizer.version_in_range() to check if asset version
    falls within CVE's version_range string.
    If no version_range in CVE → match on product only (conservative).

Usage:
    from core.matcher import run_matcher
    matches = run_matcher()              # uses default DB
    matches = run_matcher(db_path="..")  # custom DB path
"""

import logging
from core.normalizer import normalize_product, is_version_affected
import re
from datetime import datetime, timezone
from typing import Optional

from database.db import (
    get_all_assets,
    get_recent_cves,
    get_critical_cves,
    alert_already_sent,
    record_alert_sent,
    log_scraper_run,
    get_connection,
    DB_PATH,
)

# ── Logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Confidence levels ─────────────────────────────────────────────────────────
CONFIDENCE_EXACT   = "HIGH"      # product_norm exact match
CONFIDENCE_OEM     = "MEDIUM"    # same vendor, no product match
CONFIDENCE_KEYWORD = "LOW"       # keyword in description only

# Minimum severity to generate an alert (set to None to alert on everything)
MIN_ALERT_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM"}

# OEM → keywords that identify vendor in asset banners/product names
_OEM_KEYWORDS = {
    "Cisco":      ["cisco"],
    "Fortinet":   ["fortinet", "fortigate", "fortios"],
    "Juniper":    ["juniper", "junos"],
    "Palo Alto":  ["palo alto", "panos", "pan-os"],
    "F5":         ["f5", "big-ip", "bigip"],
    "Microsoft":  ["microsoft", "windows", "iis", "exchange"],
    "VMware":     ["vmware", "esxi", "vcenter", "vsphere"],
    "Apache":     ["apache", "httpd", "tomcat"],
    "Linux":      ["linux", "ubuntu", "debian", "centos", "rhel"],
    "Oracle":     ["oracle"],
    "SAP":        ["sap"],
    "Siemens":    ["siemens", "simatic"],
    "Intel":      ["intel"],
    "Google":     ["google", "chrome", "android"],
    "Apple":      ["apple", "macos", "ios"],
    "Huawei":     ["huawei"],
    "Ericsson":   ["ericsson"],
    "ZTE":        ["zte"],
}


# ── Match result dataclass (plain dict for simplicity) ────────────────────────
def _make_match(cve: dict, asset: dict, confidence: str, reason: str) -> dict:
    """Build a standardised match result dict."""
    return {
        "cve_id":        cve["cve_id"],
        "asset_ip":      asset["ip"],
        "asset_port":    asset["port"],
        "org":           asset["org"],
        "asn":           asset["asn"],
        "hostname":      asset["hostname"],
        "product_norm":  cve["product_norm"],
        "asset_version": asset["version"],
        "version_range": cve["version_range"],
        "severity":      cve["severity"],
        "cvss_score":    cve["cvss_score"],
        "oem":           cve["oem"],
        "description":   cve["description"],
        "mitigation":    cve["mitigation"],
        "advisory_url":  cve["advisory_url"],
        "published_date":cve["published_date"],
        "confidence":    confidence,
        "match_reason":  reason,
        "matched_at":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source":        cve["source"],
    }


# ── Version check ─────────────────────────────────────────────────────────────
def _version_matches(asset_version: Optional[str], version_range: Optional[str]) -> bool:
    if not version_range:
        return True
    if not asset_version:
        return True
    try:
        return is_version_affected(asset_version, version_range)
    except Exception as e:
        logger.debug("is_version_affected error (%s, %s): %s", asset_version, version_range, e)
        return True  # parse error → conservatively assume affected


# ── OEM match ─────────────────────────────────────────────────────────────────
def _oem_matches(cve_oem: Optional[str], asset: dict) -> bool:
    """Check if CVE's OEM matches the asset's product/banner."""
    if not cve_oem or cve_oem == "Unknown":
        return False

    keywords = _OEM_KEYWORDS.get(cve_oem, [cve_oem.lower()])
    asset_text = " ".join([
        (asset["product_norm"] or ""),
        (asset["banner"] or ""),
        (asset["service"] or ""),
    ]).lower()

    return any(kw in asset_text for kw in keywords)


# ── Keyword match ─────────────────────────────────────────────────────────────
def _keyword_matches(cve: dict, asset: dict) -> bool:
    """
    Last-resort: check if CVE description mentions the asset's product.
    Avoids false positives by requiring at least 4-char keyword match.
    """
    if not asset["product_norm"]:
        return False

    desc = (cve["description"] or "").lower()
    product_parts = asset["product_norm"].replace("_", " ").split()

    # Require at least 2 parts of product name to appear in description
    matches = sum(1 for part in product_parts if len(part) >= 4 and part in desc)
    return matches >= min(2, len(product_parts))


# ── Core matcher ──────────────────────────────────────────────────────────────
def match_cve_to_assets(
    cve:    dict,
    assets: list[dict],
) -> list[dict]:
    """
    Match a single CVE against all known assets.
    Returns list of match dicts (may be empty).
    """
    matches = []

    # Skip if severity not in alert threshold
    if MIN_ALERT_SEVERITY and cve["severity"] not in MIN_ALERT_SEVERITY:
        return []

    cve_product = cve.get("product_norm") or normalize_product(cve.get("product_raw", ""))

    for asset in assets:
        asset_product = asset["product_norm"]
        if not asset_product:
            continue

        # ── Pass 1: Exact product_norm match ─────────────────────────────────
        if cve_product and asset_product == cve_product:
            if _version_matches(asset["version"], cve["version_range"]):
                matches.append(_make_match(
                    cve, asset,
                    confidence = CONFIDENCE_EXACT,
                    reason     = f"Exact product match: {cve_product}"
                ))
                continue   # no need to check lower confidence passes

        # ── Pass 2: OEM-level match ───────────────────────────────────────────
        if _oem_matches(cve.get("oem"), asset):
            if _version_matches(asset["version"], cve["version_range"]):
                matches.append(_make_match(
                    cve, asset,
                    confidence = CONFIDENCE_OEM,
                    reason     = f"OEM match: {cve.get('oem')} on {asset_product}"
                ))
                continue

        # ── Pass 3: Keyword match ─────────────────────────────────────────────
        if _keyword_matches(cve, asset):
            matches.append(_make_match(
                cve, asset,
                confidence = CONFIDENCE_KEYWORD,
                reason     = f"Keyword match in description for {asset_product}"
            ))

    return matches


# ── Bulk runner ───────────────────────────────────────────────────────────────
def run_matcher(
    hours_back:   int  = 24,
    include_all:  bool = False,
    db_path:      str  = DB_PATH,
    dry_run:      bool = False,
) -> list[dict]:
    """
    Run the full matching pipeline.

    Args:
        hours_back:  How many hours of CVEs to match against. Default 24.
        include_all: If True, also include CRITICAL CVEs regardless of age.
        dry_run:     If True, don't record alerts_sent (for testing).
        db_path:     SQLite DB path.

    Returns:
        List of new match dicts (deduped against alerts_sent table).
    """
    logger.info("Starting matcher run (hours_back=%d, dry_run=%s)", hours_back, dry_run)
    start_time = datetime.now(timezone.utc)

    # ── Load assets ───────────────────────────────────────────────────────────
    raw_assets = get_all_assets(db_path)
    if not raw_assets:
        logger.warning("No assets in DB — nothing to match against.")
        logger.warning("Run asset discovery first or insert dummy assets for testing.")
        return []

    assets = [dict(a) for a in raw_assets]
    logger.info("Loaded %d assets from DB", len(assets))

    # ── Load CVEs ─────────────────────────────────────────────────────────────
    raw_cves = get_recent_cves(hours=hours_back, db_path=db_path)
    cves     = [dict(c) for c in raw_cves]

    if include_all:
        # Also grab all CRITICAL CVEs regardless of age
        raw_critical = get_critical_cves(db_path)
        critical_ids = {c["cve_id"] for c in cves}
        for c in raw_critical:
            if c["cve_id"] not in critical_ids:
                cves.append(dict(c))

    logger.info("Loaded %d CVEs to match", len(cves))

    # ── Run matching ──────────────────────────────────────────────────────────
    all_matches  = []
    new_matches  = []
    skipped_dedup = 0

    for cve in cves:
        matches = match_cve_to_assets(cve, assets)
        all_matches.extend(matches)

        for match in matches:
            # Dedup check — skip if alert already sent
            if alert_already_sent(match["cve_id"], match["asset_ip"], db_path):
                skipped_dedup += 1
                continue

            new_matches.append(match)

            # Record in alerts_sent immediately to prevent duplicate alerts
            # even if alerter fails halfway through
            if not dry_run:
                record_alert_sent({
                    "cve_id":     match["cve_id"],
                    "asset_ip":   match["asset_ip"],
                    "asset_port": match["asset_port"],
                    "org":        match["org"],
                    "severity":   match["severity"],
                    "recipient":  "pending",   # alerter fills this in
                }, db_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(
        "Matcher complete in %.2fs — %d total matches, %d new, %d skipped (dedup)",
        elapsed, len(all_matches), len(new_matches), skipped_dedup
    )

    if new_matches:
        # Log by severity
        by_severity = {}
        for m in new_matches:
            by_severity.setdefault(m["severity"], 0)
            by_severity[m["severity"]] += 1
        logger.info("New matches by severity: %s", by_severity)

    log_scraper_run(
        source       = "matcher",
        status       = "success",
        cves_fetched = len(new_matches),
        db_path      = db_path,
    )

    return new_matches


# ── Get all CVEs from DB (not just recent) ────────────────────────────────────
def get_all_cves(db_path: str = DB_PATH) -> list:
    """Fetch every CVE from the DB — used for full re-scan."""
    with get_connection(db_path) as conn:
        return conn.execute("SELECT * FROM cves ORDER BY published_date DESC").fetchall()


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  matcher.py  —  NTRO CVE Matcher Self-Test")
    print("=" * 60)

    # ── Test 1: dry run against recent CVEs ───────────────────────────────────
    print("\n[Test 1] Dry run — recent CVEs (last 24h) vs assets...")
    matches = run_matcher(hours_back=24, dry_run=True)
    print(f"  New matches found: {len(matches)}")

    # ── Test 2: full scan including all CRITICAL ──────────────────────────────
    print("\n[Test 2] Full scan — all CRITICAL CVEs vs assets...")
    matches_all = run_matcher(hours_back=24, include_all=True, dry_run=True)
    print(f"  New matches found: {len(matches_all)}")

    if not matches_all:
        print("\n[!] No matches found.")
        print("    This could mean:")
        print("    - No CVEs in DB yet (run scrapers first)")
        print("    - No assets in DB yet (run asset discovery or insert dummies)")
        print("    - Products don't overlap (check product_norm values)")

        # Debug: show what's in DB
        from database.db import get_stats, get_all_assets, get_recent_cves
        stats = get_stats()
        print(f"\n    DB stats: {stats}")

        assets = [dict(a) for a in get_all_assets()]
        print(f"\n    Asset product_norms: {[a['product_norm'] for a in assets]}")

        cves = [dict(c) for c in get_recent_cves(hours=720)]  # last 30 days
        print(f"\n    CVE product_norms (sample): {list(set(c['product_norm'] for c in cves))[:10]}")
        sys.exit(0)

    # ── Print match details ───────────────────────────────────────────────────
    print(f"\n[+] Top matches:\n")
    seen = set()
    for m in matches_all[:10]:
        key = (m["cve_id"], m["asset_ip"])
        if key in seen:
            continue
        seen.add(key)

        print(f"  {'='*50}")
        print(f"  CVE        : {m['cve_id']}")
        print(f"  Severity   : {m['severity']} (CVSS: {m['cvss_score']})")
        print(f"  Asset      : {m['asset_ip']}:{m['asset_port']} ({m['hostname']})")
        print(f"  Org        : {m['org']} ({m['asn']})")
        print(f"  Product    : {m['product_norm']}")
        print(f"  Asset ver  : {m['asset_version']}")
        print(f"  CVE range  : {m['version_range']}")
        print(f"  Confidence : {m['confidence']}")
        print(f"  Reason     : {m['match_reason']}")
        print(f"  Source     : {m['source']}")
        print(f"  URL        : {m['advisory_url']}")
        print()

    print("=" * 60)
    print(f"  Done. Total new matches: {len(matches_all)}")
    print("=" * 60)