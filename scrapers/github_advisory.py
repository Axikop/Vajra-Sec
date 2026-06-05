"""
scrapers/github_advisory.py
---------------------------
Scraper for GitHub Security Advisory Database (GHSA).

Uses GitHub's public GraphQL API — no token required for public advisories.
Token optional but recommended for higher rate limits (5000 vs 60 req/hr).

Add to config.py if you have a token:
    GITHUB_TOKEN = "ghp_xxxx"

Ecosystems covered (relevant to Indian PSU/BSNL infrastructure):
    - PIP     — Python / Django / Flask
    - NPM     — Node.js
    - MAVEN   — Java / Spring
    - COMPOSER — PHP / WordPress
    - NUGET   — ASP.NET / .NET
    - RUBYGEMS — Ruby on Rails
    - GO      — Go

Usage:
    from scrapers.github_advisory import scrape_github_advisory
    records = scrape_github_advisory()
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
GRAPHQL_URL     = "https://api.github.com/graphql"
REST_URL        = "https://api.github.com/advisories"
SOURCE_NAME     = "github_advisory"
REQUEST_TIMEOUT = 30
REQUEST_DELAY   = 1.0

TARGET_ECOSYSTEMS = [
    "PIP",
    "NPM",
    "MAVEN",
    "COMPOSER",
    "NUGET",
    "RUBYGEMS",
    "GO",
]

# Severity mapping
_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "UNKNOWN":  "UNKNOWN",
}

# GraphQL query — reused from friend's code, adapted for our needs
_ADVISORY_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem, $after: String) {
  securityVulnerabilities(
    ecosystem: $ecosystem
    first: 100
    after: $after
    orderBy: { field: UPDATED_AT, direction: DESC }
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        publishedAt
        updatedAt
        cvss {
          score
          vectorString
        }
        identifiers {
          type
          value
        }
        references {
          url
        }
      }
      package {
        name
        ecosystem
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
    }
  }
}
"""


# ── HTTP session ──────────────────────────────────────────────────────────────
def _make_session(github_token: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "NTRO-CVE-Monitor/1.0",
    })
    if github_token:
        s.headers["Authorization"] = f"Bearer {github_token}"
    return s


# ── GraphQL fetcher ───────────────────────────────────────────────────────────
def _fetch_ecosystem(
    session:    requests.Session,
    ecosystem:  str,
    max_pages:  int = 3,
    days_back:  int = 7,
) -> list[dict]:
    """
    Fetch advisories for one ecosystem via GraphQL pagination.
    Stops early when advisories are older than days_back.
    """
    all_nodes   = []
    after       = None
    page        = 0
    cutoff      = datetime.now(timezone.utc).timestamp() - (days_back * 86400)

    while page < max_pages:
        payload = {
            "query":     _ADVISORY_QUERY,
            "variables": {"ecosystem": ecosystem, "after": after},
        }

        try:
            resp = session.post(GRAPHQL_URL, json=payload, timeout=REQUEST_TIMEOUT)

            if resp.status_code == 401:
                logger.error("[GitHub] Token invalid — falling back to unauthenticated")
                session.headers.pop("Authorization", None)
                continue

            if resp.status_code == 429:
                logger.warning("[GitHub] Rate limit hit — sleeping 60s")
                time.sleep(60)
                continue

            resp.raise_for_status()
            data = resp.json()

            if "errors" in data:
                logger.warning("[GitHub] GraphQL error: %s", data["errors"])
                break

            vulns     = data["data"]["securityVulnerabilities"]
            nodes     = vulns["nodes"]
            page_info = vulns["pageInfo"]

            # Filter by date and stop if too old
            stop = False
            for node in nodes:
                updated = node.get("advisory", {}).get("updatedAt", "")
                if updated:
                    try:
                        ts = datetime.fromisoformat(
                            updated.replace("Z", "+00:00")
                        ).timestamp()
                        if ts < cutoff:
                            stop = True
                            break
                    except ValueError:
                        pass
                all_nodes.append(node)

            logger.info(
                "[GitHub] %s page %d: %d nodes (total %d)",
                ecosystem, page + 1, len(nodes), len(all_nodes)
            )

            if stop or not page_info["hasNextPage"]:
                break

            after  = page_info["endCursor"]
            page  += 1
            time.sleep(REQUEST_DELAY)

        except requests.RequestException as e:
            logger.warning("[GitHub] Request failed for %s: %s", ecosystem, e)
            break

    return all_nodes


# ── Parser ────────────────────────────────────────────────────────────────────
def _parse_node(node: dict) -> Optional[dict]:
    """
    Parse a GraphQL node into our standard CVE dict.
    Returns None if the node is invalid or missing key fields.
    """
    try:
        advisory = node.get("advisory", {})
        package  = node.get("package", {})

        if not advisory or not package:
            return None

        # CVE ID — prefer CVE over GHSA
        cve_id  = None
        ghsa_id = advisory.get("ghsaId", "")

        for ident in advisory.get("identifiers", []):
            if ident.get("type") == "CVE":
                cve_id = ident["value"].upper()
                break

        vuln_id = cve_id or ghsa_id
        if not vuln_id:
            return None

        # CVSS
        cvss_data  = advisory.get("cvss") or {}
        cvss_score = cvss_data.get("score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        # Severity
        raw_sev  = advisory.get("severity", "UNKNOWN").upper()
        severity = _SEVERITY_MAP.get(raw_sev, "UNKNOWN")

        # Product info
        pkg_name    = package.get("name", "unknown")
        ecosystem   = package.get("ecosystem", "").lower()
        vuln_range  = node.get("vulnerableVersionRange")
        patched     = (node.get("firstPatchedVersion") or {}).get("identifier")

        product_raw  = f"{pkg_name} ({ecosystem})" if ecosystem else pkg_name
        product_norm = f"{ecosystem}_{pkg_name}".lower().replace("-", "_").replace(".", "_")[:80]

        # Version range — convert GitHub format to our format
        # GitHub uses "< 1.2.3" or ">= 1.0, < 2.0" format — already compatible
        version_range = vuln_range or (f"< {patched}" if patched else None)

        # Description
        description = (
            advisory.get("summary") or
            advisory.get("description") or ""
        )[:2000]

        # Advisory URL — first reference URL
        advisory_url = ""
        refs = advisory.get("references", [])
        if refs:
            advisory_url = refs[0].get("url", "")
        if not advisory_url and ghsa_id:
            advisory_url = f"https://github.com/advisories/{ghsa_id}"

        # Published date
        published = ""
        pub_str   = advisory.get("publishedAt", "")
        if pub_str:
            published = pub_str[:10]

        # Mitigation
        mitigation = "Update to patched version."
        if patched:
            mitigation = f"Update {pkg_name} to version {patched} or later."

        return {
            "cve_id":         vuln_id,
            "source":         SOURCE_NAME,
            "product_raw":    product_raw,
            "product_norm":   product_norm,
            "version_range":  version_range,
            "oem":            ecosystem.upper() if ecosystem else "GitHub",
            "severity":       severity,
            "cvss_score":     cvss_score,
            "description":    description,
            "mitigation":     mitigation,
            "advisory_url":   advisory_url,
            "published_date": published,
            "_ghsa_id":       ghsa_id,
            "_package":       pkg_name,
            "_ecosystem":     ecosystem,
            "_patched":       patched,
        }

    except Exception as e:
        logger.warning("[GitHub] Failed to parse node: %s", e)
        return None


# ── Main scrape function ──────────────────────────────────────────────────────
def scrape_github_advisory(
    github_token: Optional[str] = None,
    days_back:    int = 7,
    max_pages:    int = 3,
) -> list[dict]:
    """
    Scrape GitHub Security Advisory Database for recent vulnerabilities.

    Args:
        github_token: Optional GitHub PAT for higher rate limits.
                      Without token: 60 req/hr. With token: 5000 req/hr.
                      Add GITHUB_TOKEN to config.py to use.
        days_back:    How many days back to fetch. Default 7.
        max_pages:    Max GraphQL pages per ecosystem. Default 3 (300 advisories).

    Returns:
        List of CVE record dicts ready for db.insert_cves_bulk().
    """
    # Try to load token from config if not provided
    if github_token is None:
        try:
            from config import GITHUB_TOKEN
            github_token = GITHUB_TOKEN
            logger.info("[GitHub] Using token from config.py")
        except (ImportError, AttributeError):
            logger.info("[GitHub] No token — using unauthenticated (60 req/hr)")

    session     = _make_session(github_token)
    all_records = []
    seen_ids    = set()

    for ecosystem in TARGET_ECOSYSTEMS:
        logger.info("[GitHub] Fetching ecosystem: %s", ecosystem)
        nodes = _fetch_ecosystem(session, ecosystem, max_pages, days_back)

        for node in nodes:
            record = _parse_node(node)
            if record is None:
                continue
            if record["cve_id"] in seen_ids:
                continue
            seen_ids.add(record["cve_id"])
            all_records.append(record)

        time.sleep(REQUEST_DELAY)

    logger.info(
        "[GitHub] Scrape complete. %d unique records across %d ecosystems",
        len(all_records), len(TARGET_ECOSYSTEMS)
    )
    return all_records


def clean_for_db(records: list[dict]) -> list[dict]:
    """Strip internal fields before passing to db.insert_cves_bulk()."""
    internal = {"_ghsa_id", "_package", "_ecosystem", "_patched"}
    return [{k: v for k, v in r.items() if k not in internal} for r in records]


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  github_advisory.py  —  GitHub Advisory Scraper Self-Test")
    print("=" * 60)

    results = scrape_github_advisory(days_back=7, max_pages=2)

    if not results:
        print("[!] No results returned.")
        sys.exit(0)

    db_ready = clean_for_db(results)

    by_sev = {}
    by_eco = {}
    for r in results:
        by_sev.setdefault(r["severity"], 0)
        by_sev[r["severity"]] += 1
        by_eco.setdefault(r["_ecosystem"], 0)
        by_eco[r["_ecosystem"]] += 1

    print(f"\n[+] Fetched {len(results)} unique advisories")
    print(f"    Severity  : {by_sev}")
    print(f"    Ecosystem : {by_eco}\n")

    for r in results[:5]:
        print(f"  ID        : {r['cve_id']}")
        print(f"  GHSA      : {r['_ghsa_id']}")
        print(f"  Package   : {r['_package']} ({r['_ecosystem']})")
        print(f"  Severity  : {r['severity']} (CVSS: {r['cvss_score']})")
        print(f"  Range     : {r['version_range']}")
        print(f"  Patched   : {r['_patched']}")
        print(f"  Published : {r['published_date']}")
        print()

    print("=" * 60)
    print(f"  DB-ready records: {len(db_ready)}")
    print("=" * 60)