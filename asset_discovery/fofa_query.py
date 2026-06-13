"""
Passive asset discovery using FOFA search engine API.
Takes enriched CVE data (product + version from the local LLM) and finds
internet-facing devices in Indian critical infrastructure.

NO active scanning — FOFA is a passive search engine (already crawled).
Free tier: 300 queries/month, 100 results/query.

Requires in config.py:
    FOFA_EMAIL   = "@email.com"
    FOFA_API_KEY = "APIkey"
"""

import base64
import logging
import time
from typing import Optional

import requests

from config import FOFA_EMAIL, FOFA_API_KEY

logger = logging.getLogger(__name__)

FOFA_API_URL = "https://fofa.info/api/v1/search/all"
FOFA_SIZE    = 100   # max results per query on free tier

# ── Indian ASNs for critical infra filtering ─────────────────────────────────
INDIAN_ASNS = {
    "AS9829":   "BSNL",
    "AS4755":   "TATA Communications",
    "AS17813":  "MTNL Mumbai",
    "AS17762":  "MTNL Delhi",
    "AS55836":  "Reliance Jio",
    "AS24560":  "Airtel",
    "AS45820":  "ONGC",
    "AS45714":  "NIC (National Informatics Centre)",
    "AS55824":  "GAIL India",
    "AS55826":  "Power Grid India",
    "AS45595":  "BBNL",
    "AS10029":  "VSNL/Tata",
}


PRODUCT_FOFA_MAP = {
    "cisco ios":          'app="Cisco-IOS"',
    "cisco ios xe":       'app="Cisco-IOS-XE"',
    "cisco nx-os":        'app="Cisco-NX-OS"',
    "cisco asa":          'app="Cisco-ASA"',
    "cisco router":       'app="Cisco-IOS"',
    "fortinet fortigate": 'app="Fortinet-FortiGate"',
    "fortios":            'app="Fortinet-FortiGate"',
    "juniper junos":      'app="Juniper-JunOS"',
    "juniper":            'app="Juniper-JunOS"',
    "palo alto":          'app="Palo-Alto-Networks-PAN-OS"',
    "pan-os":             'app="Palo-Alto-Networks-PAN-OS"',
    "microsoft windows":  'app="Windows"',
    "microsoft exchange": 'app="Microsoft-Exchange"',
    "huawei":             'app="Huawei"',
    "zte":                'app="ZTE"',
    "ericsson":           'app="Ericsson"',
    "mikrotik":           'app="MikroTik-RouterOS"',
    "routeros":           'app="MikroTik-RouterOS"',
    "apache":             'app="Apache-httpd"',
    "nginx":              'app="nginx"',
    "openssl":            'title="openssl"',
    "vmware esxi":        'app="VMware-ESXi"',
    "vmware":             'app="VMware"',
    "f5 big-ip":          'app="F5-BIG-IP"',
    "big-ip":             'app="F5-BIG-IP"',
    "siemens":            'app="Siemens"',
}



def build_fofa_query(
    product: str,
    version: str = "",
    country: str = "IN",
) -> str:
    product_lower = product.lower().strip()

    fofa_app = None
    for key, val in PRODUCT_FOFA_MAP.items():
        if key in product_lower or product_lower in key:
            fofa_app = val
            break

    if not fofa_app:
        logger.warning(f"[FOFA] No app tag for '{product}', using banner search")
        fofa_app = f'banner="{product}"'

    # version field is paid-only on FOFA — not included
    query = " && ".join([fofa_app, f'country="{country}"'])
    logger.info(f"[FOFA] Built query: {query}")
    return query



def _encode_query(query: str) -> str:
    """Base64 encode query as required by FOFA API."""
    return base64.b64encode(query.encode()).decode()



def fofa_search(
    query: str,
    size: int = FOFA_SIZE,
    fields: str = "ip,port,host,title,country,region,asn,org,domain,protocol",
) -> list[dict]:
    """
    Execute a FOFA search query via the REST API.
 
    Args:
        query:   raw FOFA query string (will be base64 encoded)
        size:    number of results (max 300 on free credits)
        fields:  comma-separated field values

    Returns:
        List of result dicts with the requested fields as keys
    """
    params = {
        "email":  FOFA_EMAIL,
        "key":    FOFA_API_KEY,
        "qbase64": _encode_query(query),
        "size":   size,
        "fields": fields,
        "full":   "false",
    }

    try:
        resp = requests.get(FOFA_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("error"):
            logger.error(f"[FOFA] API error: {data.get('errmsg', 'unknown')}")
            return []

        results_raw = data.get("results", [])
        field_list  = [f.strip() for f in fields.split(",")]

        results = []
        for row in results_raw:
            if isinstance(row, list):
                results.append(dict(zip(field_list, row)))
            elif isinstance(row, dict):
                results.append(row)

        logger.info(f"[FOFA] Got {len(results)} results")
        return results

    except requests.RequestException as e:
        logger.error(f"[FOFA] Request failed: {e}")
        return []
    except Exception as e:
        logger.error(f"[FOFA] Unexpected error: {e}")
        return []



def filter_indian_critical_infra(results: list[dict]) -> list[dict]:
    """
    Filter FOFA results to only Indian critical infrastructure orgs
    based on known ASNs.

    Args:
        results: raw FOFA result dicts

    Returns:
        Filtered list with an added 'org_name' key
    """
    filtered = []
    for r in results:
        asn = r.get("asn", "").strip()
        if asn and not asn.startswith("AS"):
            asn = f"AS{asn}"

        if asn in INDIAN_ASNS or any(x in r.get("org","").upper() for x in ["BSNL","ONGC","AIRTEL","MTNL","NIC","GAIL","RAILTEL","POWERGRID"]):
            r["org_name"] = INDIAN_ASNS[asn]
            r["asn"]      = asn
            filtered.append(r)

    logger.info(f"[FOFA] {len(filtered)} results matched Indian critical infra ASNs")
    return filtered



def find_affected_indian_assets(
    product: str,
    version: str = "",
    also_return_all: bool = False,
) -> list[dict]:
    """
    Full pipeline: build query → FOFA search → filter Indian critical infra.

    Args:
        product:         normalized product name from Groq enrichment
        version:         affected version from Groq enrichment (optional)
        also_return_all: if True, returns all Indian results not just CSO ASNs

    Returns:
        List of affected asset dicts with ip, port, host, org_name, asn
    """
    query   = build_fofa_query(product, version, country="IN")
    results = fofa_search(query)

    if not results:
        logger.warning(f"[FOFA] No results for {product} {version}")
        return []

    if also_return_all:
        # Return all Indian results (country=IN already filtered in query)
        logger.info(f"[FOFA] Returning all {len(results)} Indian results")
        return results

    # Default: only known critical infra ASNs
    return filter_indian_critical_infra(results)


def find_assets_from_enriched(enriched: dict) -> list[dict]:
    """
    Convenience wrapper — takes Groq enriched dict directly.
    Tries each affected product+version combo and deduplicates.

    Args:
        enriched: dict from core.groq_enricher.enrich_cve()
                  keys: products, affected_versions, cve_id, ...

    Returns:
        Deduplicated list of affected Indian asset dicts
    """
    products  = enriched.get("products", [])
    versions  = enriched.get("affected_versions") or []
    cve_id    = enriched.get("cve_id", "unknown")

    if not products:
        logger.warning(f"[FOFA] No products in enriched data for {cve_id}")
        return []

    seen_ips = set()
    all_assets = []

    # Try each product, with and without version
    for product in products:
        # Search without version first (broader)
        assets = find_affected_indian_assets(product)
        for asset in assets:
            ip = asset.get("ip", "")
            if ip and ip not in seen_ips:
                asset["cve_id"] = cve_id
                all_assets.append(asset)
                seen_ips.add(ip)

        # Then narrow down with versions
        for version in versions[:3]:   # limit to first 3 versions to save quota
            assets_v = find_affected_indian_assets(product, version)
            for asset in assets_v:
                ip = asset.get("ip", "")
                if ip and ip not in seen_ips:
                    asset["cve_id"] = cve_id
                    all_assets.append(asset)
                    seen_ips.add(ip)

            time.sleep(0.5)   

    logger.info(f"[FOFA] Total unique affected Indian assets for {cve_id}: {len(all_assets)}")
    return all_assets


if __name__ == "__main__":
    import json
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    print("=== Test 1: Raw FOFA query for Cisco IOS in India ===")
    assets = find_affected_indian_assets("cisco ios xe", version="")
    print(json.dumps(assets[:5], indent=2))   # print first 5

    # Test 2: from enriched dict (simulated Groq output)
    print("\n=== Test 2: From enriched CVE dict ===")
    fake_enriched = {
        "cve_id":            "CVE-2024-20399",
        "products":          ["Cisco NX-OS"],
        "affected_versions": ["9.3(10)", "10.2(6)"],
        "severity":          "Medium",
        "description":       "CLI command injection in Cisco NX-OS",
        "mitigation":        "Upgrade to 9.3(13) or later",
    }
    affected = find_assets_from_enriched(fake_enriched)
    print(json.dumps(affected[:5], indent=2))


