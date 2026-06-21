"""
Passive asset discovery using FOFA search engine API.
Takes enriched CVE data (product + version from the local LLM) and finds
internet-facing devices in Indian critical infrastructure.

NO active scanning — FOFA is a passive search engine (already crawled).

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





def build_fofa_query(
    product: str,
    version: str = "",
    country: str = "IN",
) -> Optional[str]:
    """
    Map a product to a VERIFIED FOFA tag (via core.fofa_catalog) and anchor to
    country. Returns None when no verified fingerprint exists — precision-first,
    we no longer fall back to a `banner="<product>"` guess (which matched
    almost nothing and produced noise). `version` is ignored: FOFA version
    search needs Business+/F-points, which this plan lacks.

    The single source of truth for product → FOFA fingerprint is now
    core/fofa_catalog.py (the old unverified PRODUCT_FOFA_MAP was removed).
    """
    from core import fofa_catalog

    entry = fofa_catalog.lookup(product)
    if not entry:
        logger.warning(f"[FOFA] no verified fingerprint for '{product}' — skipping")
        return None

    query = f'{entry["clause"]} && country="{country}"'
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
   
    query   = build_fofa_query(product, version, country="IN")
    if not query:
        return []
    results = fofa_search(query)

    if not results:
        logger.warning(f"[FOFA] No results for {product} {version}")
        return []

    if also_return_all:
        logger.info(f"[FOFA] Returning all {len(results)} Indian results")
        return results

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

    for product in products:
        assets = find_affected_indian_assets(product)
        for asset in assets:
            ip = asset.get("ip", "")
            if ip and ip not in seen_ips:
                asset["cve_id"] = cve_id
                all_assets.append(asset)
                seen_ips.add(ip)

        for version in versions[:3]:   
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


