"""
Orchestrates the CVE enrichment flow:

    raw CVE ID
       ↓
    Tavily web search (scrapers/agent_search.py)
       ↓
    Local LLM extraction (core/groq_enricher.py via Ollama)
       ↓:
       FOFA API asset hunt → org-CIDR matcher → per-org dispatch]

"""

from __future__ import annotations

import logging
import time
from typing import Optional

from scrapers.agent_search import (
    enrich_with_full_articles,
    search_cve,
)
from core.groq_enricher import enrich_cve

logger = logging.getLogger(__name__)


def enrich_single_cve(
    cve_id: str,
    extra_query: str = "",
    max_results: int = 8,
) -> Optional[dict]:
    """
    Search the web for a CVE, fetch the top articles, and extract
    structured fields with the local LLM. Returns the enriched dict or
    None if web search returned nothing or the LLM call failed.
    """
    logger.info(f"[Pipeline] Enriching {cve_id}")

    results = search_cve(cve_id, max_results=max_results, extra_query=extra_query)
    if not results:
        logger.warning(f"[Pipeline] No web search results for {cve_id}")
        return None

    context  = enrich_with_full_articles(results, top_n=2)
    enriched = enrich_cve(cve_id, context)

    if enriched:
        logger.info(f"[Pipeline] Enrichment done for {cve_id}")
    return enriched


# ── Stage 3 (placeholder): FOFA asset hunt + org dispatch ────────────────────
# Once the FOFA F-Points API key and the org/CIDR map land from NTRO,
# this becomes:
#
#     from asset_discovery.fofa_query import find_assets_from_enriched
#     from core.org_dispatcher import match_assets_to_orgs, dispatch_per_org
#
#     assets    = find_assets_from_enriched(enriched)
#     by_org    = match_assets_to_orgs(assets, ORG_CIDR_MAP)
#     dispatch_per_org(cve_id, enriched, fofa_query, by_org)
#
# until then, run_full_pipeline returns enrichment-only results.
def _fofa_asset_hunt(enriched: dict) -> list[dict]:
    """Stub. Returns [] until the FOFA F-Points integration is wired up."""
    return []


def run_full_pipeline(
    cve_id: str,
    extra_query: str = "",
    max_results: int = 8,
    skip_fofa: bool = True,
) -> dict:
    """
    Full pipeline: enrich CVE → (later) find affected Indian assets via FOFA.

    Args:
        cve_id:       e.g. "CVE-2024-20399"
        extra_query:  optional extra terms for the web search
        max_results:  Tavily result count (default 8)
        skip_fofa:    skip the FOFA asset hunt. Default True today since
                      the integration is not wired yet — flip to False once
                      `_fofa_asset_hunt` is implemented.

    Returns:
        {"enriched": dict | None, "affected_assets": list[dict]}
    """
    result: dict = {"enriched": None, "affected_assets": []}

    enriched = enrich_single_cve(cve_id, extra_query, max_results)
    if not enriched:
        logger.error(f"[Pipeline] Enrichment failed for {cve_id}")
        return result

    result["enriched"] = enriched

    if skip_fofa:
        return result

    logger.info(f"[Pipeline] Starting FOFA asset hunt for {cve_id}")
    result["affected_assets"] = _fofa_asset_hunt(enriched)
    logger.info(
        f"[Pipeline] Done for {cve_id}: "
        f"{len(result['affected_assets'])} affected Indian assets found"
    )
    return result


def run_batch_pipeline(
    cve_ids: list[str],
    delay: float = 3.0,
    skip_fofa: bool = True,
) -> list[dict]:
    """Run `run_full_pipeline` for each CVE with a polite delay between calls."""
    all_results = []
    total = len(cve_ids)
    for i, cve_id in enumerate(cve_ids, 1):
        logger.info(f"[Pipeline] Batch {i}/{total}: {cve_id}")
        all_results.append(run_full_pipeline(cve_id, skip_fofa=skip_fofa))
        if i < total:
            time.sleep(delay)

    succeeded = sum(1 for r in all_results if r["enriched"])
    logger.info(f"[Pipeline] Batch done: {succeeded}/{total} enriched")
    return all_results


if __name__ == "__main__":
    import json
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    print("=== Test: enrichment only (no FOFA) ===")
    out = run_full_pipeline("CVE-2024-21762", skip_fofa=True)
    print(json.dumps(out["enriched"], indent=2))
