"""
-------------------------
Agentic web search for CVE intelligence using Tavily.

The "light agent" pattern: Tavily itself is the agent. We hand it the
query, it picks the most relevant articles across the web (vendor
advisories, security blogs, researcher writeups), ranks them, and
returns clean content. We then optionally deep-fetch the top hits for
even more context before passing everything to the local Ollama LLM.

"""

import logging
import time
from typing import Optional

import requests

from config import TAVILY_API_KEY

logger = logging.getLogger(__name__)

_tavily_client = None


def _get_client():
    """Lazy-init Tavily client so the module can still be imported without a key."""
    global _tavily_client
    if _tavily_client is not None:
        return _tavily_client
    if not TAVILY_API_KEY:
        raise RuntimeError(
            "TAVILY_API_KEY missing in config.py. "
            "Get a free key at https://app.tavily.com"
        )
    from tavily import TavilyClient
    _tavily_client = TavilyClient(api_key=TAVILY_API_KEY)
    return _tavily_client


def _to_legacy_format(tavily_result: dict) -> dict:
    """
    Tavily returns: {title, url, content, score, raw_content?}
    Legacy DDG format expected by callers: {title, href, body}
    """
    return {
        "title": tavily_result.get("title", ""),
        "href":  tavily_result.get("url", ""),
        "body":  tavily_result.get("content", "").strip(),
        "score":       tavily_result.get("score"),
        "raw_content": tavily_result.get("raw_content"),
    }


def search_cve(
    cve_id: str,
    max_results: int = 5,
    extra_query: str = "",
    sleep_between: float = 1.5,
) -> list[dict]:
    """
    Search the web for a given CVE ID using the Tavily agentic search API.
    Tavily ranks results by relevance and returns clean text excerpts.

    Args:
        cve_id:        e.g. "CVE-2026-0300"
        max_results:   how many results to fetch (default 5 — lean for CPU LLM)
        extra_query:   optional additional terms
        sleep_between: delay between retries on failure

    Returns:
        List of dicts with legacy keys: title, href, body
    """
    query = f"{cve_id} affected versions patch mitigation {extra_query}".strip()
    logger.info(f"[Tavily] Searching: {query}")

    for attempt in range(3):
        try:
            client = _get_client()
           
            response = client.search(
                query        = query,
                search_depth = "basic",
                max_results  = max_results,
                include_domains = [
                    "nvd.nist.gov", "cve.mitre.org", "cve.org",
                    "cisa.gov", "github.com", "githubusercontent.com",
                    "cisco.com", "fortinet.com", "fortiguard.com",
                    "microsoft.com", "msrc.microsoft.com",
                    "paloaltonetworks.com", "ivanti.com",
                    "vmware.com", "broadcom.com",
                    "tenable.com", "rapid7.com", "qualys.com",
                    "sans.org", "schneier.com", "darkreading.com",
                    "bleepingcomputer.com", "thehackernews.com",
                    "securityweek.com", "krebsonsecurity.com",
                ],
            )

            results_raw = response.get("results", []) if isinstance(response, dict) else []
            results = [_to_legacy_format(r) for r in results_raw]

            logger.info(f"[Tavily] Got {len(results)} results for {cve_id}")
            return results

        except Exception as e:
            logger.warning(f"[Tavily] Attempt {attempt+1} failed for {cve_id}: {e}")
            time.sleep(sleep_between * (attempt + 1))

    logger.warning(f"[Tavily] Domain-filtered search exhausted, trying open search")
    try:
        client = _get_client()
        response = client.search(
            query        = query,
            search_depth = "basic",
            max_results  = max_results,
        )
        results_raw = response.get("results", []) if isinstance(response, dict) else []
        results = [_to_legacy_format(r) for r in results_raw]
        logger.info(f"[Tavily] Open search returned {len(results)} results")
        return results
    except Exception as e:
        logger.error(f"[Tavily] All retries exhausted for {cve_id}: {e}")
        return []


def search_product_cves(
    product: str,
    vendor: str = "",
    max_results: int = 10,
) -> list[dict]:
    """
    Search for recent CVEs affecting a specific product/vendor.
    Useful for asset-based lookups (e.g. "Cisco IOS vulnerabilities 2025").
    """
    query = f"{vendor} {product} CVE vulnerability 2025 2026 patch".strip()
    logger.info(f"[Tavily] Product search: {query}")

    try:
        client = _get_client()
        response = client.search(
            query        = query,
            search_depth = "basic",
            max_results  = max_results,
        )
        results_raw = response.get("results", []) if isinstance(response, dict) else []
        return [_to_legacy_format(r) for r in results_raw]
    except Exception as e:
        logger.error(f"[Tavily] Product search failed for {vendor} {product}: {e}")
        return []


def format_results_for_llm(results: list[dict]) -> str:
    """
    Format search results into a clean string block ready to be passed
    to the local LLM (Ollama Qwen) as context.
    """
    if not results:
        return "No search results found."

    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"[Source {i}] {r.get('title', 'No title')}")
        lines.append(f"URL: {r.get('href', '')}")
        lines.append(f"Snippet: {r.get('body', '').strip()}")
        lines.append("")

    return "\n".join(lines)


def fetch_article_text(url: str, timeout: int = 8) -> str:
    """
    Fetch plain text from a URL for deeper version extraction.
    Strips nav/footer/script noise. Returns empty string on failure.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["nav", "footer", "script", "style", "header"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return text[:3000]
    except Exception as e:
        logger.warning(f"[Tavily] Failed to fetch {url}: {e}")
        return ""


def enrich_with_full_articles(results: list[dict], top_n: int = 2) -> str:
  
    PER_ARTICLE_CAP = 1200
    SNIPPET_CAP     = 400

    lines = []
    for i, r in enumerate(results[:top_n], 1):
        title = r.get("title", "")
        url   = r.get("href", "")
        snippet = r.get("body", "").strip()

    
        raw = r.get("raw_content")
        if raw and len(raw) > len(snippet):
            content = raw[:PER_ARTICLE_CAP]
        else:
            full_text = fetch_article_text(url)
            content   = (full_text or snippet)[:PER_ARTICLE_CAP]

        lines.append(f"[Source {i}] {title}")
        lines.append(f"URL: {url}")
        lines.append(f"Content: {content}")
        lines.append("")

    for i, r in enumerate(results[top_n:], top_n + 1):
        lines.append(f"[Source {i}] {r.get('title', '')}")
        lines.append(f"URL: {r.get('href', '')}")
        lines.append(f"Snippet: {r.get('body', '').strip()[:SNIPPET_CAP]}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    test_cve = "CVE-2024-21762"   # Fortinet SSL VPN 
    print(f"=== Tavily search test: {test_cve} ===\n")

    results = search_cve(test_cve, max_results=5)
    print(f"Got {len(results)} results\n")

    for i, r in enumerate(results, 1):
        print(f"[{i}] {r.get('title', '')[:80]}")
        print(f"    {r.get('href', '')}")
        print(f"    {r.get('body', '')[:120]}...")
        print()

    print("\n=== LLM-ready context preview ===\n")
    print(format_results_for_llm(results)[:600])
