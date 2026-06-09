"""
Pulls @fofabot tweets via Nitter RSS instead of scraping X directly.

"""

import logging
import re
import time
from typing import Optional

import requests
import feedparser

logger = logging.getLogger(__name__)

NITTER_INSTANCES = [
    "https://nitter.net",
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
    "https://nitter.kavin.rocks",
    "https://nitter.cz",
]

FOFABOT_HANDLE  = "fofabot"
REQUEST_TIMEOUT = 15
USER_AGENT      = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


_TAG_RE  = re.compile(r"<[^>]+>")
_WS_RE   = re.compile(r"\s+")
_HREF_RE = re.compile(r'<a\s+[^>]*href="(https?://[^"]+)"', re.IGNORECASE)


def _extract_first_real_url(html: str) -> Optional[str]:
    """
    Pull the first non-fofa, non-twitter URL out of a Nitter HTML fragment.
    Used for the `ref_url` field, since Nitter renders fofabot's t.co links
    as <a href="...">text…</a> and our HTML stripper would otherwise drop
    the href and leave only truncated display text like "site.com/path…".
    """
    for m in _HREF_RE.finditer(html or ""):
        url = m.group(1)
        host = url.split("/")[2].lower() if "://" in url else ""
        if any(skip in host for skip in ("fofa.info", "twitter.com", "x.com", "nitter.")):
            continue
        return url
    return None


def _clean_html(s: str) -> str:
    """Strip HTML tags and collapse whitespace from a Nitter description."""
    if not s:
        return ""
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    s = s.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.IGNORECASE)
    s = _TAG_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    return s


def parse_fofabot_tweet(text: str) -> Optional[dict]:
    """
    Parse a single @fofabot tweet body and extract CVE intel.
    Returns dict or None if the tweet doesn't match the expected format.
    """
    cve_match = re.search(r"(CVE-\d{4}-\d+)", text)
    if not cve_match:
        return None
    cve_id = cve_match.group(1)

    cvss_match = re.search(r"CVSS\s+([\d.]+)", text)
    cvss = float(cvss_match.group(1)) if cvss_match else None

    
    fofa_match = re.search(
        r"FOFA\s+Query:\s*(.+?)(?:\n|🔖|Refer:|#\w|🎯|🔗|⚠|$)",
        text, re.DOTALL,
    )
    fofa_raw = fofa_match.group(1).strip() if fofa_match else None

    fofa_india = None
    if fofa_raw:
        fofa_clean = re.sub(r'&&\s*country="[^"]*"', "", fofa_raw).strip()
        fofa_clean = fofa_clean.rstrip(" .;,")
        if fofa_clean:
            fofa_india = f'{fofa_clean} && country="IN"'

    ref_url = None
    ref_match = re.search(r"Refer:\s*(https?://\S+)", text)
    if ref_match:
        ref_url = ref_match.group(1).strip()
    else:
        url_match = re.search(r"https?://(?!en\.fofa\.info)\S+", text)
        if url_match:
            ref_url = url_match.group(0).rstrip(".,;)")

    desc_match = re.search(
        r"CVE-\d{4}-\d+[^:]*?:\s*(.+?)(?=\n*FOFA|\n*🔗|\n*🎯|$)",
        text, re.DOTALL,
    )
    description = desc_match.group(1).strip().replace("\n", " ") if desc_match else None

    return {
        "cve_id":      cve_id,
        "cvss":        cvss,
        "description": description,
        "fofa_query":  fofa_india,
        "fofa_raw":    fofa_raw,
        "ref_url":     ref_url,
        "raw_tweet":   text,
    }


def _fetch_rss(handle: str) -> Optional[list]:
    """
    Try each Nitter instance until one returns a parseable feed with entries.
    Returns the list of feedparser entries, or None if every instance failed.
    """
    headers = {"User-Agent": USER_AGENT}
    for base in NITTER_INSTANCES:
        url = f"{base.rstrip('/')}/{handle}/rss"
        try:
            logger.info("[Fofabot] Trying %s", url)
            r = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
            if r.status_code != 200 or not r.content:
                logger.debug("[Fofabot] %s -> HTTP %s", url, r.status_code)
                continue

            feed = feedparser.parse(r.content)
            if not feed.entries:
                logger.debug("[Fofabot] %s -> no entries", url)
                continue

            logger.info("[Fofabot] %s -> %d entries", url, len(feed.entries))
            return feed.entries
        except requests.RequestException as e:
            logger.debug("[Fofabot] %s failed: %s", url, e)
            continue

    logger.error("[Fofabot] All Nitter instances failed; no fofabot feed available")
    return None


def _entry_to_text(entry) -> tuple[str, Optional[str]]:
    """
    Combine title + description into the full tweet text. Nitter sometimes
    truncates the title and puts the rest in description, so we use both.

    Returns (cleaned_text, first_external_url). The URL is extracted from
    the raw HTML *before* stripping, since Nitter renders links as
    <a href="real_url">truncated_display…</a> and the href would otherwise
    be lost.
    """
    title_raw = entry.get("title", "") or ""
    body_raw  = entry.get("summary") or entry.get("description") or ""

    title = _clean_html(title_raw)
    body  = _clean_html(body_raw)

    if title and body and not body.startswith(title[:30]):
        text = f"{title}\n{body}"
    else:
        text = body or title

    ref_url = _extract_first_real_url(body_raw) or _extract_first_real_url(title_raw)
    return text, ref_url


def scrape_fofabot(
    username: str = "",      # ignored; kept for backward compat
    password: str = "",      # ignored
    email:    str = "",      # ignored
    max_tweets: int = 10,
    headless:   bool = True, # ignored
) -> list[dict]:
    """
    Fetch recent @fofabot tweets via Nitter RSS and parse out CVE intel.

    Returns a list of parsed dicts with the same shape as before:
        cve_id, cvss, description, fofa_query, fofa_raw, ref_url, raw_tweet

    The auth params (username/password/email) and headless flag are kept
    in the signature for backward compatibility with main.py and any
    external callers — they are silently ignored.
    """
    entries = _fetch_rss(FOFABOT_HANDLE)
    if not entries:
        return []

    results: list[dict] = []
    seen: set[str] = set()

    for entry in entries:
        if len(results) >= max_tweets:
            break
        text, url_hint = _entry_to_text(entry)
        if not text:
            continue
        parsed = parse_fofabot_tweet(text)
        if not parsed:
            continue
        if parsed["cve_id"] in seen:
            continue
        seen.add(parsed["cve_id"])
        if not parsed.get("ref_url") and url_hint:
            parsed["ref_url"] = url_hint
        logger.info(
            "[Fofabot] Parsed %s | FOFA: %s",
            parsed["cve_id"], parsed["fofa_query"],
        )
        results.append(parsed)

    logger.info("[Fofabot] Done — %d unique CVEs extracted", len(results))
    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    tweets = scrape_fofabot(max_tweets=5)

    print(f"\n=== Extracted {len(tweets)} CVEs ===")
    for t in tweets:
        print(f"\nCVE:   {t['cve_id']}")
        print(f"CVSS:  {t['cvss']}")
        print(f"FOFA:  {t['fofa_query']}")
        print(f"Ref:   {t['ref_url']}")
        desc = t.get("description") or ""
        print(f"Desc:  {desc[:120]}{'...' if len(desc) > 120 else ''}")
