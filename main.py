"""
usage:
    python main.py              # start scheduler (runs forever)
    python main.py --now        # run full pipeline once and exit
    python main.py --scrape     # run scrapers only
    python main.py --fofabot    # run fofabot scraper only
    python main.py --stats      # print DB stats and exit
    python main.py --dry-run    # run pipeline but skip alerts
"""

import argparse
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
import schedule

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FILE   = os.path.join(os.path.dirname(__file__), "logs", "cve_monitor.log")

def setup_logging(level: int = logging.INFO) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ]
    logging.basicConfig(level=level, format=LOG_FORMAT, handlers=handlers)

logger = logging.getLogger(__name__)


def _load_config() -> dict:
    try:
        import config as cfg
    except ImportError:
        logger.critical("config.py not found!")
        sys.exit(1)
    return {
        "nvd_api_key": getattr(cfg, "NVD_API_KEY", ""),
        "dev_mode":    getattr(cfg, "DEV_MODE", False),
    }


def _run_certIn() -> list[dict]:
    try:
        from scrapers.certIn import scrape_certIn
        records = scrape_certIn()
        logger.info("[CERT-In] Fetched %d records", len(records))
        return records
    except Exception as e:
        logger.error("[CERT-In] Failed: %s", e)
        return []


def _run_nvd(api_key: str) -> list[dict]:
    try:
        from scrapers.nvd import scrape_nvd
        records = scrape_nvd()
        logger.info("[NVD] Fetched %d records", len(records))
        return records
    except Exception as e:
        logger.error("[NVD] Failed: %s", e)
        return []


def _run_fofabot() -> list[dict]:
    """Scrape @fofabot tweets for CVE IDs."""
    try:
        from scrapers.fofabot_scraper import scrape_fofabot
        tweets = scrape_fofabot(max_tweets=10, headless=True)
        logger.info("[Fofabot] Extracted %d CVEs from tweets", len(tweets))
        return tweets
    except Exception as e:
        logger.error("[Fofabot] Failed: %s", e)
        return []


def _enrich_and_report(cve_id: str, fofa_hint: str = None) -> dict | None:
    try:
        from scrapers.agent_search import search_cve, enrich_with_full_articles
        from core.enrichment_pipeline import enrich_single_cve
        from core.groq_enricher import generate_fofa_query
        from core.report_generator import generate_cve_report
        from database.db import insert_cve, init_db

        logger.info("[Enrich] Processing %s", cve_id)

        results = search_cve(cve_id)

        if len(results) < 3:
            logger.warning("[Enrich] Skipping %s — only %d articles found (low coverage)", cve_id, len(results))
            return None

        enriched = enrich_single_cve(cve_id)
        if not enriched:
            logger.warning("[Enrich] LLM enrichment failed for %s", cve_id)
            return None

        fofa_query = fofa_hint or generate_fofa_query(enriched)

        init_db()
        insert_cve({
            "cve_id":        enriched.get("cve_id", cve_id),
            "source":        "enriched",
            "product_raw":   ", ".join(enriched.get("products") or []),
            "product_norm":  ", ".join(enriched.get("products") or []),
            "version_range": ", ".join(enriched.get("affected_versions") or []),
            "oem":           (enriched.get("products") or ["Unknown"])[0],
            "severity":      (enriched.get("severity") or "UNKNOWN").upper(),
            "cvss_score":    None,
            "description":   enriched.get("description"),
            "mitigation":    enriched.get("mitigation"),
            "advisory_url":  fofa_query,
            "published_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        })

        os.makedirs("reports", exist_ok=True)
        out_path = os.path.join("reports", f"{cve_id}_report.pdf")
        generate_cve_report(enriched, fofa_query, results, out_path)
        logger.info("[Enrich] PDF saved + DB updated: %s", out_path)

        return {**enriched, "fofa_query": fofa_query, "pdf_path": out_path}

    except Exception as e:
        logger.error("[Enrich] Error for %s: %s", cve_id, e)
        logger.debug(traceback.format_exc())
        return None

def _is_processed(cve_id: str) -> bool:
    return os.path.exists(os.path.join("reports", f"{cve_id}_report.pdf"))


def _get_new_cves(records: list[dict], limit: int = 20) -> list[str]:
    """
    Filter to only new unprocessed CVEs.
    Prioritize CRITICAL and HIGH severity.
    Limit to avoid hammering the LLM and external APIs.
    """
    seen = set()
    priority = []
    normal   = []

    for r in records:
        cve_id = r.get("cve_id")
        if not cve_id or cve_id in seen:
            continue
        if _is_processed(cve_id):
            continue
        seen.add(cve_id)
        sev = (r.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH"):
            priority.append(cve_id)
        else:
            normal.append(cve_id)

    # CRITICAL/HIGH first, then rest, capped at limit
    return (priority + normal)[:limit]


def run_scrape_pipeline(cfg: dict) -> None:
    """Pull CVEs from NVD + CERT-In, enrich new ones, generate PDFs."""
    logger.info("=" * 55)
    logger.info("CVE SCRAPE PIPELINE STARTING — %s",
                datetime.now().strftime("%Y-%m-%d %H:%M"))
    logger.info("=" * 55)

    records = []
    records.extend(_run_certIn())
    records.extend(_run_nvd(cfg["nvd_api_key"]))

    new_cves = _get_new_cves(records, limit=20)
    logger.info("New unprocessed CVEs to enrich: %d", len(new_cves))

    for cve_id in new_cves:
        _enrich_and_report(cve_id)
        time.sleep(2)

    logger.info("Scrape pipeline done — %d CVEs processed", len(new_cves))


def run_fofabot_pipeline() -> None:
    """Scrape @fofabot, enrich each CVE, generate PDFs."""
    logger.info("=" * 55)
    logger.info("FOFABOT PIPELINE STARTING — %s",
                datetime.now().strftime("%Y-%m-%d %H:%M"))
    logger.info("=" * 55)

    tweets = _run_fofabot()
    if not tweets:
        logger.info("No new fofabot CVEs found")
        return

    for tweet in tweets:
        cve_id     = tweet.get("cve_id")
        fofa_query = tweet.get("fofa_query")  # already has country=IN
        if not cve_id:
            continue
        if _is_processed(cve_id):
            logger.info("[Fofabot] %s already processed, skipping", cve_id)
            continue
        _enrich_and_report(cve_id, fofa_hint=fofa_query)
        time.sleep(3)

    logger.info("Fofabot pipeline done")


def run_full_pipeline(cfg: dict) -> None:
    """Run both scraper + fofabot pipelines."""
    start = datetime.now(timezone.utc)
    logger.info("FULL PIPELINE RUN — %s", start.strftime("%Y-%m-%d %H:%M UTC"))

    run_scrape_pipeline(cfg)
    run_fofabot_pipeline()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info("FULL PIPELINE COMPLETE in %.1fs", elapsed)


def log_stats() -> None:
    reports = len([f for f in os.listdir("reports") if f.endswith(".pdf")]) \
              if os.path.exists("reports") else 0
    logger.info("STATS — PDF reports generated: %d", reports)


def run_scheduler(cfg: dict) -> None:
    logger.info("=" * 55)
    logger.info("NTRO CVE MONITOR STARTING")
    logger.info("Dev mode : %s", cfg["dev_mode"])
    logger.info("=" * 55)

    run_full_pipeline(cfg)
    log_stats()

    schedule.every(6).hours.do(run_full_pipeline, cfg=cfg)
    schedule.every(3).hours.do(run_fofabot_pipeline)
    schedule.every(24).hours.do(log_stats)

    logger.info("Scheduler running — full pipeline every 6hrs, fofabot every 3hrs")
    logger.info("Press Ctrl+C to stop")

    while True:
        try:
            schedule.run_pending()
            time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            sys.exit(0)
        except Exception as e:
            logger.error("Scheduler error: %s", e)
            time.sleep(60)


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE Monitoring System")
    parser.add_argument("--now",     action="store_true", help="Run full pipeline once and exit")
    parser.add_argument("--scrape",  action="store_true", help="Run NVD+CERT-In scrapers only")
    parser.add_argument("--fofabot", action="store_true", help="Run fofabot scraper only")
    parser.add_argument("--stats",   action="store_true", help="Print stats and exit")
    parser.add_argument("--dry-run", action="store_true", help="Run without sending alerts")
    parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.debug else logging.INFO)
    cfg = _load_config()

    os.makedirs("reports", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    if args.stats:
        log_stats()
    elif args.scrape:
        run_scrape_pipeline(cfg)
    elif args.fofabot:
        run_fofabot_pipeline()
    elif args.now or args.dry_run:
        run_full_pipeline(cfg)
    else:
        run_scheduler(cfg)


if __name__ == "__main__":
    main()