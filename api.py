"""
api.py
------
JSON API for the React frontend. Runs on port 5000.

This is intentionally separate from app.py so the legacy Flask UI keeps
working untouched. The React frontend (in ./frontend) is the new entrypoint.

Run:
    python api.py            # Dev:  port 5000, debug on, CORS open
    python app.py            # Legacy UI: still works, untouched

Endpoints:
    GET  /api/stats                  Dashboard stats from SQLite
    GET  /api/cves?limit=50          Recent CVEs
    GET  /api/reports                List of generated PDF reports
    GET  /api/health                 Health probe
    POST /api/generate               Kick off enrichment for a CVE
    GET  /api/stream/<job_id>        Server-Sent Events log stream
    GET  /api/download/<cve_id>      Download generated PDF
"""

import logging
import os
import queue
import threading
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

job_queues: dict[str, queue.Queue] = {}


# ── Pipeline pre-warm ────────────────────────────────────────────────────────
def _prewarm_ollama():
    def _warm():
        try:
            import requests
            from config import OLLAMA_BASE_URL, OLLAMA_MODEL
            url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
            requests.post(url, json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "user", "content": "ok"}],
                "stream": False,
                "keep_alive": "30m",
                "options": {"num_predict": 1, "num_ctx": 512},
            }, timeout=120)
            logger.info("[Prewarm] Ollama model loaded")
        except Exception as e:
            logger.warning(f"[Prewarm] failed: {e}")

    threading.Thread(target=_warm, daemon=True).start()


# ── FofaGPT archive bootstrap (seeds + PDF + fofabot, then index) ───────────
def _bootstrap_fofa_archive():
    """
    Backfill the fofa_archive table from all available sources, then
    embed any rows that don't have a vector yet. Runs in a background
    thread so API startup isn't blocked.
    """
    def _run():
        try:
            from core.fofa_archive import (
                backfill_seeds, backfill_from_pdf_reports,
                backfill_from_fofabot, archive_size,
            )
            s = backfill_seeds()
            p = backfill_from_pdf_reports()
            f = backfill_from_fofabot()
            logger.info(
                f"[Archive] bootstrap inserted seeds={s} pdf={p} fofabot={f}; "
                f"size now {archive_size()}"
            )
            from core.fofa_rag import ensure_embeddings
            n = ensure_embeddings()
            logger.info(f"[Archive] embedded {n} new rows; RAG ready")
        except Exception as e:
            logger.exception(f"[Archive] bootstrap failed: {e}")

    threading.Thread(target=_run, daemon=True).start()


# ── Continuous fofabot ingestion (every N hours while API is up) ────────────
INGEST_INTERVAL_SECONDS = 3 * 60 * 60   # 3 hours, matches main.py scheduler


def _run_ingest_cycle() -> dict:
    """
    Pull fresh fofabot tweets, dedupe + insert into archive, embed any
    new rows. Used by both the scheduled background thread and the
    on-demand /api/fofa-gpt/ingest endpoint. Returns a summary dict.
    """
    from core.fofa_archive import backfill_from_fofabot, archive_size
    from core.fofa_rag import ensure_embeddings
    before = archive_size()
    inserted = backfill_from_fofabot()
    embedded = ensure_embeddings()
    after = archive_size()
    return {
        "inserted":     inserted,
        "embedded":     embedded,
        "size_before":  before,
        "size_after":   after,
        "ts":           datetime.utcnow().isoformat() + "Z",
    }


def _start_ingest_loop():
    """
    Background thread that re-runs the fofabot pull every INGEST_INTERVAL_SECONDS.
    First cycle is the bootstrap above, so this only starts the *recurring*
    schedule and skips the immediate first run.
    """
    import time

    def _loop():
        # Stagger first wake-up so we don't double-run with the bootstrap thread
        time.sleep(INGEST_INTERVAL_SECONDS)
        while True:
            try:
                summary = _run_ingest_cycle()
                logger.info(
                    f"[Ingest] cycle complete: "
                    f"+{summary['inserted']} fofabot rows, "
                    f"+{summary['embedded']} embeddings, "
                    f"archive now {summary['size_after']}"
                )
            except Exception as e:
                logger.warning(f"[Ingest] cycle failed: {e}")
            time.sleep(INGEST_INTERVAL_SECONDS)

    threading.Thread(target=_loop, daemon=True).start()
    logger.info(
        f"[Ingest] background loop scheduled every "
        f"{INGEST_INTERVAL_SECONDS // 3600}h"
    )


# ── Pipeline runner (matches app.py format for backwards compat) ─────────────
def run_pipeline(cve_id: str, q: queue.Queue):
    try:
        q.put(f"[+] Starting pipeline for {cve_id}")

        q.put("[*] Searching the web (Tavily) for articles...")
        from scrapers.agent_search import search_cve, enrich_with_full_articles
        results = search_cve(cve_id)
        q.put(f"[+] Found {len(results)} articles")

        if len(results) < 1:
            q.put("[!] No search results — cannot enrich")
            q.put("DONE:error")
            return

        q.put("[*] Fetching full article content...")
        context = enrich_with_full_articles(results, top_n=2)

        q.put("[*] Running local LLM enrichment (Ollama)...")
        from core.groq_enricher import enrich_cve
        enriched = enrich_cve(cve_id, context)
        if not enriched:
            q.put("[!] ERROR: Enrichment failed (check Ollama is running)")
            q.put("DONE:error")
            return

        q.put(f"[+] Severity: {enriched.get('severity')}")
        q.put(f"[+] Products: {', '.join(enriched.get('products') or [])}")
        q.put(f"[+] Affected versions: {len(enriched.get('affected_versions') or [])} found")
        q.put(f"[+] Fixed versions: {len(enriched.get('fixed_versions') or [])} found")

        q.put("[*] Generating FOFA query...")
        from core.groq_enricher import generate_fofa_query
        query = generate_fofa_query(enriched)
        q.put(f"[+] FOFA: {query}")

        q.put("[*] Building PDF report...")
        from core.report_generator import generate_cve_report
        out_path = os.path.join("reports", f"{cve_id}_report.pdf")
        os.makedirs("reports", exist_ok=True)
        generate_cve_report(enriched, query, results, out_path)

        # Send the structured result so the frontend can render cards
        q.put(f"RESULT:{_safe_json({'enriched': enriched, 'fofa_query': query, 'pdf_path': out_path})}")

        q.put(f"[+] PDF saved: {out_path}")
        q.put(f"DONE:ok:{cve_id}")
    except Exception as e:
        logger.exception("Pipeline error")
        q.put(f"[!] ERROR: {e}")
        q.put("DONE:error")


def _safe_json(obj) -> str:
    import json
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "{}"


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/stats")
def stats():
    """Aggregate stats for the dashboard."""
    try:
        from database.db import get_stats, init_db, get_connection
        init_db()
        s = get_stats()

        # Severity breakdown for the chart
        sev_buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM cves GROUP BY severity"
            ).fetchall()
            for r in rows:
                sev = (r["severity"] or "UNKNOWN").upper()
                if sev in sev_buckets:
                    sev_buckets[sev] = r["c"]

            # Source breakdown
            src_rows = conn.execute(
                "SELECT source, COUNT(*) AS c FROM cves GROUP BY source ORDER BY c DESC"
            ).fetchall()
            sources = [{"source": r["source"], "count": r["c"]} for r in src_rows]

        # Reports on disk
        reports_dir = "reports"
        report_count = 0
        if os.path.isdir(reports_dir):
            report_count = sum(1 for f in os.listdir(reports_dir) if f.endswith(".pdf"))

        return jsonify({
            "totals": {
                "cves":    s.get("total_cves", 0),
                "assets":  s.get("total_assets", 0),
                "alerts":  s.get("total_alerts", 0),
                "reports": report_count,
            },
            "severity": sev_buckets,
            "sources":  sources,
        })
    except Exception as e:
        logger.exception("/api/stats failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/cves")
def cves():
    """Recent CVE rows for the dashboard table."""
    try:
        from database.db import get_connection, init_db
        init_db()
        limit = max(1, min(500, request.args.get("limit", 50, type=int)))
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT cve_id, source, severity, cvss_score, oem, "
                "       product_raw, product_norm, version_range, "
                "       description, published_date, fetched_at, advisory_url "
                "FROM cves "
                "ORDER BY fetched_at DESC "
                "LIMIT ?",
                (limit,),
            ).fetchall()
        return jsonify({"cves": [dict(r) for r in rows]})
    except Exception as e:
        logger.exception("/api/cves failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports")
def reports():
    """List generated PDF reports."""
    reports_dir = "reports"
    if not os.path.isdir(reports_dir):
        return jsonify({"reports": []})

    items = []
    for fn in sorted(os.listdir(reports_dir), reverse=True):
        if not fn.endswith(".pdf"):
            continue
        path = os.path.join(reports_dir, fn)
        cve_id = fn.replace("_report.pdf", "")
        items.append({
            "cve_id":   cve_id,
            "filename": fn,
            "size":     os.path.getsize(path),
            "modified": datetime.utcfromtimestamp(os.path.getmtime(path)).isoformat() + "Z",
        })
    return jsonify({"reports": items})


@app.route("/api/generate", methods=["POST"])
def generate():
    cve_id = (request.json or {}).get("cve_id", "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return jsonify({"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNN"}), 400

    job_id = str(uuid.uuid4())
    q = queue.Queue()
    job_queues[job_id] = q

    t = threading.Thread(target=run_pipeline, args=(cve_id, q), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "cve_id": cve_id})


@app.route("/api/stream/<job_id>")
def stream(job_id):
    def generate_stream():
        q = job_queues.get(job_id)
        if not q:
            yield "data: [!] Job not found\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=15)
                yield f"data: {msg}\n\n"
                if msg.startswith("DONE:"):
                    break
            except queue.Empty:
                yield ": keepalive\n\n"

    return Response(
        generate_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/download/<cve_id>")
def download(cve_id):
    cve_id = cve_id.strip().upper()
    path = os.path.join("reports", f"{cve_id}_report.pdf")
    if not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    return send_file(path, as_attachment=True, download_name=f"{cve_id}_report.pdf")


# ── FofaGPT (natural-language → FOFA query) ──────────────────────────────────
@app.route("/api/fofa-gpt", methods=["POST"])
def fofa_gpt():
    prompt = ((request.json or {}).get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400
    try:
        from core.fofa_gpt import nl_to_fofa
        result = nl_to_fofa(prompt)
        return jsonify(result)
    except Exception as e:
        logger.exception("/api/fofa-gpt failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/fofa-gpt/examples")
def fofa_gpt_examples():
    try:
        from core.fofa_gpt import get_fofabot_examples
        return jsonify({"examples": get_fofabot_examples(limit=12)})
    except Exception as e:
        logger.exception("/api/fofa-gpt/examples failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/fofa-gpt/stats")
def fofa_gpt_stats():
    """
    Stats about the RAG corpus — total entries by source. Used by the UI
    to show how big the verified-example dataset is.
    """
    try:
        from database.db import get_connection
        from core.fofa_archive import init_archive_table
        init_archive_table()
        with get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM fofa_archive").fetchone()[0]
            by_src = conn.execute(
                "SELECT source, COUNT(*) AS c FROM fofa_archive GROUP BY source"
            ).fetchall()
            embedded = conn.execute(
                "SELECT COUNT(*) FROM fofa_archive WHERE embedding IS NOT NULL"
            ).fetchone()[0]
        return jsonify({
            "total":     total,
            "embedded":  embedded,
            "by_source": [{"source": r["source"], "count": r["c"]} for r in by_src],
        })
    except Exception as e:
        logger.exception("/api/fofa-gpt/stats failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/fofa-gpt/ingest", methods=["POST"])
def fofa_gpt_ingest():
    """
    On-demand fofabot ingest. Useful during demos to show the corpus
    growing live. Same logic as the scheduled background loop.
    """
    try:
        summary = _run_ingest_cycle()
        return jsonify(summary)
    except Exception as e:
        logger.exception("/api/fofa-gpt/ingest failed")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    _prewarm_ollama()
    _bootstrap_fofa_archive()
    _start_ingest_loop()
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
