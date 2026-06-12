"""
Flask web UI for CVE Intelligence Report generation.
"""

import os
import threading
import queue
import logging
from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)
job_queues = {}  # job_id -> queue of log lines


def _prewarm_ollama():
    """
    Hit Ollama with a tiny request on startup so the model is loaded into
    RAM before the first demo CVE arrives. Without this the first CVE pays
    a 30-60s cold-load penalty.
    """
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
            logging.getLogger(__name__).info("[Prewarm] Ollama model loaded")
        except Exception as e:
            logging.getLogger(__name__).warning(f"[Prewarm] failed: {e}")

    threading.Thread(target=_warm, daemon=True).start()

def run_pipeline(cve_id: str, q: queue.Queue):
    try:
        q.put(f"[+] Starting pipeline for {cve_id}...")

        q.put("[*] Searching the web (Tavily) for articles...")
        from scrapers.agent_search import (
            search_cve, enrich_with_full_articles,
        )
        results = search_cve(cve_id)
        q.put(f"[+] Found {len(results)} articles")

        if len(results) < 1:
            q.put("[!] No search results — cannot enrich")
            q.put("DONE:error")
            return

        q.put("[*] Fetching full article content...")
        context = enrich_with_full_articles(results, top_n=2)

        q.put("[*] Running local LLM enrichment (Ollama, may take 1-2 min on CPU)...")
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

        q.put(f"[+] PDF saved: {out_path}")
        q.put(f"DONE:ok:{cve_id}")

    except Exception as e:
        q.put(f"[!] ERROR: {e}")
        q.put("DONE:error")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate", methods=["POST"])
def generate():
    cve_id = request.json.get("cve_id", "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return jsonify({"error": "Invalid CVE ID format"}), 400

    import uuid
    job_id = str(uuid.uuid4())
    q = queue.Queue()
    job_queues[job_id] = q

    t = threading.Thread(target=run_pipeline, args=(cve_id, q), daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/stream/<job_id>")
def stream(job_id):
    def generate_stream():
        q = job_queues.get(job_id)
        if not q:
            yield "data: [!] Job not found\n\n"
            return
        # Heartbeat every 15s keeps the connection alive while Ollama runs.
        # Total wall time is bounded by OLLAMA_TIMEOUT in core.groq_enricher.
        while True:
            try:
                msg = q.get(timeout=15)
                yield f"data: {msg}\n\n"
                if msg.startswith("DONE:"):
                    break
            except queue.Empty:
                yield ": keepalive\n\n"

    from flask import Response
    return Response(generate_stream(), mimetype="text/event-stream")


@app.route("/download/<cve_id>")
def download(cve_id):
    path = os.path.join("reports", f"{cve_id}_report.pdf")
    if not os.path.exists(path):
        return "Report not found", 404
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    _prewarm_ollama()
    app.run(debug=True, port=5000, threaded=True)