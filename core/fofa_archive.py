"""
core/fofa_archive.py
---------------------
SQLite-backed archive of (natural-language description, FOFA query) pairs
sourced from fofabot tweets and existing PDF reports. Used as the corpus
for RAG retrieval in `core/fofa_gpt.py`.

Schema (lazy-created in the same DB the rest of the project uses):

    fofa_archive(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id      TEXT,                       -- nullable for non-CVE seeds
        nl          TEXT NOT NULL,              -- natural-language description
        query       TEXT NOT NULL,              -- canonical FOFA query
        description TEXT,                       -- optional longer description
        cvss        REAL,
        ref_url     TEXT,
        source      TEXT NOT NULL,              -- 'fofabot' | 'pdf' | 'seed'
        embedding   BLOB,                       -- numpy float32 vector
        added_at    TEXT NOT NULL,
        UNIQUE(query, nl)
    )

Public API:
    init_archive_table(db_path)
    add_entry(record, db_path)               -> bool (True if newly inserted)
    bulk_add(records, db_path)               -> int (count newly inserted)
    get_all_entries(db_path, with_embedding) -> list[dict]
    backfill_from_fofabot(db_path)           -> int
    backfill_from_pdf_reports(db_path)       -> int
    archive_size(db_path)                    -> int
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from database.db import DB_PATH, get_connection

logger = logging.getLogger(__name__)


# ── Schema ───────────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS fofa_archive (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT,
    nl          TEXT NOT NULL,
    query       TEXT NOT NULL,
    description TEXT,
    cvss        REAL,
    ref_url     TEXT,
    source      TEXT NOT NULL,
    embedding   BLOB,
    added_at    TEXT NOT NULL,
    UNIQUE(query, nl)
);
CREATE INDEX IF NOT EXISTS idx_fofa_archive_cve    ON fofa_archive(cve_id);
CREATE INDEX IF NOT EXISTS idx_fofa_archive_source ON fofa_archive(source);
"""


def init_archive_table(db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(_SCHEMA_SQL)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Insert ───────────────────────────────────────────────────────────────────
def add_entry(record: dict, db_path: str = DB_PATH) -> bool:
    """
    Insert a single record. Returns True if inserted, False if duplicate.
    Required keys: nl, query, source. Optional: cve_id, description,
    cvss, ref_url, embedding (bytes).
    """
    init_archive_table(db_path)
    record = {
        "cve_id":      record.get("cve_id"),
        "nl":          record["nl"].strip(),
        "query":       record["query"].strip(),
        "description": record.get("description"),
        "cvss":        record.get("cvss"),
        "ref_url":     record.get("ref_url"),
        "source":      record["source"],
        "embedding":   record.get("embedding"),
        "added_at":    _now(),
    }
    sql = """
        INSERT OR IGNORE INTO fofa_archive
            (cve_id, nl, query, description, cvss, ref_url, source, embedding, added_at)
        VALUES
            (:cve_id, :nl, :query, :description, :cvss, :ref_url, :source, :embedding, :added_at)
    """
    with get_connection(db_path) as conn:
        cur = conn.execute(sql, record)
        return cur.rowcount > 0


def bulk_add(records: Iterable[dict], db_path: str = DB_PATH) -> int:
    """Bulk insert. Returns count of newly inserted rows."""
    init_archive_table(db_path)
    rows = []
    for r in records:
        if not r.get("nl") or not r.get("query") or not r.get("source"):
            continue
        rows.append({
            "cve_id":      r.get("cve_id"),
            "nl":          r["nl"].strip(),
            "query":       r["query"].strip(),
            "description": r.get("description"),
            "cvss":        r.get("cvss"),
            "ref_url":     r.get("ref_url"),
            "source":      r["source"],
            "embedding":   r.get("embedding"),
            "added_at":    _now(),
        })

    if not rows:
        return 0

    sql = """
        INSERT OR IGNORE INTO fofa_archive
            (cve_id, nl, query, description, cvss, ref_url, source, embedding, added_at)
        VALUES
            (:cve_id, :nl, :query, :description, :cvss, :ref_url, :source, :embedding, :added_at)
    """
    with get_connection(db_path) as conn:
        before = conn.execute("SELECT COUNT(*) FROM fofa_archive").fetchone()[0]
        conn.executemany(sql, rows)
        after  = conn.execute("SELECT COUNT(*) FROM fofa_archive").fetchone()[0]
    return after - before


# ── Retrieve ─────────────────────────────────────────────────────────────────
def get_all_entries(
    db_path: str = DB_PATH,
    with_embedding: bool = False,
    limit: Optional[int] = None,
) -> list[dict]:
    init_archive_table(db_path)
    cols = "id, cve_id, nl, query, description, cvss, ref_url, source, added_at"
    if with_embedding:
        cols += ", embedding"
    q = f"SELECT {cols} FROM fofa_archive"
    if limit:
        q += f" LIMIT {int(limit)}"
    with get_connection(db_path) as conn:
        rows = conn.execute(q).fetchall()
    return [dict(r) for r in rows]


def archive_size(db_path: str = DB_PATH) -> int:
    init_archive_table(db_path)
    with get_connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM fofa_archive").fetchone()[0]


def update_embedding(entry_id: int, embedding: bytes, db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            "UPDATE fofa_archive SET embedding = ? WHERE id = ?",
            (embedding, entry_id),
        )


# ── Backfill: fofabot RSS ────────────────────────────────────────────────────
def backfill_from_fofabot(db_path: str = DB_PATH, max_tweets: int = 50) -> int:
    """
    Pull whatever fofabot tweets are reachable via Nitter RSS right now and
    add new (nl, query) pairs to the archive. Idempotent — duplicates are
    skipped via the (query, nl) UNIQUE constraint.
    """
    try:
        from scrapers.fofabot_scraper import scrape_fofabot
    except Exception as e:
        logger.warning(f"[Archive] fofabot scraper unavailable: {e}")
        return 0

    tweets = scrape_fofabot(max_tweets=max_tweets)
    records = []
    for t in tweets:
        cve_id = t.get("cve_id")
        query  = t.get("fofa_query")
        desc   = (t.get("description") or "").strip()
        if not query or not cve_id:
            continue

        # Build one or two NL prompts per tweet for diversity:
        # 1. CVE-anchored: matches users searching by CVE ID
        # 2. Description-anchored: matches users searching by intent
        records.append({
            "cve_id":      cve_id,
            "nl":          f"find devices vulnerable to {cve_id}",
            "query":       query,
            "description": desc,
            "cvss":        t.get("cvss"),
            "ref_url":     t.get("ref_url"),
            "source":      "fofabot",
        })
        if desc:
            records.append({
                "cve_id":      cve_id,
                "nl":          desc,
                "query":       query,
                "description": desc,
                "cvss":        t.get("cvss"),
                "ref_url":     t.get("ref_url"),
                "source":      "fofabot",
            })

    inserted = bulk_add(records, db_path)
    logger.info(f"[Archive] fofabot backfill: {inserted} new of {len(records)} candidates")
    return inserted


# ── Backfill: existing PDF reports ───────────────────────────────────────────
# Each PDF in reports/ was generated by the enrichment pipeline and contains
# a verified FOFA query. The matching enriched dict isn't persisted, but the
# SQLite `cves` table holds the metadata (advisory_url field stores the FOFA
# query for enriched-source CVEs). We can mine that cleanly.

def backfill_from_pdf_reports(db_path: str = DB_PATH) -> int:
    """
    Use the existing `cves` rows where source='enriched' to seed the archive.
    `advisory_url` for enriched rows holds the FOFA query (see main.py).
    """
    from database.db import get_connection
    init_archive_table(db_path)

    records = []
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT cve_id, product_norm, severity, description, cvss_score,
                   advisory_url AS fofa_query
            FROM cves
            WHERE source = 'enriched' AND advisory_url IS NOT NULL
            """
        ).fetchall()

    for r in rows:
        query = (r["fofa_query"] or "").strip()
        # Skip rows whose advisory_url isn't actually a FOFA query
        if not query or "=" not in query or "country" not in query:
            continue
        # Skip legacy queries that used the wrong field name (product= instead
        # of app=). Those were generated before we fixed the FOFA generator
        # and would teach the LLM the wrong syntax.
        if "product=" in query:
            continue
        cve_id  = r["cve_id"]
        product = (r["product_norm"] or "").replace("_", " ").strip() or "the affected product"
        records.append({
            "cve_id":      cve_id,
            "nl":          f"find devices vulnerable to {cve_id}",
            "query":       query,
            "description": r["description"],
            "cvss":        r["cvss_score"],
            "source":      "pdf",
        })
        records.append({
            "cve_id":      cve_id,
            "nl":          f"find {product} servers in India",
            "query":       query,
            "description": r["description"],
            "cvss":        r["cvss_score"],
            "source":      "pdf",
        })

    inserted = bulk_add(records, db_path)
    logger.info(f"[Archive] PDF backfill: {inserted} new of {len(records)} candidates")
    return inserted


# ── Backfill: seed examples ──────────────────────────────────────────────────
SEED_EXAMPLES_NL_QUERY: list[tuple[str, str]] = [
    ("find Roundcube webmail servers in India",                      'app="Roundcube-Webmail" && country="IN"'),
    ("find ERPNext instances exposed in India",                      'app="ERPNext" && country="IN"'),
    ("find FortiGate SSL VPN devices in India",                      '(app="FortiOS" || app="Fortinet-SSL-VPN") && country="IN"'),
    ("Palo Alto GlobalProtect portals in India",                     '(app="PAN-OS" || app="Palo-Alto-GlobalProtect") && country="IN"'),
    ("Cisco IOS XE devices running 17.9 in India",                   'app="Cisco-IOS-XE" && country="IN" && banner*="17.9.*"'),
    ("Microsoft Exchange servers in India",                          'app="Microsoft-Exchange" && country="IN"'),
    ("TYPO3 CMS instances in India",                                 'app="TYPO3" && country="IN"'),
    ("FreePBX servers in India",                                     'app="FreePBX" && country="IN"'),
    ("Apache Tomcat instances in India",                             'app="Apache-Tomcat" && country="IN"'),
    ("Citrix NetScaler ADC devices in India",                        'app="Citrix-ADC" && country="IN"'),
    ("Ivanti Connect Secure VPN gateways in India",                  'app="Ivanti-Connect-Secure" && country="IN"'),
    ("VMware vCenter servers running 7.x in India",                  'app="VMware-vCenter" && country="IN" && banner*="7.*"'),
    ("nginx servers in India",                                       'app="nginx" && country="IN"'),
    ("Apache HTTP servers in India",                                 'app="Apache-httpd" && country="IN"'),
    ("MikroTik routers in India",                                    'app="MikroTik-RouterOS" && country="IN"'),
    ("Atlassian Confluence in India",                                'app="Atlassian-Confluence" && country="IN"'),
    ("Atlassian Jira in India",                                      'app="Atlassian-Jira" && country="IN"'),
    ("WordPress sites in India",                                     'app="WordPress" && country="IN"'),
    ("Drupal sites in India",                                        'app="Drupal" && country="IN"'),
    ("F5 BIG-IP load balancers in India",                            'app="F5-BIG-IP" && country="IN"'),
    ("VMware ESXi hypervisors in India",                             'app="VMware-ESXi" && country="IN"'),
    ("Microsoft IIS web servers in India",                           'app="Microsoft-IIS" && country="IN"'),
    ("Microsoft SharePoint servers in India",                        'app="Microsoft-SharePoint" && country="IN"'),
    ("Cisco ASA firewalls in India",                                 'app="Cisco-ASA" && country="IN"'),
    ("Juniper SRX firewalls in India",                               '(app="Juniper-JunOS" || app="Juniper-SRX") && country="IN"'),
    ("FortiManager devices in India",                                'app="FortiManager" && country="IN"'),
    ("Pulse Secure VPN gateways in India",                           'app="Pulse-Secure" && country="IN"'),
    ("Jenkins automation servers in India",                          'app="Jenkins" && country="IN"'),
    ("GitLab self-hosted in India",                                  'app="GitLab" && country="IN"'),
    ("Cisco Webex platforms in India",                               'app="Cisco-Webex" && country="IN"'),
    ("Cisco Identity Services Engine in India",                      'app="Cisco-ISE" && country="IN"'),
    ("Siemens SIMATIC PLCs in India",                                'app="Siemens-SIMATIC" && country="IN"'),
    ("MLflow tracking servers in India",                             'app="MLflow" && country="IN"'),
    ("Open WebUI instances in India",                                'app="Open-WebUI" && country="IN"'),
    ("phpMyFAQ knowledge bases in India",                            'app="phpMyFAQ" && country="IN"'),
    ("Chroma vector database servers in India",                      'app="Chroma-ChromaDB" && country="IN"'),
    ("Joomla CMS sites in India",                                    'app="Joomla" && country="IN"'),
    ("FortiAnalyzer servers in India",                               'app="FortiAnalyzer" && country="IN"'),
    ("FortiWeb web application firewalls in India",                  'app="FortiWeb" && country="IN"'),
    ("FortiProxy gateways in India",                                 'app="FortiProxy" && country="IN"'),
]


def backfill_seeds(db_path: str = DB_PATH) -> int:
    """Add the curated static seed examples. Idempotent."""
    records = [
        {"nl": nl, "query": q, "source": "seed"}
        for nl, q in SEED_EXAMPLES_NL_QUERY
    ]
    inserted = bulk_add(records, db_path)
    logger.info(f"[Archive] seed backfill: {inserted} new of {len(records)} candidates")
    return inserted


# ── Self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    s = backfill_seeds()
    p = backfill_from_pdf_reports()
    f = backfill_from_fofabot()
    print(f"\nseeds inserted : {s}")
    print(f"pdf inserted   : {p}")
    print(f"fofabot inserted: {f}")
    print(f"archive size   : {archive_size()}")
