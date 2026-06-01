"""
database/db.py
--------------
SQLite database layer for the NTRO CVE Monitoring System.
Handles schema creation, all insert/query operations, and deduplication.

Tables:
    - cves         : Normalized CVE records from all sources
    - assets       : Discovered assets (IPs, banners, product fingerprints)
    - alerts_sent  : Dedup log to prevent re-alerting on same (cve_id, asset_ip)
"""

import sqlite3
import logging
import os
from datetime import datetime, timezone
from contextlib import contextmanager

# ── Logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── DB path (resolved relative to project root) ───────────────────────────────
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "cve_monitor.db")


# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
-- All CVEs collected from NVD, OEM advisories, CERT-In, GitHub, etc.
CREATE TABLE IF NOT EXISTS cves (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT    NOT NULL,
    source          TEXT    NOT NULL,           -- 'nvd' | 'cisco' | 'microsoft' | 'certIn' | 'github' | ...
    product_raw     TEXT,                       -- original product string from source
    product_norm    TEXT,                       -- normalizer.py output
    version_range   TEXT,                       -- e.g. "< 17.3.1" or "15.0 - 15.4.3"
    oem             TEXT,                       -- 'Cisco' | 'Microsoft' | 'Fortinet' etc.
    severity        TEXT,                       -- 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
    cvss_score      REAL,                       -- CVSS v3 base score (nullable)
    description     TEXT,
    mitigation      TEXT,
    advisory_url    TEXT,
    published_date  TEXT,                       -- ISO-8601
    fetched_at      TEXT    NOT NULL,           -- ISO-8601, when we scraped it
    UNIQUE(cve_id, source)                      -- same CVE can appear in NVD + OEM advisory
);

-- Assets discovered via ZMap/Nmap/FOFA/crt.sh for target organisations
CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL,
    port            INTEGER,
    protocol        TEXT,                       -- 'tcp' | 'udp'
    service         TEXT,                       -- 'http' | 'ssh' | 'smb' ...
    banner          TEXT,                       -- raw banner grabbed by nmap
    product_norm    TEXT,                       -- normalizer.py output
    version         TEXT,                       -- detected version string
    org             TEXT,                       -- 'BSNL' | 'ONGC' | 'NIC' ...
    asn             TEXT,                       -- e.g. 'AS9829'
    hostname        TEXT,
    discovered_at   TEXT    NOT NULL,           -- ISO-8601
    last_seen       TEXT    NOT NULL,           -- ISO-8601; updated on re-scan
    UNIQUE(ip, port, protocol)
);

-- Alert dedup log: one row = one alert sent for a (CVE, asset) pair
CREATE TABLE IF NOT EXISTS alerts_sent (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT    NOT NULL,
    asset_ip        TEXT    NOT NULL,
    asset_port      INTEGER,
    org             TEXT,
    severity        TEXT,
    sent_at         TEXT    NOT NULL,           -- ISO-8601
    recipient       TEXT,                       -- email address alerted
    UNIQUE(cve_id, asset_ip)                    -- core dedup constraint
);

-- Optional: source run log so we can audit scraper health
CREATE TABLE IF NOT EXISTS scraper_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL,           -- scraper name
    status          TEXT    NOT NULL,           -- 'success' | 'partial' | 'failed'
    cves_fetched    INTEGER DEFAULT 0,
    error_msg       TEXT,
    ran_at          TEXT    NOT NULL            -- ISO-8601
);

-- Indexes for hot query paths
CREATE INDEX IF NOT EXISTS idx_cves_cve_id      ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_product_norm ON cves(product_norm);
CREATE INDEX IF NOT EXISTS idx_cves_severity    ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_assets_product   ON assets(product_norm);
CREATE INDEX IF NOT EXISTS idx_assets_org       ON assets(org);
CREATE INDEX IF NOT EXISTS idx_alerts_cve_ip    ON alerts_sent(cve_id, asset_ip);
"""


# ── Connection context manager ────────────────────────────────────────────────
@contextmanager
def get_connection(db_path: str = DB_PATH):
    """
    Yields a sqlite3 connection with WAL mode and foreign keys enabled.
    Auto-commits on clean exit, rolls back on exception.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row          # access columns by name
    conn.execute("PRAGMA journal_mode=WAL") # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema initialisation ─────────────────────────────────────────────────────
def init_db(db_path: str = DB_PATH) -> None:
    """Create all tables and indexes. Safe to call multiple times (IF NOT EXISTS)."""
    logger.info("Initialising database at %s", db_path)
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
    logger.info("Database ready.")


# ── Helper ────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ══════════════════════════════════════════════════════════════════════════════
#  CVE operations
# ══════════════════════════════════════════════════════════════════════════════

def insert_cve(cve: dict, db_path: str = DB_PATH) -> bool:
    """
    Insert a single CVE record. Silently skips duplicates (same cve_id + source).

    Expected keys in `cve` dict:
        cve_id, source, product_raw, product_norm, version_range, oem,
        severity, cvss_score, description, mitigation, advisory_url, published_date

    Returns True if inserted, False if duplicate.
    """
    sql = """
        INSERT OR IGNORE INTO cves (
            cve_id, source, product_raw, product_norm, version_range,
            oem, severity, cvss_score, description, mitigation,
            advisory_url, published_date, fetched_at
        ) VALUES (
            :cve_id, :source, :product_raw, :product_norm, :version_range,
            :oem, :severity, :cvss_score, :description, :mitigation,
            :advisory_url, :published_date, :fetched_at
        )
    """
    cve.setdefault("fetched_at", _now_iso())
    cve.setdefault("severity", "UNKNOWN")

    with get_connection(db_path) as conn:
        cur = conn.execute(sql, cve)
        inserted = cur.rowcount > 0

    if inserted:
        logger.debug("Inserted CVE %s from %s", cve.get("cve_id"), cve.get("source"))
    return inserted


def insert_cves_bulk(cves: list[dict], db_path: str = DB_PATH) -> int:
    """
    Bulk insert a list of CVE dicts. Returns number of new rows inserted.
    Much faster than calling insert_cve() in a loop for large batches.
    """
    if not cves:
        return 0

    sql = """
        INSERT OR IGNORE INTO cves (
            cve_id, source, product_raw, product_norm, version_range,
            oem, severity, cvss_score, description, mitigation,
            advisory_url, published_date, fetched_at
        ) VALUES (
            :cve_id, :source, :product_raw, :product_norm, :version_range,
            :oem, :severity, :cvss_score, :description, :mitigation,
            :advisory_url, :published_date, :fetched_at
        )
    """
    now = _now_iso()
    for c in cves:
        c.setdefault("fetched_at", now)
        c.setdefault("severity", "UNKNOWN")

    with get_connection(db_path) as conn:
        conn.executemany(sql, cves)
        # rowcount after executemany = total rows affected
        count = conn.execute(
            "SELECT changes()"
        ).fetchone()[0]

    logger.info("Bulk inserted %d new CVEs (batch size: %d)", count, len(cves))
    return count


def get_cves_by_product(product_norm: str, db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return all CVE rows matching a normalised product name."""
    sql = "SELECT * FROM cves WHERE product_norm = ? ORDER BY published_date DESC"
    with get_connection(db_path) as conn:
        return conn.execute(sql, (product_norm,)).fetchall()


def get_recent_cves(hours: int = 24, db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return CVEs fetched within the last `hours` hours."""
    sql = """
        SELECT * FROM cves
        WHERE fetched_at >= datetime('now', ?)
        ORDER BY fetched_at DESC
    """
    with get_connection(db_path) as conn:
        return conn.execute(sql, (f"-{hours} hours",)).fetchall()


def get_critical_cves(db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return all CRITICAL and HIGH severity CVEs."""
    sql = """
        SELECT * FROM cves
        WHERE severity IN ('CRITICAL', 'HIGH')
        ORDER BY cvss_score DESC, published_date DESC
    """
    with get_connection(db_path) as conn:
        return conn.execute(sql).fetchall()


# ══════════════════════════════════════════════════════════════════════════════
#  Asset operations
# ══════════════════════════════════════════════════════════════════════════════

def upsert_asset(asset: dict, db_path: str = DB_PATH) -> bool:
    """
    Insert a new asset or update last_seen if it already exists.

    Expected keys:
        ip, port, protocol, service, banner, product_norm, version,
        org, asn, hostname

    Returns True if new asset, False if existing (last_seen updated).
    """
    now = _now_iso()

    insert_sql = """
        INSERT INTO assets (
            ip, port, protocol, service, banner,
            product_norm, version, org, asn, hostname,
            discovered_at, last_seen
        ) VALUES (
            :ip, :port, :protocol, :service, :banner,
            :product_norm, :version, :org, :asn, :hostname,
            :discovered_at, :last_seen
        )
        ON CONFLICT(ip, port, protocol) DO UPDATE SET
            service      = excluded.service,
            banner       = excluded.banner,
            product_norm = excluded.product_norm,
            version      = excluded.version,
            last_seen    = excluded.last_seen
    """
    asset.setdefault("discovered_at", now)
    asset["last_seen"] = now

    with get_connection(db_path) as conn:
        cur = conn.execute(insert_sql, asset)
        is_new = cur.rowcount > 0 and conn.execute(
            "SELECT changes()"
        ).fetchone()[0] == 1

    logger.debug("Upserted asset %s:%s", asset.get("ip"), asset.get("port"))
    return is_new


def get_assets_by_product(product_norm: str, db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return all asset rows running a specific normalised product."""
    sql = "SELECT * FROM assets WHERE product_norm = ? ORDER BY org, ip"
    with get_connection(db_path) as conn:
        return conn.execute(sql, (product_norm,)).fetchall()


def get_assets_by_org(org: str, db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return all assets belonging to an organisation (e.g. 'BSNL')."""
    sql = "SELECT * FROM assets WHERE org = ? ORDER BY ip, port"
    with get_connection(db_path) as conn:
        return conn.execute(sql, (org,)).fetchall()


def get_all_assets(db_path: str = DB_PATH) -> list[sqlite3.Row]:
    """Return every asset row. Used by the matcher to iterate over the estate."""
    sql = "SELECT * FROM assets ORDER BY org, ip, port"
    with get_connection(db_path) as conn:
        return conn.execute(sql).fetchall()


# ══════════════════════════════════════════════════════════════════════════════
#  Alert dedup operations
# ══════════════════════════════════════════════════════════════════════════════

def alert_already_sent(cve_id: str, asset_ip: str, db_path: str = DB_PATH) -> bool:
    """Return True if an alert for this (cve_id, asset_ip) pair was already sent."""
    sql = "SELECT 1 FROM alerts_sent WHERE cve_id = ? AND asset_ip = ? LIMIT 1"
    with get_connection(db_path) as conn:
        return conn.execute(sql, (cve_id, asset_ip)).fetchone() is not None


def record_alert_sent(alert: dict, db_path: str = DB_PATH) -> None:
    """
    Record that an alert was dispatched. Silently ignores if already recorded.

    Expected keys: cve_id, asset_ip, asset_port, org, severity, recipient
    """
    sql = """
        INSERT OR IGNORE INTO alerts_sent (
            cve_id, asset_ip, asset_port, org, severity, sent_at, recipient
        ) VALUES (
            :cve_id, :asset_ip, :asset_port, :org, :severity, :sent_at, :recipient
        )
    """
    alert.setdefault("sent_at", _now_iso())
    with get_connection(db_path) as conn:
        conn.execute(sql, alert)
    logger.debug("Recorded alert: %s → %s", alert.get("cve_id"), alert.get("asset_ip"))


# ══════════════════════════════════════════════════════════════════════════════
#  Scraper run log
# ══════════════════════════════════════════════════════════════════════════════

def log_scraper_run(source: str, status: str,
                    cves_fetched: int = 0, error_msg: str = None,
                    db_path: str = DB_PATH) -> None:
    """Log the result of a scraper execution for health monitoring."""
    sql = """
        INSERT INTO scraper_runs (source, status, cves_fetched, error_msg, ran_at)
        VALUES (?, ?, ?, ?, ?)
    """
    with get_connection(db_path) as conn:
        conn.execute(sql, (source, status, cves_fetched, error_msg, _now_iso()))
    logger.info("Scraper run logged: source=%s status=%s fetched=%d",
                source, status, cves_fetched)


def get_last_scraper_run(source: str, db_path: str = DB_PATH) -> sqlite3.Row | None:
    """Return the most recent run record for a given scraper."""
    sql = """
        SELECT * FROM scraper_runs
        WHERE source = ?
        ORDER BY ran_at DESC
        LIMIT 1
    """
    with get_connection(db_path) as conn:
        return conn.execute(sql, (source,)).fetchone()


# ══════════════════════════════════════════════════════════════════════════════
#  Stats / dashboard helpers
# ══════════════════════════════════════════════════════════════════════════════

def get_stats(db_path: str = DB_PATH) -> dict:
    """Return a summary dict useful for logging or a status email."""
    with get_connection(db_path) as conn:
        total_cves   = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        critical     = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'"
        ).fetchone()[0]
        high         = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity='HIGH'"
        ).fetchone()[0]
        total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts_sent").fetchone()[0]

    return {
        "total_cves":   total_cves,
        "critical":     critical,
        "high":         high,
        "total_assets": total_assets,
        "total_alerts": total_alerts,
    }


# ── Self-test (run directly: python -m database.db) ───────────────────────────
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    TEST_DB = "/tmp/test_cve_monitor.db"
    logger.info("=== Running db.py self-test on %s ===", TEST_DB)

    # 1. Init
    init_db(TEST_DB)

    # 2. Insert a CVE
    sample_cve = {
        "cve_id":        "CVE-2024-20399",
        "source":        "cisco",
        "product_raw":   "Cisco IOS XE Software",
        "product_norm":  "cisco_ios_xe",
        "version_range": "< 17.9.4a",
        "oem":           "Cisco",
        "severity":      "CRITICAL",
        "cvss_score":    9.8,
        "description":   "Unauthenticated RCE in Cisco IOS XE Web UI.",
        "mitigation":    "Upgrade to 17.9.4a or disable HTTP server.",
        "advisory_url":  "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-rce",
        "published_date": "2024-10-14",
    }
    assert insert_cve(sample_cve, TEST_DB), "First insert should succeed"
    assert not insert_cve(sample_cve, TEST_DB), "Duplicate insert should be ignored"

    # 3. Insert an asset
    sample_asset = {
        "ip":           "117.239.1.1",
        "port":         443,
        "protocol":     "tcp",
        "service":      "https",
        "banner":       "Cisco IOS XE 17.6.1",
        "product_norm": "cisco_ios_xe",
        "version":      "17.6.1",
        "org":          "BSNL",
        "asn":          "AS9829",
        "hostname":     "router1.bsnl.in",
    }
    upsert_asset(sample_asset, TEST_DB)

    # 4. Alert dedup
    assert not alert_already_sent("CVE-2024-20399", "117.239.1.1", TEST_DB)
    record_alert_sent({
        "cve_id":     "CVE-2024-20399",
        "asset_ip":   "117.239.1.1",
        "asset_port": 443,
        "org":        "BSNL",
        "severity":   "CRITICAL",
        "recipient":  "soc@ntro.gov.in",
    }, TEST_DB)
    assert alert_already_sent("CVE-2024-20399", "117.239.1.1", TEST_DB)

    # 5. Stats
    stats = get_stats(TEST_DB)
    logger.info("Stats: %s", stats)
    assert stats["total_cves"] == 1
    assert stats["total_assets"] == 1
    assert stats["total_alerts"] == 1

    logger.info("=== All tests passed ✓ ===")