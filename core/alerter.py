"""
Email alerting module for the NTRO CVE Monitoring System.

Takes match dicts from matcher.py and sends structured plain-text
email alerts via Gmail SMTP. Handles dedup, batching, and retries.

Alert format:
    - One email per severity group (CRITICAL, HIGH, MEDIUM)
    - Each email contains all new matches of that severity
    - Dedup guaranteed via alerts_sent table in DB

Usage:
    from core.alerter import send_alerts
    from core.matcher import run_matcher
    matches = run_matcher()
    send_alerts(matches)
"""

import logging
import smtplib
import socket
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from database.db import record_alert_sent, DB_PATH

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

SEVERITY_MARKER = {
    "CRITICAL": "[!!!] CRITICAL",
    "HIGH":     "[!!]  HIGH",
    "MEDIUM":   "[!]   MEDIUM",
    "LOW":      "[ ]   LOW",
    "UNKNOWN":  "[?]   UNKNOWN",
}


def _get_smtp_config() -> dict:
    """Load SMTP config from config.py."""
    try:
        from config import (
            SMTP_SENDER, SMTP_PASSWORD,
            SMTP_RECEIVER, SMTP_HOST, SMTP_PORT
        )
        return {
            "sender":   SMTP_SENDER,
            "password": SMTP_PASSWORD,
            "receiver": SMTP_RECEIVER,
            "host":     SMTP_HOST,
            "port":     SMTP_PORT,
        }
    except ImportError as e:
        logger.error("Missing SMTP config in config.py: %s", e)
        return {}


def _send_email(
    subject:  str,
    body:     str,
    cfg:      dict,
    retries:  int = 3,
) -> bool:
    """
    Send a plain-text email via Gmail SMTP with TLS.
    Returns True on success, False on failure.
    """
    msg = MIMEMultipart()
    msg["From"]    = f"NTRO CVE Monitor <{cfg['sender']}>"
    msg["To"]      = cfg["receiver"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    for attempt in range(1, retries + 1):
        try:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(cfg["sender"], cfg["password"])
                server.sendmail(cfg["sender"], cfg["receiver"], msg.as_string())
            logger.info("Email sent: %s", subject)
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP auth failed — check SMTP_PASSWORD in config.py")
            return False   # no point retrying auth errors

        except (smtplib.SMTPException, socket.error) as e:
            logger.warning("SMTP error (attempt %d/%d): %s", attempt, retries, e)
            if attempt == retries:
                logger.error("Failed to send email after %d attempts: %s", retries, subject)
                return False

    return False


def _build_email_body(matches: list[dict], severity: str) -> str:
    """
    Build a clean plain-text email body for a group of matches.
    """
    now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    marker  = SEVERITY_MARKER.get(severity, severity)
    count   = len(matches)

    lines = [
        "=" * 65,
        f"  NTRO CVE ALERT — {marker}",
        f"  Generated: {now}",
        f"  Total Affected Assets: {count}",
        "=" * 65,
        "",
        "This is an automated alert from the NTRO CVE Monitoring System.",
        "The following vulnerabilities have been matched to assets in",
        "Indian Critical Sector Organisation infrastructure.",
        "",
    ]

    for i, m in enumerate(matches, 1):
        lines += [
            f"─" * 65,
            f"  ALERT #{i}",
            f"─" * 65,
            f"  CVE ID       : {m['cve_id']}",
            f"  Severity     : {m['severity']}" +
                (f" (CVSS: {m['cvss_score']})" if m.get('cvss_score') else ""),
            f"  Source       : {m['source'].upper()}",
            f"  Published    : {m['published_date']}",
            "",
            f"  AFFECTED ASSET",
            f"  Organisation : {m['org']} ({m['asn']})",
            f"  IP Address   : {m['asset_ip']}:{m['asset_port']}",
            f"  Hostname     : {m.get('hostname') or 'N/A'}",
            f"  Product      : {m['product_norm']}",
            f"  Version      : {m.get('asset_version') or 'Unknown'}",
            f"  CVE Range    : {m.get('version_range') or 'All versions'}",
            "",
            f"  VULNERABILITY DETAILS",
            f"  OEM          : {m.get('oem') or 'Unknown'}",
            f"  Description  : {_wrap_text(m.get('description') or 'N/A', 55, '               ')}",
            "",
            f"  MITIGATION",
            f"  {_wrap_text(m.get('mitigation') or 'Refer to vendor advisory.', 60, '  ')}",
            "",
            f"  Match Confidence : {m.get('confidence', 'N/A')}",
            f"  Match Reason     : {m.get('match_reason', 'N/A')}",
            f"  Advisory URL     : {m.get('advisory_url', 'N/A')}",
            "",
        ]

    lines += [
        "=" * 65,
        "  ACTION REQUIRED",
        "=" * 65,
        "",
        "  1. Review each CVE against the affected asset.",
        "  2. Apply patches or mitigations as indicated.",
        "  3. Verify remediation and update asset inventory.",
        "  4. Escalate CRITICAL findings immediately.",
        "",
        "─" * 65,
        "  NTRO CVE Monitoring System",
        "  National Technical Research Organisation",
        "  Government of India",
        "  [Automated Alert]",
        "─" * 65,
    ]

    return "\n".join(lines)


def _wrap_text(text: str, width: int, indent: str) -> str:
    """Wrap long text at word boundaries with indent for continuation lines."""
    if not text or len(text) <= width:
        return text
    words   = text.split()
    lines   = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = (current + " " + word).strip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return ("\n" + indent).join(lines)


def _build_subject(matches: list[dict], severity: str) -> str:
    """Build email subject line."""
    orgs  = list(set(m["org"] for m in matches))
    org_str = ", ".join(orgs[:3])
    if len(orgs) > 3:
        org_str += f" +{len(orgs)-3} more"
    return (
        f"[NTRO CVE ALERT] {severity} — "
        f"{len(matches)} vuln(s) affecting {org_str}"
    )


def send_alerts(
    matches:    list[dict],
    db_path:    str  = DB_PATH,
    dry_run:    bool = False,
    min_severity: Optional[str] = None,
) -> dict:
  
    if not matches:
        logger.info("No matches to alert on.")
        return {"sent": 0, "failed": 0, "skipped": 0, "total": 0}

    cfg = _get_smtp_config()
    if not cfg and not dry_run:
        logger.error("No SMTP config — cannot send alerts.")
        return {"sent": 0, "failed": len(matches), "skipped": 0, "total": len(matches)}

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if min_severity:
        min_rank = severity_rank.get(min_severity, 999)
        matches  = [m for m in matches if severity_rank.get(m["severity"], 999) <= min_rank]

    if not matches:
        logger.info("No matches above minimum severity threshold.")
        return {"sent": 0, "failed": 0, "skipped": len(matches), "total": len(matches)}

    grouped: dict[str, list] = {}
    for m in matches:
        grouped.setdefault(m["severity"], []).append(m)

    stats = {"sent": 0, "failed": 0, "skipped": 0, "total": len(matches)}

    for severity in SEVERITY_ORDER:
        if severity not in grouped:
            continue

        group   = grouped[severity]
        subject = _build_subject(group, severity)
        body    = _build_email_body(group, severity)

        if dry_run:
            print("\n" + "=" * 65)
            print(f"DRY RUN — would send email:")
            print(f"Subject : {subject}")
            print(f"To      : {cfg.get('receiver', 'N/A')}")
            print(f"Body preview (first 500 chars):")
            print(body[:500])
            print("=" * 65)
            stats["sent"] += len(group)
            continue

        success = _send_email(subject, body, cfg)

        if success:
            stats["sent"] += len(group)
            for m in group:
                try:
                    record_alert_sent({
                        "cve_id":     m["cve_id"],
                        "asset_ip":   m["asset_ip"],
                        "asset_port": m["asset_port"],
                        "org":        m["org"],
                        "severity":   m["severity"],
                        "recipient":  cfg["receiver"],
                    }, db_path)
                except Exception:
                    pass  # already recorded by matcher, this is just updating recipient
        else:
            stats["failed"] += len(group)
            logger.error(
                "Failed to send %s alert email (%d matches)",
                severity, len(group)
            )

    logger.info(
        "Alert dispatch complete — sent: %d, failed: %d, skipped: %d",
        stats["sent"], stats["failed"], stats["skipped"]
    )
    return stats


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 65)
    print("  alerter.py  —  NTRO CVE Alerter Self-Test")
    print("=" * 65)

    print("\n[Test 1] Dry run with dummy CRITICAL match...")
    dummy_matches = [
        {
            "cve_id":         "CVE-2026-20399",
            "asset_ip":       "117.239.1.1",
            "asset_port":     443,
            "org":            "BSNL",
            "asn":            "AS9829",
            "hostname":       "router1.bsnl.in",
            "product_norm":   "cisco_ios_xe",
            "asset_version":  "17.6.1",
            "version_range":  "< 17.9.4a",
            "severity":       "CRITICAL",
            "cvss_score":     9.8,
            "oem":            "Cisco",
            "description":    (
                "Unauthenticated remote code execution in Cisco IOS XE "
                "Web UI. An attacker can execute arbitrary commands with "
                "root privileges without authentication."
            ),
            "mitigation":     "Upgrade to Cisco IOS XE 17.9.4a or later. "
                              "Disable HTTP server if not required: "
                              "'no ip http server' and 'no ip http secure-server'.",
            "advisory_url":   "https://sec.cloudapps.cisco.com/security/center/"
                              "content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-rce",
            "published_date": "2026-03-19",
            "confidence":     "HIGH",
            "match_reason":   "Exact product match: cisco_ios_xe",
            "matched_at":     datetime.now(timezone.utc).isoformat(),
            "source":         "nvd",
        }
    ]

    send_alerts(dummy_matches, dry_run=True)

    print("\n[Test 2] Send real email to yourself...")
    answer = input("Send a real test email? (y/n): ").strip().lower()
    if answer == "y":
        stats = send_alerts(dummy_matches, dry_run=False)
        print(f"\nResult: {stats}")
        if stats["sent"] > 0:
            print("[+] Email sent! Check your inbox.")
        else:
            print("[!] Send failed. Check SMTP config in config.py.")
    else:
        print("Skipped real send.")

    print("\n[Test 3] Full pipeline — matcher → alerter (dry run)...")
    try:
        from core.matcher import run_matcher
        matches = run_matcher(hours_back=720, include_all=True, dry_run=True)
        print(f"  Matcher found {len(matches)} new matches")
        if matches:
            # Send dry run alerts
            stats = send_alerts(matches[:5], dry_run=True)
            print(f"  Alert stats: {stats}")
    except Exception as e:
        print(f"  Pipeline test failed: {e}")

    print("\n" + "=" * 65)
    print("  alerter.py self-test complete")
    print("=" * 65)