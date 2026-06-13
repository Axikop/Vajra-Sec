"""
asset_discovery/crtsh.py
------------------------
Passive subdomain enumeration for target organisations via
crt.sh — a public certificate transparency log search engine.

Certificate transparency logs record every SSL/TLS certificate
ever issued. This means every subdomain that has ever had HTTPS
is publicly listed. No scanning, no probing — purely passive.

What this does:
    1. Query crt.sh for all certificates issued to *.bsnl.in
    2. Extract unique subdomains
    3. Resolve each subdomain to IP via DNS
    4. Filter IPs that belong to target ASN (AS9829 for BSNL)
    5. Return asset dicts ready for db.upsert_asset()

Usage:
    from asset_discovery.crtsh import run_crtsh
    assets = run_crtsh(domain="bsnl.in", asn="AS9829", org="BSNL")
"""

import logging
import re
import socket
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

CRTSH_URL       = "https://crt.sh/?q={domain}&output=json"
IPINFO_URL      = "https://ipinfo.io/{ip}/json"
REQUEST_TIMEOUT = 30
DNS_TIMEOUT     = 5
REQUEST_DELAY   = 0.5

_SKIP_PATTERNS = [
    r'^\*\.',           # wildcards
    r'^www\.',          # generic www
    r'\.cdn\.',         # CDN nodes
    r'mail\.',          # mail servers
    r'smtp\.',
    r'pop\.',
    r'imap\.',
]

_DEFAULT_PORT = 443


def _query_crtsh(domain: str) -> list[str]:
    """
    Query crt.sh for all subdomains of a domain.
    Returns list of unique subdomain strings.
    """
    url = CRTSH_URL.format(domain=f"%.{domain}")
    logger.info("[crtsh] Querying crt.sh for *.%s", domain)

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.error("[crtsh] crt.sh request failed: %s", e)
        return []
    except ValueError:
        logger.error("[crtsh] crt.sh returned invalid JSON")
        return []

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and domain in name:
                subdomains.add(name)

    logger.info("[crtsh] Found %d raw subdomains", len(subdomains))
    return list(subdomains)


def _filter_subdomains(subdomains: list[str]) -> list[str]:
    """Remove wildcards, generic subdomains, and duplicates."""
    filtered = []
    for sub in subdomains:
        skip = False
        for pattern in _SKIP_PATTERNS:
            if re.search(pattern, sub):
                skip = True
                break
        if not skip:
            filtered.append(sub)

    # Deduplicate
    filtered = list(set(filtered))
    logger.info("[crtsh] %d subdomains after filtering", len(filtered))
    return filtered


def _resolve_dns(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address. Returns None if resolution fails."""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.timeout):
        return None


_BSNL_PREFIXES = [
    "61.0.", "61.1.", "61.2.", "61.3.",
    "117.239.", "117.240.", "117.241.",
    "210.212.", "218.248.", "218.249.",
    "59.163.", "115.112.", "122.166.",
    "124.124.", "125.16.", "125.17.",
    "136.232.", "152.57.", "182.71.",
    "192.168.122.",  # internal — skip
]

def _is_bsnl_ip(ip: str) -> bool:
    """Check if IP belongs to BSNL AS9829 using known prefixes."""
    return any(ip.startswith(p) for p in _BSNL_PREFIXES)

def _get_ip_info(ip: str) -> dict:
    """Return ASN info using local prefix lookup — no API needed."""
    if _is_bsnl_ip(ip):
        return {"asn": "AS9829", "org": "BSNL-NIB", "country": "IN", "city": ""}
    return {"asn": "", "org": "", "country": "", "city": ""}


def _infer_port_service(hostname: str) -> tuple[int, str, str]:
    """
    Infer likely port and service from hostname.
    Returns (port, protocol, service).
    """
    h = hostname.lower()
    if any(x in h for x in ["mail", "smtp", "pop", "imap", "mx"]):
        return 25, "tcp", "smtp"
    if any(x in h for x in ["ftp"]):
        return 21, "tcp", "ftp"
    if any(x in h for x in ["ssh", "bastion", "jump"]):
        return 22, "tcp", "ssh"
    if any(x in h for x in ["rdp"]):
        return 3389, "tcp", "rdp"
    if any(x in h for x in ["dns", "ns1", "ns2", "ns3"]):
        return 53, "udp", "dns"
    if any(x in h for x in ["http", "web", "www", "portal", "app"]):
        return 80, "tcp", "http"
    # Default — HTTPS
    return 443, "tcp", "https"


def run_crtsh(
    domain:     str  = "bsnl.in",
    asn:        str  = "AS9829",
    org:        str  = "BSNL",
    filter_asn: bool = True,
    max_hosts:  int  = 500,
) -> list[dict]:
    """
    Enumerate BSNL subdomains via crt.sh and resolve to IPs.

    Args:
        domain:     Root domain to search (e.g. 'bsnl.in')
        asn:        Target ASN to filter results (e.g. 'AS9829')
        org:        Organisation name for DB records
        filter_asn: If True, only return IPs belonging to target ASN
        max_hosts:  Safety cap on number of hosts to process

    Returns:
        List of asset dicts ready for db.upsert_asset()
    """
    logger.info("[crtsh] Starting subdomain enumeration for %s (ASN: %s)", domain, asn)

    # Step 1 — Query crt.sh
    raw_subdomains = _query_crtsh(domain)
    if not raw_subdomains:
        logger.warning("[crtsh] No subdomains found for %s", domain)
        return []

    # Step 2 — Filter
    subdomains = _filter_subdomains(raw_subdomains)
    subdomains = subdomains[:max_hosts]

    # Step 3 — Resolve + filter by ASN
    assets      = []
    resolved    = 0
    filtered    = 0
    failed_dns  = 0

    logger.info("[crtsh] Resolving %d subdomains...", len(subdomains))

    for i, hostname in enumerate(subdomains):
        if i % 50 == 0 and i > 0:
            logger.info("[crtsh] Progress: %d/%d resolved", i, len(subdomains))

        # DNS resolution
        ip = _resolve_dns(hostname)
        if not ip:
            failed_dns += 1
            continue

        resolved += 1

        # ASN check
        if filter_asn:
            ip_info = _get_ip_info(ip)
            time.sleep(0.2)  

            if asn and not _is_bsnl_ip(ip):
                filtered += 1
                logger.debug(
                    "[crtsh] %s (%s) → ASN %s — not %s, skipping",
                    hostname, ip, ip_info.get("asn"), asn
                )
                continue

            record_asn = ip_info.get("asn", asn)
            record_org = ip_info.get("org", org)
        else:
            record_asn = asn
            record_org = org

        # Infer port/service
        port, protocol, service = _infer_port_service(hostname)

        asset = {
            "ip":           ip,
            "port":         port,
            "protocol":     protocol,
            "service":      service,
            "banner":       None,
            "product_norm": None,   # nmap_finger.py fills this in
            "version":      None,   # nmap_finger.py fills this in
            "org":          record_org or org,
            "asn":          record_asn or asn,
            "hostname":     hostname,
        }
        assets.append(asset)

        logger.debug("[crtsh] ✓ %s → %s:%d (%s)", hostname, ip, port, service)
        time.sleep(REQUEST_DELAY)

    logger.info(
        "[crtsh] Done — resolved: %d, ASN-filtered: %d, DNS-failed: %d, assets: %d",
        resolved, filtered, failed_dns, len(assets)
    )
    return assets


def clean_for_db(assets: list[dict]) -> list[dict]:
    """Assets are already in DB format — pass-through."""
    return assets


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("  crtsh.py  —  BSNL Subdomain Enumeration Self-Test")
    print("=" * 60)

    # Run with filter_asn=False first to see all resolved subdomains
    # then set filter_asn=True to only keep BSNL IPs
    assets = run_crtsh(
        domain     = "bsnl.in",
        asn        = "AS9829",
        org        = "BSNL",
        filter_asn = True,
        max_hosts  = 100,
    )

    if not assets:
        print("[!] No assets found — trying without ASN filter...")
        assets = run_crtsh(
            domain     = "bsnl.in",
            asn        = "AS9829",
            org        = "BSNL",
            filter_asn = False,
            max_hosts  = 20,
        )

    print(f"\n[+] Found {len(assets)} BSNL assets\n")
    for a in assets[:10]:
        print(f"  {a['hostname']:<45} {a['ip']:<18} {a['service']:<8} {a['asn']}")

    print()
    print("=" * 60)
    print(f"  Total assets ready for DB: {len(assets)}")
    print("=" * 60)

    # Ask if user wants to insert into DB
    if assets:
        ans = input("\nInsert into DB? (y/n): ").strip().lower()
        if ans == "y":
            import sys
            sys.path.insert(0, "..")
            from database.db import upsert_asset
            inserted = 0
            for a in assets:
                if upsert_asset(a):
                    inserted += 1
            print(f"Inserted {inserted}/{len(assets)} assets into DB")