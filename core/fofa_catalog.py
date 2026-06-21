"""
core/fofa_catalog.py
--------------------
Single source of truth mapping human product names -> *verified* FOFA tags.

Replaces the two old, divergent, partly-wrong catalogs
(`groq_enricher._FOFA_APP_CATALOG` and `asset_discovery.fofa_query.PRODUCT_FOFA_MAP`).

Every tag here was confirmed against the live FOFA API on this account's plan
(FOFA Personal, no F-points) — see fofa_verify_catalog.py / round2 / round3 and
data/fofa_catalog_verified.json. Tags that returned 820300 ("app does not
exist") or were valid-but-empty (e.g. `FortiOS`=38 hosts) are deliberately
absent: per the precision-first directive, an unmapped product yields "no
verified fingerprint" rather than a wrong/fuzzy guess.

Two query fields are used:
    app="X"      — FOFA's curated fingerprint (exact match). Preferred.
    product="X"  — works on this plan even though `product` can't be RETURNED;
                   used where a product has no app= tag (e.g. Squid, Kubernetes).

Public API:
    lookup(product_name) -> dict | None
        {"field": "app"|"product", "value": "<tag>",
         "in_count": int, "global_count": int}
    server_lookup(product_name) -> str | None      # e.g. IIS/Apache via server=
    catalog_size() -> int
"""

from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "fofa_catalog_verified.json")


def _load_verified() -> dict:
    try:
        with open(_DATA, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("[Catalog] could not load %s: %s", _DATA, e)
        return {}


VERIFIED: dict = _load_verified()



_ALIASES_RAW: dict[str, str] = {
 
    "fortimanager": "FORTINET-FortiManager", "forti manager": "FORTINET-FortiManager",
    "fortiswitch": "FORTINET-FortiSwitch",
    "fortimail": "FORTINET-FortiMail",
    "fortianalyzer": "FORTINET-FortiAnalyzer",
    "fortiweb": "Fortinet-FortiWeb", "forti web": "Fortinet-FortiWeb",
    "fortiadc": "FORTINET-FortiADC",
    "fortinac": "FORTINET-FortiNAC",
    "fortinet ssl vpn": "SSL-VPN", "fortigate ssl vpn": "SSL-VPN",
    "globalprotect": "paloalto-GlobalProtect",
    "palo alto globalprotect": "paloalto-GlobalProtect",
    "pan-os": "Palo-Alto-pan-os", "panos": "Palo-Alto-pan-os",
    "palo alto": "Palo-Alto-pan-os", "palo alto networks": "Palo-Alto-pan-os",
    "ivanti connect secure": "Ivanti-Connect-Secure", "ivanti": "Ivanti-Connect-Secure",
    "pulse connect secure": "Pulse-Connect-Secure", "pulse secure": "Pulse-Connect-Secure",
    "sonicwall": "SonicWall", "sonic wall": "SonicWall",
    "watchguard": "WatchGuard-Firewall",
    "sophos firewall": "Sophos-Firewall", "sophos xg": "Sophos-Firewall", "sophos": "Sophos-Firewall",
    "sophos utm": "Sophos-UTM",
    "citrix gateway": "Citrix-Gateway", "netscaler gateway": "Citrix-Gateway",
    "citrix adc": "Citrix-ADC", "netscaler": "Citrix-ADC",
    "f5 big-ip": "F5-BIGIP", "f5 big ip": "F5-BIGIP", "big-ip": "F5-BIGIP",
    "bigip": "F5-BIGIP", "f5": "F5-BIGIP", "f5 networks": "F5-BIGIP",
    "mikrotik": "MikroTik-RouterOS", "routeros": "MikroTik-RouterOS",
    "pfsense": "pfSense",
    "zyxel usg": "ZYXEL-USG310", "zyxel": "ZYXEL-USG310",
    # ── Cisco ──
    "cisco router": "Cisco-Router",
    "cisco ios xe": "Cisco-IOS-XE", "cisco ios-xe": "Cisco-IOS-XE", "ios xe": "Cisco-IOS-XE",
    "cisco ios": "Cisco-IOS",
    "cisco firepower": "Cisco-Firepower", "firepower": "Cisco-Firepower",
    "cisco ftd": "Cisco-Firepower", "cisco ise": "Cisco-ISE",
    "nginx": "nginx", "openresty": "OpenResty", "litespeed": "LiteSpeed",
    "jetty": "Jetty",
    "tomcat": "APACHE-Tomcat", "apache tomcat": "APACHE-Tomcat",
    "jboss": "JBoss", "glassfish": "GlassFish",
    "websphere": "IBM-WebSphere", "ibm websphere": "IBM-WebSphere",
    "weblogic": "WebLogic-Server", "oracle weblogic": "WebLogic-Server",
    "exchange": "Microsoft-Exchange", "microsoft exchange": "Microsoft-Exchange", "owa": "Microsoft-Exchange",
    "roundcube": "Roundcube-Webmail",
    "exim": "Exim-Mail-Server", "postfix": "Postfix", "dovecot": "Dovecot",
    "mailenable": "MailEnable", "zimbra": "Zimbra-Collaboration-Suite",
    "mysql": "MySQL", "postgresql": "PostgreSQL", "postgres": "PostgreSQL",
    "mongodb": "MongoDB", "mongo": "MongoDB", "redis": "Redis",
    "elasticsearch": "Elasticsearch", "elastic": "Elasticsearch",
    "mssql": "Microsoft-SQL-Server", "sql server": "Microsoft-SQL-Server",
    "microsoft sql server": "Microsoft-SQL-Server",
    "memcached": "Memcached", "clickhouse": "ClickHouse",
    "influxdb": "InfluxDB", "neo4j": "Neo4j", "phpmyadmin": "phpMyAdmin",
    "wordpress": "WordPress", "drupal": "drupal", "joomla": "Joomla",
    "typo3": "TYPO3", "magento": "Magento", "prestashop": "PrestaShop",
    "opencart": "OpenCart", "moodle": "Moodle", "nextcloud": "Nextcloud",
    "owncloud": "ownCloud", "liferay": "Liferay",
    "confluence": "Atlassian-Confluence", "atlassian confluence": "Atlassian-Confluence",
    "jira": "Atlassian-Jira", "atlassian jira": "Atlassian-Jira",
    "sharepoint": "Microsoft-SharePoint", "microsoft sharepoint": "Microsoft-SharePoint",
    "coldfusion": "Adobe-ColdFusion", "adobe coldfusion": "Adobe-ColdFusion",
    "ghost": "Ghost", "erpnext": "ERPNext", "kentico": "Kentico-CMS",
    "thinkphp": "ThinkPHP", "ofbiz": "Apache_OFBiz", "apache ofbiz": "Apache_OFBiz",
    "activemq": "APACHE-ActiveMQ", "sugarcrm": "sugarcrm", "geoserver": "geoserver",
    "strapi": "strapi-Headless-CMS",
    "esxi": "VMware-ESXi", "vmware esxi": "VMware-ESXi",
    "vcenter": "VMware-vCenter", "vmware vcenter": "VMware-vCenter",
    "vmware horizon": "VMware-Horizon", "horizon": "VMware-Horizon",
    "proxmox": "Proxmox-VE",
    "gitlab": "GitLab", "gitea": "Gitea", "jenkins": "Jenkins",
    "portainer": "Portainer", "grafana": "Grafana", "kibana": "Kibana",
    "webmin": "Webmin", "usermin": "Usermin", "virtualmin": "Virtualmin",
    "kubernetes": "Kubernetes", "k8s": "Kubernetes",
    "plesk": "plesk-Obsidian", "cyberpanel": "CyberPanel",
    "rdp": "RDP", "remote desktop": "RDP", "vnc": "VNC",
    "openssh": "OpenSSH", "ssh": "OpenSSH", "openvpn": "OpenVPN",
    "teamviewer": "TeamViewer", "squid": "Squid", "haproxy": "HAProxy",
    "proftpd": "ProFTPD", "vsftpd": "vsftpd",
    "nagios": "nagios-xi", "observium": "Observium", "wazuh": "Wazuh",
    "siemens": "Siemens-SIMATIC", "simatic": "Siemens-SIMATIC",
    "modbus": "Modbus", "bacnet": "BACnet",
    "rockwell": "Rockwell-Automation", "allen bradley": "Rockwell-Automation",
    "ollama": "Ollama", "mlflow": "mlflow", "open webui": "Open-WebUI",
    "litellm": "LiteLLM-API", "chroma": "Chroma-ChromaDB", "chromadb": "Chroma-ChromaDB",
    "dify": "Dify", "librechat": "LibreChat", "langflow": "LOGSPACE-LangFlow",
    "windows": "Windows", "next.js": "Next.js", "nextjs": "Next.js",
    "node.js": "Node.js", "nodejs": "Node.js", "django": "Django",
    "astro": "Astro", "freepbx": "FreePBX", "servicenow": "servicenow-Products",
    "netgear": "NETGEAR", "brother printer": "brother-Printer", "traccar": "Traccar",
}

# ── Multi-field precise detections ───────────────────────────────────────────
# For products with NO usable app= tag, or where an exact title=/body=/server=
# string is the precise signal (mostly sourced from nuclei-templates' own
# fofa-query metadata — community-vetted, so exact-match = low false positives).
# Every clause was verified live with Indian presence. Checked BEFORE the app=
# alias table, but global longest-key matching means a more specific alias
# (e.g. "apache tomcat") still wins over a short detection key (e.g. "apache").
_DETECTIONS: dict[str, dict] = {
    "check point":        {"clause": 'body="check point ssl network"', "in": 492},
    "checkpoint":         {"clause": 'body="check point ssl network"', "in": 492},
    "manageengine":       {"clause": 'title="ManageEngine"', "in": 1181},
    "zoho manageengine":  {"clause": 'title="ManageEngine"', "in": 1181},
    "juniper":            {"clause": 'title="Juniper Web Device Manager"', "in": 1338},
    "juniper srx":        {"clause": 'title="Juniper Web Device Manager"', "in": 1338},
    "fortigate":          {"clause": 'body="/remote/login"', "in": 5368},
    "fortios":            {"clause": 'body="/remote/login"', "in": 5368},
    "fortinet":           {"clause": 'body="/remote/login"', "in": 5368},
    "cisco asa":          {"clause": 'body="/+CSCOE+/"', "in": 3856},
    "zimbra":             {"clause": 'title="Zimbra"', "in": 7757},
    "panorama":           {"clause": 'title="Panorama"', "in": 96},
    "palo alto panorama": {"clause": 'title="Panorama"', "in": 96},
    "iis":                {"clause": 'server*="Microsoft-IIS"'},
    "microsoft iis":      {"clause": 'server*="Microsoft-IIS"'},
    "apache http server": {"clause": 'server*="Apache"', "in": 2595607},
    "apache httpd":       {"clause": 'server*="Apache"', "in": 2595607},
    "httpd":              {"clause": 'server*="Apache"', "in": 2595607},
    "apache":             {"clause": 'server*="Apache"', "in": 2595607},
}

_PRODUCT_STOPWORDS = {
    "software", "hardware", "system", "platform", "application", "server",
    "client", "service", "appliance", "device", "n/a", "unknown", "various",
    "multiple",
}


def _validate_aliases() -> dict[str, str]:
    """Keep only aliases whose target tag is actually in the verified table."""
    good, dropped = {}, []
    for alias, tag in _ALIASES_RAW.items():
        if tag in VERIFIED:
            good[alias] = tag
        else:
            dropped.append((alias, tag))
    if dropped:
        logger.warning("[Catalog] %d aliases dropped (tag not verified): %s",
                       len(dropped), ", ".join(f"{a}->{t}" for a, t in dropped[:10]))
    return good


ALIASES: dict[str, str] = _validate_aliases()


def _norm_key(s: str) -> str:
    """Lowercase, turn hyphens/underscores into spaces (so 'Cisco-ASA' matches
    the 'cisco asa' key), collapse whitespace. Dots are kept (next.js, node.js)."""
    s = re.sub(r"[-_]+", " ", (s or "").lower())
    return re.sub(r"\s+", " ", s).strip()



_LOOKUP_KEYS: list[tuple[str, str, str]] = sorted(
    [(_norm_key(k), k, "det") for k in _DETECTIONS]
    + [(_norm_key(k), k, "alias") for k in ALIASES],
    key=lambda t: len(t[0]), reverse=True,
)


def _normalize(product: str) -> str:
    p = _norm_key(product)
    p = re.sub(r"\s+v?\d[\d.()a-z]*$", "", p).strip()
    return p


@lru_cache(maxsize=2048)
def lookup(product: str) -> Optional[dict]:
  
    p = _normalize(product)
    if not p or p in _PRODUCT_STOPWORDS:
        return None
    for nkey, okey, src in _LOOKUP_KEYS:
        if p == nkey or p.startswith(nkey + " ") or nkey in p:
            if src == "det":
                det = _DETECTIONS[okey]
                return {"clause": det["clause"], "in_count": det.get("in"),
                        "global_count": det.get("global"), "kind": "detection"}
            tag = ALIASES[okey]
            meta = VERIFIED.get(tag, {})
            field = meta.get("field", "app")
            return {"clause": f'{field}="{tag}"', "in_count": meta.get("in"),
                    "global_count": meta.get("global"), "kind": field}
    return None


def catalog_size() -> int:
    return len(VERIFIED)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"verified tags: {catalog_size()}   aliases: {len(ALIASES)}   detections: {len(_DETECTIONS)}")
    for t in ["FortiManager", "palo alto globalprotect", "fortigate", "nginx",
              "Microsoft Exchange", "f5 big-ip", "weblogic", "Cisco IOS XE",
              "Microsoft IIS", "apache http server", "apache tomcat",
              "Check Point", "ManageEngine", "Cisco ASA", "Zimbra", "Juniper SRX",
              "some random product"]:
        r = lookup(t)
        print(f"  {t:26s} -> {r['clause'] if r else '(no verified fingerprint)':40s}"
              + (f"  IN={r['in_count']}" if r and r.get('in_count') is not None else ""))
