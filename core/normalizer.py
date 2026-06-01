"""
core/normalizer.py
------------------
Product name & version normalisation engine for the NTRO CVE Monitoring System.

Responsibilities:
    1. Normalise raw product strings from OEM advisories / NVD into a
       canonical key  (e.g. "Cisco IOS XE 17.6" → "cisco_ios_xe")
    2. Parse raw version strings into comparable (major, minor, patch, build)
       tuples
    3. Decide whether a discovered asset version falls within a CVE's
       affected version range string (e.g. "< 17.9.4a", "15.0 - 15.4.3")


Usage:
    from core.normalizer import normalize_product, parse_version, is_version_affected
"""

import re
import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)




PRODUCT_ALIASES: dict[str, str] = {

    "cisco ios xe":                     "cisco_ios_xe",
    "ios xe":                           "cisco_ios_xe",
    "iosxe":                            "cisco_ios_xe",
    "cisco ios xe software":            "cisco_ios_xe",
    "cisco ios":                        "cisco_ios",
    "ios":                              "cisco_ios",
    "cisco ios software":               "cisco_ios",
    "cisco nx-os":                      "cisco_nxos",
    "nx-os":                            "cisco_nxos",
    "nxos":                             "cisco_nxos",
    "cisco nx-os software":             "cisco_nxos",
    "cisco asa":                        "cisco_asa",
    "cisco adaptive security appliance":"cisco_asa",
    "asa software":                     "cisco_asa",
    "cisco firepower":                  "cisco_firepower",
    "cisco fmc":                        "cisco_firepower",
    "firepower management center":      "cisco_firepower",
    "cisco ftd":                        "cisco_ftd",
    "firepower threat defense":         "cisco_ftd",
    "cisco anyconnect":                 "cisco_anyconnect",
    "anyconnect secure mobility client":"cisco_anyconnect",
    "cisco webex":                      "cisco_webex",
    "webex meetings":                   "cisco_webex",
    "cisco ise":                        "cisco_ise",
    "cisco identity services engine":   "cisco_ise",
    "cisco prime":                      "cisco_prime",
    "cisco aironet":                    "cisco_aironet",
    "cisco catalyst":                   "cisco_catalyst_switch",
    "cisco small business":             "cisco_small_business",
    "cisco rv series":                  "cisco_rv_router",
    "cisco umbrella":                   "cisco_umbrella",
    "cisco sd-wan":                     "cisco_sdwan",
    "cisco vmanage":                    "cisco_sdwan",

    "windows 10":                       "microsoft_windows_10",
    "microsoft windows 10":             "microsoft_windows_10",
    "windows 11":                       "microsoft_windows_11",
    "microsoft windows 11":             "microsoft_windows_11",
    "windows server 2019":              "microsoft_windows_server_2019",
    "microsoft windows server 2019":    "microsoft_windows_server_2019",
    "windows server 2022":              "microsoft_windows_server_2022",
    "microsoft windows server 2022":    "microsoft_windows_server_2022",
    "windows server 2016":              "microsoft_windows_server_2016",
    "microsoft windows server 2016":    "microsoft_windows_server_2016",
    "windows server 2012":              "microsoft_windows_server_2012",
    "microsoft windows server 2012 r2": "microsoft_windows_server_2012",
    "exchange server":                  "microsoft_exchange",
    "microsoft exchange":               "microsoft_exchange",
    "microsoft exchange server":        "microsoft_exchange",
    "sharepoint":                       "microsoft_sharepoint",
    "microsoft sharepoint":             "microsoft_sharepoint",
    "microsoft sharepoint server":      "microsoft_sharepoint",
    "azure":                            "microsoft_azure",
    "microsoft azure":                  "microsoft_azure",
    "azure active directory":           "microsoft_azure_ad",
    "active directory":                 "microsoft_active_directory",
    "microsoft active directory":       "microsoft_active_directory",
    "iis":                              "microsoft_iis",
    "internet information services":    "microsoft_iis",
    "microsoft iis":                    "microsoft_iis",
    ".net framework":                   "microsoft_dotnet",
    "microsoft .net":                   "microsoft_dotnet",
    "microsoft office":                 "microsoft_office",
    "office 365":                       "microsoft_office_365",
    "microsoft 365":                    "microsoft_office_365",
    "microsoft teams":                  "microsoft_teams",
    "microsoft edge":                   "microsoft_edge",
    "edge":                             "microsoft_edge",
    "skype for business":               "microsoft_skype_business",
    "sql server":                       "microsoft_sql_server",
    "microsoft sql server":             "microsoft_sql_server",
    "power bi":                         "microsoft_power_bi",
    "rdp":                              "microsoft_rdp",
    "remote desktop":                   "microsoft_rdp",
    "hyper-v":                          "microsoft_hyperv",
    "defender":                         "microsoft_defender",
    "microsoft defender":               "microsoft_defender",
    "microsoft windows 10":             "microsoft_windows_10",
    "microsoft windows 11":             "microsoft_windows_11",
    "microsoft windows server 2019":    "microsoft_windows_server_2019",
    "microsoft windows server 2022":    "microsoft_windows_server_2022",
    "microsoft windows server 2016":    "microsoft_windows_server_2016",
    "windows 10":                       "microsoft_windows_10",
    "windows 11":                       "microsoft_windows_11",
    "fortios":                          "fortinet_fortios",
    "fortigate":                        "fortinet_fortios",
    "fortinet fortios":                 "fortinet_fortios",
    "fortinet fortigate":               "fortinet_fortios",
    "fortimanager":                     "fortinet_fortimanager",
    "fortinet fortimanager":            "fortinet_fortimanager",
    "fortianalyzer":                    "fortinet_fortianalyzer",
    "fortinet fortianalyzer":           "fortinet_fortianalyzer",
    "fortiweb":                         "fortinet_fortiweb",
    "fortinet fortiweb":                "fortinet_fortiweb",
    "fortiproxy":                       "fortinet_fortiproxy",
    "fortinet fortiproxy":              "fortinet_fortiproxy",
    "forticlient":                      "fortinet_forticlient",
    "fortinet forticlient":             "fortinet_forticlient",
    "fortimail":                        "fortinet_fortimail",
    "fortiswitchmanager":               "fortinet_fortiswitch",
    "fortiswitch":                      "fortinet_fortiswitch",
    "fortiadc":                         "fortinet_fortiadc",
    "fortiddos":                        "fortinet_fortiddos",
    "fortisoar":                        "fortinet_fortisoar",
    "fortisiem":                        "fortinet_fortisiem",
    "fortiap":                          "fortinet_fortiap",

    "junos":                            "juniper_junos",
    "juniper junos":                    "juniper_junos",
    "juniper networks junos os":        "juniper_junos",
    "junos os":                         "juniper_junos",
    "juniper srx":                      "juniper_srx",
    "srx series":                       "juniper_srx",
    "juniper mx":                       "juniper_mx",
    "mx series":                        "juniper_mx",
    "juniper ex":                       "juniper_ex",
    "ex series":                        "juniper_ex",
    "juniper qfx":                      "juniper_qfx",

    "pan-os":                           "paloalto_panos",
    "palo alto pan-os":                 "paloalto_panos",
    "palo alto networks pan-os":        "paloalto_panos",
    "globalprotect":                    "paloalto_globalprotect",
    "palo alto globalprotect":          "paloalto_globalprotect",
    "panorama":                         "paloalto_panorama",
    "palo alto panorama":               "paloalto_panorama",
    "cortex xdr":                       "paloalto_cortex_xdr",
    "prisma":                           "paloalto_prisma",
    "palo alto prisma":                 "paloalto_prisma",

    "big-ip":                           "f5_bigip",
    "f5 big-ip":                        "f5_bigip",
    "f5 networks big-ip":               "f5_bigip",
    "big-ip apm":                       "f5_bigip_apm",
    "big-ip ltm":                       "f5_bigip_ltm",
    "big-ip asm":                       "f5_bigip_asm",
    "icontrol rest":                    "f5_bigip",
    "f5 nginx":                         "nginx",
    "nginx plus":                       "nginx",
    "nginx":                            "nginx",

    "simatic":                          "siemens_simatic",
    "siemens simatic":                  "siemens_simatic",
    "simatic s7":                       "siemens_simatic_s7",
    "siemens scalance":                 "siemens_scalance",
    "scalance":                         "siemens_scalance",
    "siemens ruggedcom":                "siemens_ruggedcom",
    "ruggedcom":                        "siemens_ruggedcom",
    "simatic wincc":                    "siemens_wincc",
    "wincc":                            "siemens_wincc",
    "tia portal":                       "siemens_tia_portal",

    "vmware esxi":                      "vmware_esxi",
    "esxi":                             "vmware_esxi",
    "vsphere":                          "vmware_vsphere",
    "vmware vsphere":                   "vmware_vsphere",
    "vcenter":                          "vmware_vcenter",
    "vmware vcenter":                   "vmware_vcenter",
    "vmware vcenter server":            "vmware_vcenter",
    "vmware workstation":               "vmware_workstation",
    "vmware fusion":                    "vmware_fusion",
    "vmware nsx":                       "vmware_nsx",
    "vmware aria":                      "vmware_aria",
    "vrealize":                         "vmware_vrealize",

    "apache http server":               "apache_httpd",
    "apache httpd":                     "apache_httpd",
    "apache":                           "apache_httpd",
    "httpd":                            "apache_httpd",
    "apache tomcat":                    "apache_tomcat",
    "tomcat":                           "apache_tomcat",
    "apache struts":                    "apache_struts",
    "struts":                           "apache_struts",
    "apache log4j":                     "apache_log4j",
    "log4j":                            "apache_log4j",
    "apache kafka":                     "apache_kafka",
    "kafka":                            "apache_kafka",
    "apache solr":                      "apache_solr",
    "solr":                             "apache_solr",

    "linux kernel":                     "linux_kernel",
    "kernel":                           "linux_kernel",
    "ubuntu":                           "ubuntu_linux",
    "ubuntu linux":                     "ubuntu_linux",
    "debian":                           "debian_linux",
    "debian linux":                     "debian_linux",
    "red hat enterprise linux":         "rhel",
    "rhel":                             "rhel",
    "centos":                           "centos",
    "centos linux":                     "centos",
    "opensuse":                         "opensuse",
    "suse linux":                       "suse_linux",

    "openssl":                          "openssl",
    "openssh":                          "openssh",
    "openvpn":                          "openvpn",
    "strongswan":                       "strongswan",
    "bind":                             "isc_bind",
    "isc bind":                         "isc_bind",
    "named":                            "isc_bind",
    "dhcpd":                            "isc_dhcp",
    "isc dhcp":                         "isc_dhcp",
    "samba":                            "samba",
    "postfix":                          "postfix",
    "sendmail":                         "sendmail",
    "exim":                             "exim",
    "wireshark":                        "wireshark",
    "snort":                            "snort",
    "suricata":                         "suricata",
    "zeek":                             "zeek",

    "mysql":                            "mysql",
    "oracle mysql":                     "mysql",
    "mariadb":                          "mariadb",
    "postgresql":                       "postgresql",
    "postgres":                         "postgresql",
    "mongodb":                          "mongodb",
    "redis":                            "redis",
    "elasticsearch":                    "elasticsearch",
    "oracle database":                  "oracle_db",
    "oracle db":                        "oracle_db",

    "spring framework":                 "spring_framework",
    "spring":                           "spring_framework",
    "spring boot":                      "spring_boot",
    "docker":                           "docker",
    "kubernetes":                       "kubernetes",
    "k8s":                              "kubernetes",
    "gitlab":                           "gitlab",
    "jenkins":                          "jenkins",
    "ansible":                          "ansible",
    "terraform":                        "terraform",
    "atlassian confluence":             "atlassian_confluence",
    "confluence":                       "atlassian_confluence",
    "atlassian jira":                   "atlassian_jira",
    "jira":                             "atlassian_jira",
    "wordpress":                        "wordpress",
    "drupal":                           "drupal",
    "joomla":                           "joomla",
    "php":                              "php",
    "node.js":                          "nodejs",
    "nodejs":                           "nodejs",
}


_SORTED_ALIASES = sorted(PRODUCT_ALIASES.keys(), key=len, reverse=True)


_STRIP_RE = re.compile(
    r"\b(software|hardware|appliance|platform|suite|solution|"
    r"server|client|agent|module|plugin|edition|release|version|"
    r"v\d[\d.]*|r\d[\d.]*)\b",
    re.IGNORECASE,
)

_TRAILING_VERSION_RE = re.compile(r"\s+\d[\d.a-z\-]*$", re.IGNORECASE)


@lru_cache(maxsize=4096)
def normalize_product(raw: str) -> Optional[str]:
    """
    Convert a raw product name string to a canonical snake_case key.
    Strategy:
        1. Lowercase + strip leading/trailing whitespace
        2. Pass 1: alias lookup on raw cleaned text (before version strip)
           — catches products where the number IS the product name (e.g. "Windows 10")
        3. Remove trailing version strings ("IOS XE 17.6" → "IOS XE")
        4. Remove generic noise words (software, server, edition …)
        5. Greedy longest-match lookup in PRODUCT_ALIASES
        6. Partial-contains fallback
        7. If no match, generate a best-effort slug (spaces → underscores)

    Returns:
        Canonical key string, e.g. "cisco_ios_xe".
        Returns None only if input is empty/None.

    Examples:
        >>> normalize_product("Cisco IOS XE Software 17.9")
        'cisco_ios_xe'
        >>> normalize_product("Microsoft Windows 10")
        'microsoft_windows_10'
        >>> normalize_product("FortiGate")
        'fortinet_fortios'
        >>> normalize_product("Apache HTTP Server 2.4.51")
        'apache_httpd'
    """
    if not raw:
        return None

    text = raw.strip().lower()

    _raw_collapsed = re.sub(r"\s+", " ", text).strip()
    for alias in _SORTED_ALIASES:
        if _raw_collapsed == alias or _raw_collapsed.startswith(alias + " "):
            return PRODUCT_ALIASES[alias]

    text = _TRAILING_VERSION_RE.sub("", text)
    text = _STRIP_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()

    for alias in _SORTED_ALIASES:
        if text == alias or text.startswith(alias):
            return PRODUCT_ALIASES[alias]

    for alias in _SORTED_ALIASES:
        if alias in text:
            return PRODUCT_ALIASES[alias]

    slug = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    if slug:
        logger.debug("No alias match for %r → slug: %r", raw, slug)
        return slug

    return None




_VERSION_TOKEN_RE = re.compile(
    r"(\d+)"             
    r"(?:[.\-_](\d+))?"  
    r"(?:[.\-_](\d+))?"  
    r"(?:[.\-_](\d+))?"  
    r"([a-z]+\d*)?"      
)

_CISCO_VERSION_RE = re.compile(
    r"(\d+)\.(\d+)\((\d+)\)([a-zA-Z]\w*)?",
    re.IGNORECASE
)


def parse_version(version_str: str) -> Optional[tuple]:
    """
    Parse a version string into a comparable tuple:
        (major, minor, patch, build, suffix)

    All numeric components are ints. Suffix is a lowercased string or "".

    Examples:
        >>> parse_version("17.9.4a")
        (17, 9, 4, 0, 'a')
        >>> parse_version("15.0(2)SG")
        (15, 0, 2, 0, 'sg')
        >>> parse_version("2.4.51")
        (2, 4, 51, 0, '')

    Returns None if the string contains no parseable version.
    """
    if not version_str:
        return None

    s = version_str.strip()

    cm = _CISCO_VERSION_RE.search(s)
    if cm:
        major  = int(cm.group(1))
        minor  = int(cm.group(2))
        patch  = int(cm.group(3))
        suffix = (cm.group(4) or "").lower()
        return (major, minor, patch, 0, suffix)

    m = _VERSION_TOKEN_RE.search(s)
    if not m:
        return None

    major  = int(m.group(1))
    minor  = int(m.group(2) or 0)
    patch  = int(m.group(3) or 0)
    build  = int(m.group(4) or 0)
    suffix = (m.group(5) or "").lower()

    return (major, minor, patch, build, suffix)


def _compare_versions(v1: tuple, v2: tuple) -> int:
    """
    Compare two parsed version tuples.
    Returns: -1 if v1 < v2, 0 if equal, +1 if v1 > v2.
    Suffix comparison: '' > any letter suffix (release > rc/beta/alpha).
    """
    for a, b in zip(v1[:4], v2[:4]):
        if a < b:
            return -1
        if a > b:
            return 1

    s1, s2 = v1[4] if len(v1) > 4 else "", v2[4] if len(v2) > 4 else ""
    if s1 == s2:
        return 0
    if s1 == "":    
        return 1
    if s2 == "":
        return -1
    return (s1 > s2) - (s1 < s2)



_RANGE_PATTERNS = [
    # "< 17.9.4a"  or  "before 17.9.4a"
    (re.compile(r"(?:before|<)\s*([\d][\d.a-zA-Z()\-_]+)", re.I), "lt"),
    # "<= 17.9.4a"  or  "through 17.9.4a"
    (re.compile(r"(?:through|<=|=<)\s*([\d][\d.a-zA-Z()\-_]+)", re.I), "lte"),
    # "> 17.6"  or  "after 17.6"
    (re.compile(r"(?:after|>(?!=))\s*([\d][\d.a-zA-Z()\-_]+)", re.I), "gt"),
    # ">= 17.6"  or  "from 17.6"  (lower bound)
    (re.compile(r"(?:from|>=|=>)\s*([\d][\d.a-zA-Z()\-_]+)", re.I), "gte"),
    # "15.0 - 15.4.3"  (inclusive range)
    (re.compile(r"([\d][\d.a-zA-Z()\-_]*)\s*[-–—]\s*([\d][\d.a-zA-Z()\-_]+)", re.I), "range"),
    # "= 17.6.1"  (exact match)
    (re.compile(r"^=?\s*([\d][\d.a-zA-Z()\-_]+)$", re.I), "exact"),
]


def is_version_affected(asset_version: str, range_str: str) -> bool:
    """
    Determine if `asset_version` falls within the CVE's `range_str`.

    Handles range formats:
        - "< 17.9.4a"          (less than)
        - "<= 17.9.4a"         (less than or equal)
        - "> 17.6"             (greater than — rare, used for lower bounds)
        - ">= 17.6"            (greater than or equal — lower bound)
        - "15.0 - 15.4.3"      (inclusive range)
        - "= 17.6.1"           (exact)
        - "17.6.1"             (exact, no operator)
        - Multiple ranges: "< 17.3.1, >= 15.0"  (comma-separated, all must hold)

    Returns:
        True  → asset IS affected
        False → asset is NOT affected, or version/range could not be parsed
    """
    if not asset_version or not range_str:
        return False

    asset_ver = parse_version(asset_version)
    if asset_ver is None:
        logger.debug("Could not parse asset version: %r", asset_version)
        return False


    sub_ranges = [s.strip() for s in range_str.split(",")]
    if len(sub_ranges) > 1:
        return all(is_version_affected(asset_version, sr) for sr in sub_ranges)

    rng = range_str.strip()

    for pattern, kind in _RANGE_PATTERNS:
        m = pattern.search(rng)
        if not m:
            continue

        if kind == "range":
            lo = parse_version(m.group(1))
            hi = parse_version(m.group(2))
            if lo and hi:
                return (
                    _compare_versions(asset_ver, lo) >= 0 and
                    _compare_versions(asset_ver, hi) <= 0
                )

        elif kind in ("lt", "lte", "gt", "gte", "exact"):
            bound = parse_version(m.group(1))
            if bound is None:
                continue
            cmp = _compare_versions(asset_ver, bound)
            if kind == "lt":    return cmp < 0
            if kind == "lte":   return cmp <= 0
            if kind == "gt":    return cmp > 0
            if kind == "gte":   return cmp >= 0
            if kind == "exact": return cmp == 0

    logger.debug("Could not parse range string: %r", range_str)
    return False



_PRODUCT_TO_OEM: dict[str, str] = {
    "cisco":      "Cisco",
    "fortinet":   "Fortinet",
    "juniper":    "Juniper",
    "paloalto":   "Palo Alto Networks",
    "f5":         "F5",
    "siemens":    "Siemens",
    "vmware":     "VMware",
    "microsoft":  "Microsoft",
    "apache":     "Apache",
    "linux":      "Linux",
    "ubuntu":     "Canonical",
    "debian":     "Debian",
    "rhel":       "Red Hat",
    "centos":     "CentOS",
    "openssl":    "OpenSSL",
    "openssh":    "OpenSSH",
    "nginx":      "NGINX",
    "oracle":     "Oracle",
    "mysql":      "Oracle",
    "atlassian":  "Atlassian",
    "spring":     "VMware Tanzu",
    "docker":     "Docker",
    "kubernetes": "CNCF",
}


def extract_oem(product_norm: str) -> str:
    """
    Infer the OEM name from a normalised product key.

    """
    if not product_norm:
        return "Unknown"
    for prefix, oem in _PRODUCT_TO_OEM.items():
        if product_norm.startswith(prefix):
            return oem
    return "Unknown"



_SEVERITY_MAP: dict[str, str] = {
    "critical":  "CRITICAL",
    "high":      "HIGH",
    "medium":    "MEDIUM",
    "moderate":  "MEDIUM",
    "low":       "LOW",
    "info":      "LOW",
    "none":      "LOW",
    "unknown":   "UNKNOWN",
}


def normalize_severity(raw: str) -> str:
    """
    Normalise a raw severity string to one of:
    CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN

    Also accepts CVSS numeric score as input (float/string):
        9.0–10.0 → CRITICAL
        7.0–8.9  → HIGH
        4.0–6.9  → MEDIUM
        0.1–3.9  → LOW
        0.0      → LOW
    """
    if not raw:
        return "UNKNOWN"

    s = str(raw).strip().lower()

    for key, val in _SEVERITY_MAP.items():
        if key in s:
            return val

    # Try numeric CVSS score
    try:
        score = float(s)
        if score >= 9.0:  return "CRITICAL"
        if score >= 7.0:  return "HIGH"
        if score >= 4.0:  return "MEDIUM"
        return "LOW"
    except ValueError:
        pass

    return "UNKNOWN"


def normalize_cve_record(raw: dict) -> dict:
    """
    Apply all normalisations to a raw CVE dict as received from a scraper.

    Mutates and returns the same dict with added/updated fields:
        product_norm, oem, severity (normalised)

    Scrapers should call this before calling db.insert_cve().
    """
    raw["product_norm"] = normalize_product(raw.get("product_raw") or "")
    raw["oem"]          = raw.get("oem") or extract_oem(raw["product_norm"] or "")
    raw["severity"]     = normalize_severity(
        raw.get("severity") or raw.get("cvss_score") or ""
    )
    return raw



if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("\n" + "="*60)
    print("  normalizer.py  —  NTRO CVE Monitor Self-Test")
    print("="*60)

    prod_tests = [
        ("Cisco IOS XE Software 17.9.4a",   "cisco_ios_xe"),
        ("FortiGate",                         "fortinet_fortios"),
        ("FORTIOS",                           "fortinet_fortios"),
        ("Apache HTTP Server 2.4.51",         "apache_httpd"),
        ("Microsoft Windows 10",              "microsoft_windows_10"),
        ("VMware vCenter Server",             "vmware_vcenter"),
        ("PAN-OS",                            "paloalto_panos"),
        ("Juniper Networks Junos OS",         "juniper_junos"),
        ("F5 BIG-IP",                         "f5_bigip"),
        ("log4j",                             "apache_log4j"),
        ("nginx",                             "nginx"),
        ("openssl",                           "openssl"),
    ]

    print("\n[1] Product Normalisation")
    all_pass = True
    for raw, expected in prod_tests:
        result = normalize_product(raw)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_pass = False
        print(f"  {status}  {raw!r:45s} → {result!r}  (expected: {expected!r})")

    print("\n[2] Version Parsing")
    ver_tests = [
        ("17.9.4a",    (17, 9, 4, 0, "a")),
        ("15.0(2)SG",  (15, 0, 2, 0, "sg")),
        ("2.4.51",     (2, 4, 51, 0, "")),
        ("7.2.3",      (7, 2, 3, 0, "")),
        ("10.0",       (10, 0, 0, 0, "")),
    ]
    for vs, expected in ver_tests:
        result = parse_version(vs)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_pass = False
        print(f"  {status}  {vs!r:20s} → {result}  (expected: {expected})")

    print("\n[3] Version Range Matching")
    range_tests = [
        ("17.6.1",  "< 17.9.4a",           True),
        ("17.9.4a", "< 17.9.4a",           False),
        ("17.9.5",  "< 17.9.4a",           False),
        ("17.6.1",  "<= 17.9.4",           True),
        ("17.9.4",  "<= 17.9.4",           True),
        ("15.2.3",  "15.0 - 15.4.3",       True),
        ("15.5.0",  "15.0 - 15.4.3",       False),
        ("14.9.9",  "15.0 - 15.4.3",       False),
        ("7.2.3",   "= 7.2.3",             True),
        ("7.2.4",   "= 7.2.3",             False),
        ("17.6.1",  ">= 17.0, < 17.9.4a",  True),
        ("16.9.9",  ">= 17.0, < 17.9.4a",  False),
    ]
    for av, rng, expected in range_tests:
        result = is_version_affected(av, rng)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_pass = False
        print(f"  {status}  ver={av!r:12s}  range={rng!r:30s} → {result}  (expected: {expected})")

    print("\n[4] Severity Normalisation")
    sev_tests = [
        ("Critical",   "CRITICAL"),
        ("HIGH",       "HIGH"),
        ("moderate",   "MEDIUM"),
        ("9.8",        "CRITICAL"),
        ("7.5",        "HIGH"),
        ("5.0",        "MEDIUM"),
        ("2.1",        "LOW"),
        ("",           "UNKNOWN"),
    ]
    for raw_sev, expected in sev_tests:
        result = normalize_severity(raw_sev)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_pass = False
        print(f"  {status}  {raw_sev!r:15s} → {result!r}  (expected: {expected!r})")

    print("\n" + "="*60)
    if all_pass:
        print("  ALL TESTS PASSED ✓")
    else:
        print("  SOME TESTS FAILED ✗  — review output above")
        sys.exit(1)
    print("="*60 + "\n")
