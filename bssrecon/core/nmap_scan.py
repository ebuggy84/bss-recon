"""
Nmap Scan Module — runs nmap with service/script detection against the target,
saves the XML output, then uses the existing bssrecon/ingest/nmap_parser.py to
parse results into the standard findings format.

Requires nmap to be installed and on PATH:
    sudo apt install nmap        # Kali / Debian
    brew install nmap            # macOS

Mode: active — only runs when --active flag is passed. Requires authorization.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from bssrecon.core import BaseModule, register_module


# ---------------------------------------------------------------------------
# Port → service risk catalogue
#
# Each entry: (port_set, protocol, label, severity, owasp, mitre, remediation)
# Evaluated in order — first match wins. Catch-all at the bottom.
# ---------------------------------------------------------------------------

_PORT_RULES: list[tuple] = [
    # ── Critical exposure ──────────────────────────────────────────────────
    (
        {23}, "tcp", "Telnet",
        "critical",
        "A02:2021 Cryptographic Failures",
        "T1021.004 - Remote Services: SSH",
        "Disable Telnet immediately. Replace with SSH. Telnet transmits credentials "
        "and session data in plaintext.",
    ),
    (
        {512, 513, 514}, "tcp", "Berkeley r-services (rsh/rlogin/rexec)",
        "critical",
        "A07:2021 Identification and Authentication Failures",
        "T1021.004 - Remote Services: SSH",
        "Disable r-services. They perform no authentication and allow trivial "
        "lateral movement. Replace with SSH.",
    ),
    (
        {1524}, "tcp", "Ingreslock backdoor port",
        "critical",
        "A05:2021 Security Misconfiguration",
        "T1505 - Server Software Component",
        "Port 1524 is associated with the Ingreslock backdoor. Investigate and "
        "remove any listening service immediately.",
    ),
    (
        {4444}, "tcp", "Metasploit default listener",
        "critical",
        "A05:2021 Security Misconfiguration",
        "T1219 - Remote Access Software",
        "Port 4444 is the Metasploit default reverse-shell port. Investigate "
        "any service listening here immediately.",
    ),

    # ── High — management & database exposure ─────────────────────────────
    (
        {22}, "tcp", "SSH",
        "low",
        "A05:2021 Security Misconfiguration",
        "T1021.004 - Remote Services: SSH",
        "Restrict SSH access to authorised IP ranges. Enforce key-based "
        "authentication, disable root login, and keep the SSH daemon patched.",
    ),
    (
        {3306}, "tcp", "MySQL",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "MySQL should not be externally reachable. Bind to 127.0.0.1, enforce "
        "strong credentials, and place behind a firewall or VPN.",
    ),
    (
        {5432}, "tcp", "PostgreSQL",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "PostgreSQL should not be externally reachable. Bind to localhost, "
        "enforce strong credentials, and restrict pg_hba.conf.",
    ),
    (
        {1433, 1434}, "tcp", "Microsoft SQL Server",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "MSSQL should not be externally accessible. Place behind a firewall, "
        "disable SA account if unused, and require Windows Authentication.",
    ),
    (
        {27017, 27018, 27019}, "tcp", "MongoDB",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "MongoDB exposed without authentication allows full database read/write. "
        "Enable auth, bind to localhost, and block externally.",
    ),
    (
        {6379}, "tcp", "Redis",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "Unauthenticated Redis allows arbitrary data read/write and often RCE "
        "via config rewrite. Require AUTH, bind to localhost, and firewall.",
    ),
    (
        {9200, 9300}, "tcp", "Elasticsearch",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "Elasticsearch without authentication exposes all indices publicly. "
        "Enable X-Pack security, require TLS, and restrict network access.",
    ),
    (
        {2375, 2376}, "tcp", "Docker API",
        "critical",
        "A05:2021 Security Misconfiguration",
        "T1611 - Escape to Host",
        "Exposed Docker API allows container creation with host mounts, leading "
        "to full host compromise. Never expose the Docker socket over TCP without "
        "mTLS. Use a Unix socket instead.",
    ),
    (
        {2379, 2380}, "tcp", "etcd",
        "critical",
        "A05:2021 Security Misconfiguration",
        "T1552 - Unsecured Credentials",
        "Exposed etcd commonly holds Kubernetes secrets, service tokens, and "
        "cluster credentials in plaintext. Restrict access to control-plane nodes "
        "only and require client certificate authentication.",
    ),
    (
        {8500}, "tcp", "Consul",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1552 - Unsecured Credentials",
        "Consul UI/API exposed without ACLs allows service registration, KV "
        "read/write, and credential extraction. Enable ACL system.",
    ),
    (
        {5601}, "tcp", "Kibana",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "Kibana exposed without authentication grants access to all Elasticsearch "
        "data and may allow RCE via Timelion or Canvas. Require login.",
    ),
    (
        {9090}, "tcp", "Prometheus",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1082 - System Information Discovery",
        "Prometheus exposes metrics endpoints that leak system internals, service "
        "topology, and sometimes credentials. Restrict to internal networks.",
    ),
    (
        {3000}, "tcp", "Grafana / Node dev server",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "Port 3000 commonly runs Grafana (default creds admin/admin) or a "
        "development server. Restrict externally and enforce authentication.",
    ),

    # ── Remote desktop ────────────────────────────────────────────────────
    (
        {3389}, "tcp", "RDP (Remote Desktop Protocol)",
        "high",
        "A07:2021 Identification and Authentication Failures",
        "T1021.001 - Remote Services: Remote Desktop Protocol",
        "RDP exposed externally is a primary ransomware entry point. Restrict "
        "to VPN/jump host, enable NLA, enforce MFA, and keep fully patched.",
    ),
    (
        {5900, 5901, 5902, 5903}, "tcp", "VNC",
        "high",
        "A07:2021 Identification and Authentication Failures",
        "T1021.005 - Remote Services: VNC",
        "VNC often uses weak or no authentication and transmits frames without "
        "encryption. Tunnel over SSH or VPN; never expose directly.",
    ),

    # ── File sharing ──────────────────────────────────────────────────────
    (
        {445}, "tcp", "SMB (Samba/Windows File Sharing)",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1021.002 - Remote Services: SMB/Windows Admin Shares",
        "SMB exposed externally enables EternalBlue-style exploits and "
        "ransomware propagation. Block at the perimeter; require SMBv3 with "
        "signing enabled.",
    ),
    (
        {139}, "tcp", "NetBIOS Session Service",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1021.002 - Remote Services: SMB/Windows Admin Shares",
        "NetBIOS exposes host information and should not be reachable externally. "
        "Block ports 135-139 at the firewall.",
    ),
    (
        {21}, "tcp", "FTP",
        "high",
        "A02:2021 Cryptographic Failures",
        "T1071.002 - Application Layer Protocol: File Transfer Protocols",
        "FTP transmits credentials and data in plaintext. Replace with SFTP or "
        "FTPS. If anonymous login is enabled, disable it immediately.",
    ),
    (
        {2049}, "tcp", "NFS",
        "high",
        "A01:2021 Broken Access Control",
        "T1039 - Data from Network Shared Drive",
        "NFS exports should never be accessible externally. Misconfigured exports "
        "allow unauthenticated filesystem access. Review /etc/exports.",
    ),

    # ── Mail ──────────────────────────────────────────────────────────────
    (
        {25}, "tcp", "SMTP",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1071.003 - Application Layer Protocol: Mail Protocols",
        "If open relay is enabled, the server can be abused for spam. Verify "
        "relay restrictions and require STARTTLS.",
    ),
    (
        {110}, "tcp", "POP3 (plaintext)",
        "medium",
        "A02:2021 Cryptographic Failures",
        "T1071.003 - Application Layer Protocol: Mail Protocols",
        "POP3 transmits credentials in plaintext. Disable in favour of POP3S "
        "(port 995) or IMAP over TLS.",
    ),
    (
        {143}, "tcp", "IMAP (plaintext)",
        "medium",
        "A02:2021 Cryptographic Failures",
        "T1071.003 - Application Layer Protocol: Mail Protocols",
        "IMAP transmits credentials in plaintext. Disable in favour of IMAPS "
        "(port 993) and enforce STARTTLS on port 143.",
    ),

    # ── Web ───────────────────────────────────────────────────────────────
    (
        {80}, "tcp", "HTTP (unencrypted web)",
        "low",
        "A02:2021 Cryptographic Failures",
        "T1071.001 - Application Layer Protocol: Web Protocols",
        "HTTP should redirect to HTTPS. Enable HSTS to prevent SSL stripping.",
    ),
    (
        {443}, "tcp", "HTTPS",
        "info",
        "A02:2021 Cryptographic Failures",
        "T1071.001 - Application Layer Protocol: Web Protocols",
        "Ensure TLS 1.2+ only, strong cipher suites, and a valid certificate "
        "with HSTS and OCSP stapling enabled.",
    ),
    (
        {8080, 8000, 8008}, "tcp", "Alternate HTTP port",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1071.001 - Application Layer Protocol: Web Protocols",
        "Alternate HTTP ports often host admin panels, dev servers, or proxies "
        "without the same hardening as the primary web stack. Review exposure.",
    ),
    (
        {8443, 8444}, "tcp", "Alternate HTTPS port",
        "low",
        "A05:2021 Security Misconfiguration",
        "T1071.001 - Application Layer Protocol: Web Protocols",
        "Alternate HTTPS ports may host management interfaces with weaker auth. "
        "Verify TLS configuration and restrict access where possible.",
    ),

    # ── DNS / infrastructure ───────────────────────────────────────────────
    (
        {53}, "tcp", "DNS (TCP — zone transfer risk)",
        "medium",
        "A05:2021 Security Misconfiguration",
        "T1590.002 - Gather Victim Network Information: DNS",
        "TCP/53 enables zone transfers. Restrict AXFR to authorised secondary "
        "nameservers only (allow-transfer in BIND).",
    ),
    (
        {161, 162}, "udp", "SNMP",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1602 - Data from Configuration Repository",
        "SNMP v1/v2c uses plaintext community strings. Exposed SNMP leaks full "
        "device configuration. Use SNMPv3 with auth+encryption or disable.",
    ),

    # ── CI/CD & developer tooling ──────────────────────────────────────────
    (
        {8080, 8090}, "tcp", "Jenkins / CI server",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1072 - Software Deployment Tools",
        "Jenkins without authentication allows arbitrary Groovy script execution "
        "and full system compromise. Require authentication and restrict externally.",
    ),
    (
        {9418}, "tcp", "Git daemon",
        "medium",
        "A01:2021 Broken Access Control",
        "T1213 - Data from Information Repositories",
        "The git:// protocol serves repositories without authentication. Ensure "
        "only intended repos are exported and consider switching to SSH or HTTPS.",
    ),

    # ── Kubernetes ────────────────────────────────────────────────────────
    (
        {6443, 8443}, "tcp", "Kubernetes API server",
        "critical",
        "A01:2021 Broken Access Control",
        "T1613 - Container and Resource Discovery",
        "Kubernetes API server exposed externally. Anonymous access or weak RBAC "
        "allows full cluster takeover. Restrict to VPN/jump host.",
    ),
    (
        {10250}, "tcp", "Kubelet API",
        "critical",
        "A01:2021 Broken Access Control",
        "T1611 - Escape to Host",
        "Kubelet API exposed without auth allows arbitrary pod exec and host "
        "filesystem access. Restrict to control-plane CIDR and require client certs.",
    ),

    # ── Misc high-value ────────────────────────────────────────────────────
    (
        {5984}, "tcp", "CouchDB",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "CouchDB Futon/Fauxton admin interface may be reachable without credentials. "
        "Require authentication and bind to localhost.",
    ),
    (
        {11211}, "tcp", "Memcached",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "Memcached has no authentication. Exposed instances allow full cache "
        "read/write and are abused for DDoS amplification. Bind to localhost.",
    ),
    (
        {389, 636}, "tcp", "LDAP / LDAPS",
        "high",
        "A07:2021 Identification and Authentication Failures",
        "T1087.002 - Account Discovery: Domain Account",
        "LDAP exposed externally allows directory enumeration and potentially "
        "anonymous bind. Restrict to internal networks and require authentication.",
    ),
    (
        {902, 903}, "tcp", "VMware ESXi / vCenter",
        "high",
        "A05:2021 Security Misconfiguration",
        "T1190 - Exploit Public-Facing Application",
        "VMware management ports should never be internet-facing. Restrict to "
        "management VLAN and keep fully patched (ESXi ransomware targets these).",
    ),
]

# Catch-all for any open port not matched above
_DEFAULT_RULE = (
    "medium",
    "A05:2021 Security Misconfiguration",
    "T1046 - Network Service Discovery",
    "Unexpected open port detected. Review whether this service is required "
    "externally. Apply firewall rules to restrict access to authorised sources only.",
)


def _classify_port(port: int, protocol: str) -> tuple[str, str, str, str, str]:
    """
    Return (label, severity, owasp, mitre, remediation) for a port/protocol.
    """
    proto = (protocol or "tcp").lower()
    for ports, rule_proto, label, severity, owasp, mitre, remediation in _PORT_RULES:
        if port in ports and rule_proto == proto:
            return label, severity, owasp, mitre, remediation
    # Unknown port — generic catch-all
    severity, owasp, mitre, remediation = _DEFAULT_RULE
    return f"Unknown service on port {port}/{proto}", severity, owasp, mitre, remediation


# ---------------------------------------------------------------------------
# Convert nmap_parser output into bss-recon findings
#
# nmap_parser.py is at bssrecon/ingest/nmap_parser.py.  Its exact return
# shape isn't known locally, but the handoff doc says it parses Nmap XML.
# The two most likely shapes returned by Nmap parsers are:
#
#   Shape A — list of host dicts:
#     [{"host": "1.2.3.4", "ports": [{"port": 80, "protocol": "tcp",
#       "state": "open", "service": "http", "version": "nginx 1.20", ...}]}]
#
#   Shape B — flat list of port dicts:
#     [{"host": "1.2.3.4", "port": 80, "protocol": "tcp",
#       "state": "open", "service": "http", "product": "nginx", "version": "1.20"}]
#
# We handle both defensively.
# ---------------------------------------------------------------------------

def _normalise_parser_output(parsed) -> list[dict]:
    """
    Normalise whatever nmap_parser returns into a flat list of port records:
      {"host": str, "port": int, "protocol": str, "state": str,
       "service": str, "version": str, "scripts": list[dict]}
    """
    if not parsed:
        return []

    # Shape A: list of host dicts each with a "ports" key
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        if "ports" in parsed[0]:
            flat = []
            for host_entry in parsed:
                host = host_entry.get("host", host_entry.get("address", ""))
                for p in host_entry.get("ports", []):
                    flat.append({
                        "host":     host,
                        "port":     int(p.get("port", p.get("portid", 0))),
                        "protocol": p.get("protocol", "tcp"),
                        "state":    p.get("state", "open"),
                        "service":  p.get("service", p.get("name", "")),
                        "version":  " ".join(filter(None, [
                            p.get("product", ""),
                            p.get("version", ""),
                            p.get("extrainfo", ""),
                        ])).strip(),
                        "scripts":  p.get("scripts", []),
                    })
            return flat

        # Shape B: already flat, each dict has "port" directly
        if "port" in parsed[0]:
            return [
                {
                    "host":     r.get("host", r.get("address", "")),
                    "port":     int(r.get("port", r.get("portid", 0))),
                    "protocol": r.get("protocol", "tcp"),
                    "state":    r.get("state", "open"),
                    "service":  r.get("service", r.get("name", "")),
                    "version":  " ".join(filter(None, [
                        r.get("product", ""),
                        r.get("version", ""),
                        r.get("extrainfo", ""),
                    ])).strip(),
                    "scripts":  r.get("scripts", []),
                }
                for r in parsed
            ]

    # Shape C: single dict (one host) — wrap and recurse
    if isinstance(parsed, dict):
        return _normalise_parser_output([parsed])

    return []


def _port_records_to_findings(records: list[dict], target: str) -> list[dict]:
    """Convert flat port records into the standard bss-recon findings list."""
    findings: list[dict] = []
    seen: set[tuple] = set()   # deduplicate (port, protocol) pairs

    for rec in records:
        if rec.get("state", "open").lower() != "open":
            continue

        port = rec["port"]
        protocol = rec.get("protocol", "tcp").lower()
        key = (port, protocol)
        if key in seen:
            continue
        seen.add(key)

        service  = rec.get("service", "")
        version  = rec.get("version", "")
        host     = rec.get("host", target)
        scripts  = rec.get("scripts", []) or []

        label, severity, owasp, mitre, remediation = _classify_port(port, protocol)

        detail_parts = [f"Open port {port}/{protocol} on {host}."]
        if service:
            detail_parts.append(f"Service: {service}.")
        if version:
            detail_parts.append(f"Version: {version}.")

        # Surface any nmap script output (vuln scripts, banner grabbing, etc.)
        script_notes: list[str] = []
        for script in scripts:
            s_id     = script.get("id", script.get("name", ""))
            s_output = script.get("output", "").strip()
            if s_id and s_output:
                # Escalate severity if vuln scripts fire
                if any(kw in s_id.lower() for kw in ("vuln", "exploit", "backdoor")):
                    if severity in ("info", "low"):
                        severity = "medium"
                script_notes.append(f"{s_id}: {s_output[:200]}")

        if script_notes:
            detail_parts.append("Script output: " + " | ".join(script_notes))

        findings.append({
            "severity":    severity,
            "title":       f"{label} exposed on port {port}/{protocol}",
            "detail":      "  ".join(detail_parts),
            "owasp":       owasp,
            "mitre":       mitre,
            "remediation": remediation,
            # Extra context — ignored by report generator, useful for diff/ingest
            "_nmap": {
                "host":     host,
                "port":     port,
                "protocol": protocol,
                "service":  service,
                "version":  version,
                "scripts":  scripts,
            },
        })

    # Sort: critical → high → medium → low → info
    _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _rank.get(f["severity"], 5))
    return findings


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

@register_module
class NmapScan(BaseModule):
    name = "nmap"
    description = "Nmap service/script scan — top 1000 ports with -sV -sC"
    requires_api_key = False
    api_key_name = None
    mode = "active"

    def run(self, target: str) -> dict:
        # ── Availability check ────────────────────────────────────────────
        if not shutil.which("nmap"):
            return {
                "domain": target,
                "nmap_available": False,
                "findings": [{
                    "severity": "info",
                    "title": "Nmap Not Installed",
                    "detail": (
                        "nmap binary not found on PATH. "
                        "Install with: sudo apt install nmap"
                    ),
                    "owasp": "",
                    "mitre": "",
                    "remediation": "Install nmap and re-run with --active.",
                }],
            }

        # ── Output paths ──────────────────────────────────────────────────
        scan_cfg = self.config.get("scan", {}) if hasattr(self, "config") else {}
        output_cfg = self.config.get("output", {}) if hasattr(self, "config") else {}

        output_dir = Path(output_cfg.get("output_dir", "./output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        # Sanitise target for use in a filename
        safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
        xml_path = output_dir / f"{safe_target}_nmap.xml"

        timeout_secs = int(scan_cfg.get("timeout", 10)) * 120  # generous for nmap

        # ── Build command ─────────────────────────────────────────────────
        # -sV  : service/version detection
        # -sC  : default NSE scripts (banner, vuln detection, common checks)
        # --top-ports 1000 : most common 1000 ports (faster than -p-)
        # -oX  : XML output (consumed by nmap_parser.py)
        # -T4  : aggressive timing (safe for authorised scans, faster than default)
        # --open : only report open ports (skip filtered/closed noise)
        cmd = [
            "nmap",
            "-sV", "-sC",
            "--top-ports", "1000",
            "--open",
            "-oX", str(xml_path),
            target,
        ]

        # Timing template + packet-rate bounds come from the active scan profile
        # (stealth/balanced/aggressive) so the operator controls scan intensity.
        cmd += self.concurrency.nmap_flags()

        try:
            subprocess.run(
                cmd,
                timeout=timeout_secs,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pass   # partial XML is still parseable
        except FileNotFoundError:
            return {
                "domain": target,
                "nmap_available": False,
                "xml_path": None,
                "findings": [],
            }

        # ── Parse XML via existing ingest module ──────────────────────────
        parsed = []
        if xml_path.exists() and xml_path.stat().st_size > 0:
            try:
                from bssrecon.ingest.nmap_parser import parse_nmap_xml
                parsed = parse_nmap_xml(str(xml_path))
            except ImportError:
                # Fall back to a minimal built-in parser so the module still
                # works even before nmap_parser.py is available locally.
                parsed = _fallback_parse_xml(xml_path)
            except Exception:
                parsed = _fallback_parse_xml(xml_path)

        # ── Convert to findings ───────────────────────────────────────────
        records  = _normalise_parser_output(parsed)
        findings = _port_records_to_findings(records, target)

        open_ports = [r for r in records if r.get("state", "open").lower() == "open"]
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "domain": target,
            "nmap_available": True,
            "xml_path": str(xml_path),
            "open_port_count": len(open_ports),
            "severity_counts": severity_counts,
            "findings": findings,
        }


# ---------------------------------------------------------------------------
# Minimal fallback XML parser
#
# Used only when bssrecon.ingest.nmap_parser is unavailable (e.g. during local
# development before the module is deployed to the Kali box). Produces the same
# Shape A output that _normalise_parser_output expects.
# ---------------------------------------------------------------------------

def _fallback_parse_xml(xml_path: Path) -> list[dict]:
    """
    Parse Nmap XML using only the stdlib defusedxml / xml.etree.ElementTree.
    Returns Shape A: list of host dicts with a "ports" list.
    """
    try:
        try:
            import defusedxml.ElementTree as ET
        except ImportError:
            import xml.etree.ElementTree as ET   # type: ignore[no-redef]

        tree = ET.parse(str(xml_path))
        root = tree.getroot()
    except Exception:
        return []

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        address = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                address = addr_el.get("addr", "")
                break

        ports: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc_el  = port_el.find("service")
            service = svc_el.get("name", "")     if svc_el is not None else ""
            product = svc_el.get("product", "")  if svc_el is not None else ""
            version = svc_el.get("version", "")  if svc_el is not None else ""
            extra   = svc_el.get("extrainfo", "") if svc_el is not None else ""

            scripts: list[dict] = []
            for sc_el in port_el.findall("script"):
                scripts.append({
                    "id":     sc_el.get("id", ""),
                    "output": sc_el.get("output", ""),
                })

            ports.append({
                "port":      int(port_el.get("portid", 0)),
                "protocol":  port_el.get("protocol", "tcp"),
                "state":     "open",
                "service":   service,
                "product":   product,
                "version":   version,
                "extrainfo": extra,
                "scripts":   scripts,
            })

        if ports:
            hosts.append({"host": address, "ports": ports})

    return hosts
