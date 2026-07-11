"""
Nmap XML Output Parser

Parses Nmap XML output files (-oX flag) and normalizes the data
into our standard finding format with OWASP and MITRE mappings.

Usage:
  nmap -sV -sC -oX scan.xml target.com
  python -m bssrecon ingest nmap scan.xml
"""
from defusedxml import ElementTree as ET
from bssrecon.utils.display import (
    print_section,
    print_table,
    print_key_value,
    print_finding,
    print_error,
    print_success,
    print_progress,
)


def parse_nmap_xml(filepath):
    """
    Parse an Nmap XML file and return structured results.

    Args:
        filepath: Path to the Nmap XML output file

    Returns:
        dict with hosts, ports, services, and findings
    """
    print_section("Nmap Import", "📥")
    print_progress(f"Parsing {filepath}")

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        print_error(f"Invalid XML: {str(e)}")
        return {"error": f"XML parse error: {str(e)}"}
    except FileNotFoundError:
        print_error(f"File not found: {filepath}")
        return {"error": f"File not found: {filepath}"}

    # Extract scan metadata
    scan_info = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "version": root.get("version", ""),
    }

    hosts = []
    all_findings = []

    for host_elem in root.findall("host"):
        host_data = {"status": "", "addresses": [], "hostnames": [],
                     "ports": [], "os_matches": []}

        # Host status
        status = host_elem.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")

        # Addresses
        for addr in host_elem.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
            })

        # Hostnames
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                host_data["hostnames"].append({
                    "name": hn.get("name", ""),
                    "type": hn.get("type", ""),
                })

        # Ports and services
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_data = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                }

                state = port_elem.find("state")
                if state is not None:
                    port_data["state"] = state.get("state", "")
                    port_data["reason"] = state.get("reason", "")

                service = port_elem.find("service")
                if service is not None:
                    port_data["service"] = service.get("name", "")
                    port_data["product"] = service.get("product", "")
                    port_data["version"] = service.get("version", "")
                    port_data["extrainfo"] = service.get("extrainfo", "")
                    port_data["cpe"] = []
                    for cpe in service.findall("cpe"):
                        port_data["cpe"].append(cpe.text)

                # NSE script results
                port_data["scripts"] = []
                for script in port_elem.findall("script"):
                    script_data = {
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    }
                    port_data["scripts"].append(script_data)

                    # Generate findings from interesting scripts
                    finding = _script_to_finding(script_data, port_data)
                    if finding:
                        all_findings.append(finding)

                host_data["ports"].append(port_data)

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host_data["os_matches"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })

        hosts.append(host_data)

    # Generate findings from open ports
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") == "open":
                # Flag commonly risky ports
                risky_ports = {
                    21: ("medium", "FTP service exposed"),
                    22: ("info", "SSH service exposed"),
                    23: ("high", "Telnet service exposed (unencrypted)"),
                    25: ("info", "SMTP service exposed"),
                    53: ("info", "DNS service exposed"),
                    80: ("info", "HTTP service exposed"),
                    110: ("medium", "POP3 service exposed (unencrypted)"),
                    135: ("high", "MSRPC exposed"),
                    139: ("high", "NetBIOS exposed"),
                    443: ("info", "HTTPS service exposed"),
                    445: ("high", "SMB exposed"),
                    1433: ("high", "MSSQL exposed to internet"),
                    1521: ("high", "Oracle DB exposed to internet"),
                    3306: ("high", "MySQL exposed to internet"),
                    3389: ("high", "RDP exposed to internet"),
                    5432: ("high", "PostgreSQL exposed to internet"),
                    5900: ("high", "VNC exposed to internet"),
                    6379: ("critical", "Redis exposed to internet"),
                    8080: ("medium", "HTTP alternate/proxy exposed"),
                    8443: ("info", "HTTPS alternate exposed"),
                    9200: ("high", "Elasticsearch exposed to internet"),
                    27017: ("critical", "MongoDB exposed to internet"),
                }

                port_num = port["port"]
                if port_num in risky_ports:
                    severity, desc = risky_ports[port_num]
                    svc = port.get("service", "unknown")
                    ver = port.get("version", "")
                    finding = {
                        "severity": severity,
                        "title": f"{desc}",
                        "detail": (
                            f"Port {port_num}/{port['protocol']} - "
                            f"{svc} {ver}".strip()
                        ),
                        "port": port_num,
                        "source": "nmap",
                    }

                    # Map to OWASP/MITRE
                    if severity in ("critical", "high"):
                        finding["owasp"] = "A05:2021 Security Misconfiguration"
                        finding["mitre"] = "T1190 - Exploit Public-Facing Application"
                    else:
                        finding["owasp"] = "A05:2021 Security Misconfiguration"
                        finding["mitre"] = (
                            "T1590.005 - Gather Victim Network Information: IP Addresses"
                        )

                    all_findings.append(finding)

    # Display results
    for host in hosts:
        ip = host["addresses"][0]["addr"] if host["addresses"] else "unknown"
        print_key_value("Host", ip)

        if host["ports"]:
            print_table(
                "Open Ports",
                [
                    ("Port", "cyan"),
                    ("State", "green"),
                    ("Service", "white"),
                    ("Version", "yellow"),
                ],
                [
                    (
                        f"{p['port']}/{p['protocol']}",
                        p.get("state", ""),
                        p.get("service", ""),
                        f"{p.get('product', '')} {p.get('version', '')}".strip(),
                    )
                    for p in host["ports"]
                    if p.get("state") == "open"
                ],
            )

    if all_findings:
        print_key_value(f"\nFindings", f"({len(all_findings)})")
        for f in all_findings:
            print_finding(f["severity"], f["title"], f.get("detail", ""))

    print_success(
        f"Imported {len(hosts)} host(s), "
        f"{sum(len(h.get('ports', [])) for h in hosts)} port(s), "
        f"{len(all_findings)} finding(s)"
    )

    return {
        "scan_info": scan_info,
        "hosts": hosts,
        "findings": all_findings,
        "source": "nmap",
    }


def _script_to_finding(script_data, port_data):
    """Convert interesting NSE script output to a finding."""
    script_id = script_data.get("id", "")
    output = script_data.get("output", "")

    # Map interesting NSE scripts to findings
    interesting_scripts = {
        "ssl-heartbleed": ("critical", "Heartbleed vulnerability detected"),
        "smb-vuln-ms17-010": ("critical", "EternalBlue vulnerability (MS17-010)"),
        "http-sql-injection": ("high", "Potential SQL injection detected"),
        "http-shellshock": ("critical", "Shellshock vulnerability detected"),
        "ssl-poodle": ("high", "POODLE vulnerability detected"),
        "ssl-ccs-injection": ("high", "CCS Injection vulnerability"),
        "http-robots.txt": ("info", "robots.txt found with entries"),
        "http-git-discover": ("high", "Git repository exposed"),
        "http-backup-finder": ("medium", "Backup files found"),
        "http-config-backup": ("medium", "Configuration backup exposed"),
    }

    if script_id in interesting_scripts:
        severity, title = interesting_scripts[script_id]
        return {
            "severity": severity,
            "title": title,
            "detail": (
                f"Port {port_data['port']}: {output[:200]}"
            ),
            "source": f"nmap-{script_id}",
            "owasp": "A06:2021 Vulnerable and Outdated Components",
            "mitre": "T1190 - Exploit Public-Facing Application",
        }

    return None
