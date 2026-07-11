"""
Shodan Recon Module
Queries Shodan for open ports, services, and known vulnerabilities.
Requires a Shodan API key (free tier: 100 queries/month).

This is what separates basic recon from real attack surface mapping.
Shodan has already scanned the entire internet - you're just looking
up what they found on your target's IP addresses.
"""
import socket
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_table,
    print_key_value,
    print_error,
    print_warning,
    print_progress,
    print_finding,
)


@register_module
class ShodanModule(BaseModule):
    name = "shodan"
    description = "Shodan port/service/vulnerability lookup"
    requires_api_key = True
    api_key_name = "shodan"

    def run(self, target: str) -> dict:
        print_section("Shodan Intelligence", "📡")

        api_key = self.get_api_key()
        if not api_key:
            print_warning(
                "Shodan API key not configured. "
                "Add your key to config.yaml or set BSS_SHODAN_KEY env var. "
                "Free tier: https://account.shodan.io"
            )
            return {"error": "No API key", "domain": target}

        try:
            import shodan
            api = shodan.Shodan(api_key)
        except ImportError:
            print_error("shodan library not installed. Run: pip install shodan")
            return {"error": "shodan library not installed", "domain": target}

        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(target)
            print_progress(f"Resolved {target} -> {ip}")
        except socket.gaierror:
            print_error(f"Could not resolve {target} to IP address")
            return {"error": f"DNS resolution failed for {target}", "domain": target}

        try:
            host = api.host(ip)

            # Basic host info
            print_key_value("IP", host.get("ip_str", ip))
            print_key_value("Organization", host.get("org", "N/A"))
            print_key_value("ISP", host.get("isp", "N/A"))
            print_key_value("OS", host.get("os", "N/A"))
            print_key_value("Last Updated", host.get("last_update", "N/A"))

            # Open ports and services
            ports = host.get("ports", [])
            print_key_value("Open Ports", ", ".join(str(p) for p in sorted(ports)))

            # Service details table
            services = []
            for item in host.get("data", []):
                services.append({
                    "port": item.get("port", ""),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("product", "unknown"),
                    "version": item.get("version", ""),
                    "banner_snippet": (item.get("data", "")[:80]
                                       .replace("\n", " ")
                                       .replace("\r", "")),
                })

            if services:
                print_table(
                    "Services Detected",
                    [
                        ("Port", "cyan"),
                        ("Proto", "dim"),
                        ("Service", "white"),
                        ("Version", "yellow"),
                        ("Banner", "dim"),
                    ],
                    [
                        (
                            s["port"],
                            s["protocol"],
                            s["service"],
                            s["version"],
                            s["banner_snippet"],
                        )
                        for s in services
                    ],
                )

            # Known vulnerabilities
            vulns = host.get("vulns", [])
            findings = []
            if vulns:
                print_key_value(
                    f"\n  ⚠ Known Vulnerabilities", f"({len(vulns)} CVEs)"
                )
                for cve in sorted(vulns):
                    finding = {
                        "severity": "high",
                        "title": cve,
                        "detail": f"https://nvd.nist.gov/vuln/detail/{cve}",
                        "owasp": "A06:2021 Vulnerable and Outdated Components",
                        "mitre": "T1190 - Exploit Public-Facing Application",
                    }
                    findings.append(finding)
                    print_finding("high", cve, f"https://nvd.nist.gov/vuln/detail/{cve}")

            results = {
                "domain": target,
                "ip": host.get("ip_str", ip),
                "organization": host.get("org", "N/A"),
                "isp": host.get("isp", "N/A"),
                "os": host.get("os", "N/A"),
                "ports": sorted(ports),
                "services": services,
                "vulnerabilities": vulns,
                "vuln_count": len(vulns),
                "findings": findings,
            }

            return results

        except shodan.APIError as e:
            if "No information available" in str(e):
                print_warning(f"Shodan has no data for {ip}")
                return {
                    "domain": target,
                    "ip": ip,
                    "note": "No Shodan data available for this host",
                }
            print_error(f"Shodan API error: {str(e)}")
            return {"error": str(e), "domain": target}
        except Exception as e:
            print_error(f"Shodan lookup failed: {str(e)}")
            return {"error": str(e), "domain": target}
