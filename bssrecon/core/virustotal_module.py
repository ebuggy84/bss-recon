"""
VirusTotal Module

Checks domain/IP reputation across 70+ security vendors.
Shows if the target has been flagged as malicious, pulls
historical DNS data, and related domains.

Free tier: 500 requests/day (more than enough).
API key: https://www.virustotal.com/gui/join-us

This tells you if the target or its infrastructure has
any history of malicious activity, which is valuable
context for both OSINT reports and pentest engagements.
"""
import requests
import time
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_finding,
    print_key_value,
    print_error,
    print_progress,
    print_table,
    print_warning,
    print_success,
)


@register_module
class VirusTotalModule(BaseModule):
    name = "virustotal"
    description = "VirusTotal domain/IP reputation and threat intelligence"
    requires_api_key = True
    api_key_name = "virustotal"

    def run(self, target: str) -> dict:
        print_section("VirusTotal Reputation", "🦠")

        api_key = self.get_api_key()
        if not api_key:
            print_warning(
                "VirusTotal API key not configured. "
                "Free tier: 500 requests/day. "
                "Get yours at: https://www.virustotal.com/gui/join-us"
            )
            return {"error": "No API key", "domain": target}

        headers = {"x-apikey": api_key}
        findings = []

        # Query domain report
        print_progress(f"Checking domain reputation for {target}")
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            resp = requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})

                # Analysis stats - how many vendors flag it
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_vendors = malicious + suspicious + harmless + undetected

                print_key_value("Malicious Flags", f"{malicious}/{total_vendors}")
                print_key_value("Suspicious Flags", f"{suspicious}/{total_vendors}")
                print_key_value("Clean", f"{harmless}/{total_vendors}")

                if malicious > 0:
                    findings.append({
                        "severity": "high",
                        "title": f"Domain Flagged as Malicious by {malicious} Vendor(s)",
                        "detail": (
                            f"{malicious} out of {total_vendors} security vendors "
                            f"flagged {target} as malicious on VirusTotal."
                        ),
                        "owasp": "A06:2021 Vulnerable and Outdated Components",
                        "mitre": "T1583 - Acquire Infrastructure",
                        "remediation": (
                            "Investigate why security vendors are flagging this "
                            "domain. Check for malware, phishing content, or "
                            "compromised infrastructure."
                        ),
                    })
                    print_finding(
                        "high",
                        f"Flagged malicious by {malicious} vendor(s)",
                        "Domain has negative reputation",
                    )

                if suspicious > 0:
                    findings.append({
                        "severity": "medium",
                        "title": f"Domain Flagged as Suspicious by {suspicious} Vendor(s)",
                        "detail": (
                            f"{suspicious} out of {total_vendors} security vendors "
                            f"flagged {target} as suspicious."
                        ),
                        "owasp": "A06:2021 Vulnerable and Outdated Components",
                        "mitre": "T1583 - Acquire Infrastructure",
                    })
                    print_finding(
                        "medium",
                        f"Flagged suspicious by {suspicious} vendor(s)",
                        "",
                    )

                if malicious == 0 and suspicious == 0:
                    print_success(f"Domain is clean across {total_vendors} vendors")

                # Categories
                categories = attributes.get("categories", {})
                if categories:
                    cat_values = list(set(categories.values()))
                    print_key_value("Categories", ", ".join(cat_values[:5]))

                # Popularity ranks
                popularity = attributes.get("popularity_ranks", {})
                if popularity:
                    for source, rank_info in list(popularity.items())[:3]:
                        print_key_value(
                            f"  {source} Rank",
                            rank_info.get("rank", "N/A"),
                        )

                # Last HTTPS certificate
                cert = attributes.get("last_https_certificate", {})
                if cert:
                    issuer = cert.get("issuer", {})
                    print_key_value(
                        "Last SSL Issuer",
                        issuer.get("O", "N/A"),
                    )

                # DNS records from VT
                last_dns = attributes.get("last_dns_records", [])
                if last_dns:
                    print_key_value(f"\n  VT DNS Records", f"({len(last_dns)})")
                    for record in last_dns[:10]:
                        rtype = record.get("type", "")
                        value = record.get("value", "")
                        from rich.console import Console
                        Console().print(f"    [dim]{rtype}: {value}[/dim]")

                # Whois info from VT
                whois_data = attributes.get("whois", "")
                registrar = attributes.get("registrar", "")
                if registrar:
                    print_key_value("VT Registrar", registrar)

                results = {
                    "domain": target,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_vendors": total_vendors,
                    "categories": categories,
                    "popularity": popularity,
                    "dns_records_count": len(last_dns),
                    "findings": findings,
                    "reputation": (
                        "clean" if malicious == 0 and suspicious == 0
                        else "flagged"
                    ),
                }

                return results

            elif resp.status_code == 401:
                print_error("Invalid VirusTotal API key")
                return {"error": "Invalid API key", "domain": target}
            elif resp.status_code == 429:
                print_warning("VirusTotal rate limit reached. Try again later.")
                return {"error": "Rate limited", "domain": target}
            else:
                print_error(f"VirusTotal returned status {resp.status_code}")
                return {"error": f"HTTP {resp.status_code}", "domain": target}

        except requests.exceptions.Timeout:
            print_error("VirusTotal request timed out")
            return {"error": "Timeout", "domain": target}
        except Exception as e:
            print_error(f"VirusTotal lookup failed: {str(e)}")
            return {"error": str(e), "domain": target}
