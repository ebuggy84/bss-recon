"""
Subdomain Enumeration Module
Discovers subdomains using Certificate Transparency logs (crt.sh).
No API key required - crt.sh is free and public.

This is the same technique the top bug bounty hunters use.
Certificate Transparency logs record every SSL cert ever issued,
so if a company got a cert for staging.example.com, it shows up here
even if they never meant for anyone to find that subdomain.
"""
import requests
import time
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_subdomain_results,
    print_key_value,
    print_error,
    print_progress,
    print_warning,
)


@register_module
class SubdomainModule(BaseModule):
    name = "subdomains"
    description = "Subdomain discovery via Certificate Transparency (crt.sh)"
    requires_api_key = False

    def run(self, target: str) -> dict:
        print_section("Subdomain Enumeration", "🔎")
        print_progress(f"Querying Certificate Transparency logs for *.{target}")

        subdomains = []
        unique_names = set()
        max_results = self.config.get("scan", {}).get("max_subdomains", 500)

        # Query crt.sh - Certificate Transparency log aggregator
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            headers = {
                "User-Agent": self.config.get("scan", {}).get(
                    "user_agent", "BSS-Recon/1.0"
                )
            }

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name = entry.get("name_value", "").strip().lower()
                    # crt.sh sometimes returns wildcard and multi-line entries
                    for sub_name in name.split("\n"):
                        sub_name = sub_name.strip()
                        if sub_name and sub_name not in unique_names:
                            # Skip wildcard-only entries
                            if sub_name.startswith("*."):
                                sub_name = sub_name[2:]
                            if sub_name and sub_name not in unique_names:
                                unique_names.add(sub_name)
                                subdomains.append({
                                    "name": sub_name,
                                    "first_seen": entry.get(
                                        "entry_timestamp", ""
                                    )[:10],
                                    "issuer": entry.get("issuer_name", ""),
                                    "cert_id": entry.get("id", ""),
                                })

                            if len(unique_names) >= max_results:
                                break

            elif response.status_code == 429:
                print_warning(
                    "Rate limited by crt.sh. Wait a minute and try again."
                )
                return {
                    "error": "Rate limited by crt.sh",
                    "domain": target,
                    "subdomains": [],
                }
            else:
                print_warning(
                    f"crt.sh returned status {response.status_code}"
                )

        except requests.exceptions.Timeout:
            print_warning("crt.sh request timed out (this happens, it's a free service)")
        except requests.exceptions.RequestException as e:
            print_error(f"crt.sh request failed: {str(e)}")
        except ValueError:
            print_warning("crt.sh returned invalid JSON (might be overloaded)")

        # Sort by name for clean output
        subdomains.sort(key=lambda x: x["name"])

        # Categorize subdomains for interesting patterns
        interesting = []
        categories = {
            "dev/staging": ["dev", "staging", "stage", "test", "uat", "qa", "sandbox"],
            "admin": ["admin", "panel", "dashboard", "manage", "cms", "backend"],
            "api": ["api", "api2", "api-v2", "graphql", "rest", "ws"],
            "mail": ["mail", "smtp", "imap", "pop", "webmail", "mx"],
            "vpn/remote": ["vpn", "remote", "rdp", "ssh", "bastion", "jump"],
            "internal": ["internal", "intranet", "corp", "private", "local"],
            "old/legacy": ["old", "legacy", "deprecated", "archive", "backup"],
            "ci/cd": ["jenkins", "gitlab", "github", "ci", "cd", "deploy", "build"],
            "monitoring": ["monitor", "grafana", "kibana", "elastic", "nagios", "zabbix"],
            "database": ["db", "database", "sql", "mongo", "redis", "postgres"],
        }

        for sub in subdomains:
            name = sub["name"].lower()
            for category, keywords in categories.items():
                if any(kw in name for kw in keywords):
                    sub["category"] = category
                    interesting.append(sub)
                    break

        print_subdomain_results(subdomains)

        # Highlight interesting finds
        if interesting:
            print_key_value(
                "\n  ⚠ Interesting Subdomains",
                f"({len(interesting)} potentially notable)",
            )
            for sub in interesting[:20]:
                cat = sub.get("category", "unknown")
                from rich.console import Console
                Console().print(
                    f"    [yellow][{cat}][/yellow] {sub['name']}"
                )

        results = {
            "domain": target,
            "subdomains": subdomains,
            "total_found": len(subdomains),
            "interesting": interesting,
            "interesting_count": len(interesting),
            "source": "crt.sh (Certificate Transparency)",
        }

        return results
