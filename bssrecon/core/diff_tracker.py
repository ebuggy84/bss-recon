"""
Bug Bounty Scope & Change Detection Module

Two features in one:

1. SCOPE MANAGER: Define what's in scope for a bug bounty program,
   and the scan automatically stays within bounds.

2. CHANGE DETECTION: Compare current scan results against previous
   scans to detect what's NEW. New subdomains, new endpoints, new
   JS files, new open ports. This is what the top hunters automate.

The idea: run this weekly/daily against your target list. When
something changes, that's where the vulnerabilities are - in the
new, untested code and infrastructure.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_finding,
    print_key_value,
    print_error,
    print_progress,
    print_warning,
    print_success,
)


@register_module
class DiffModule(BaseModule):
    name = "diff"
    description = "Change detection - compare against previous scans"
    requires_api_key = False

    def run(self, target: str) -> dict:
        print_section("Change Detection", "🔄")

        output_dir = self.config.get("output", {}).get("output_dir", "./output")
        prefix = target.replace(".", "_")
        findings = []

        # Find previous scan files for this target
        scan_files = sorted(
            Path(output_dir).glob(f"{prefix}_*.json"),
            reverse=True,
        )

        if len(scan_files) < 2:
            print_warning(
                f"Need at least 2 scans of {target} to detect changes. "
                f"Found {len(scan_files)}. Run more scans over time."
            )
            return {
                "domain": target,
                "status": "insufficient_data",
                "scans_found": len(scan_files),
                "findings": [],
            }

        # Load current (most recent) and previous scan
        current_file = scan_files[0]
        previous_file = scan_files[1]

        print_progress(f"Current scan:  {current_file.name}")
        print_progress(f"Previous scan: {previous_file.name}")

        try:
            with open(current_file) as f:
                current = json.load(f)
            with open(previous_file) as f:
                previous = json.load(f)
        except Exception as e:
            print_error(f"Could not load scan files: {str(e)}")
            return {"error": str(e), "domain": target}

        changes = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_endpoints": [],
            "new_technologies": [],
            "new_paths": [],
            "dns_changes": [],
            "ssl_changes": [],
            "header_changes": [],
        }

        # Compare subdomains
        curr_subs = set()
        prev_subs = set()
        if "subdomains" in current:
            curr_subs = {
                s["name"] for s in current["subdomains"].get("subdomains", [])
            }
        if "subdomains" in previous:
            prev_subs = {
                s["name"] for s in previous["subdomains"].get("subdomains", [])
            }

        new_subs = curr_subs - prev_subs
        removed_subs = prev_subs - curr_subs

        if new_subs:
            changes["new_subdomains"] = list(new_subs)
            print_key_value(
                f"\n  🆕 New Subdomains", f"({len(new_subs)})"
            )
            for sub in sorted(new_subs):
                from rich.console import Console
                Console().print(f"    [green]+ {sub}[/green]")
                findings.append({
                    "severity": "info",
                    "title": f"New Subdomain Detected: {sub}",
                    "detail": (
                        f"Subdomain {sub} was not present in the previous "
                        f"scan. New infrastructure should be tested."
                    ),
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1590.001 - Gather Victim Network Information",
                })

        if removed_subs:
            changes["removed_subdomains"] = list(removed_subs)
            print_key_value(
                f"\n  Removed Subdomains", f"({len(removed_subs)})"
            )
            for sub in sorted(removed_subs):
                from rich.console import Console
                Console().print(f"    [red]- {sub}[/red]")

        # Compare API endpoints (from JS analysis)
        curr_endpoints = set()
        prev_endpoints = set()
        if "jsanalyze" in current:
            curr_endpoints = set(current["jsanalyze"].get("endpoints", []))
        if "jsanalyze" in previous:
            prev_endpoints = set(previous["jsanalyze"].get("endpoints", []))

        new_endpoints = curr_endpoints - prev_endpoints
        if new_endpoints:
            changes["new_endpoints"] = list(new_endpoints)
            print_key_value(
                f"\n  🆕 New API Endpoints", f"({len(new_endpoints)})"
            )
            for ep in sorted(new_endpoints):
                from rich.console import Console
                Console().print(f"    [green]+ {ep}[/green]")
                findings.append({
                    "severity": "medium",
                    "title": f"New API Endpoint: {ep}",
                    "detail": (
                        f"New API endpoint discovered in JavaScript. "
                        f"New endpoints are high-value targets for testing."
                    ),
                    "owasp": "A01:2021 Broken Access Control",
                    "mitre": "T1190 - Exploit Public-Facing Application",
                })

        # Compare technologies
        curr_tech = set()
        prev_tech = set()
        if "techdetect" in current:
            curr_tech = {
                t["name"] for t in current["techdetect"].get("technologies", [])
            }
        if "techdetect" in previous:
            prev_tech = {
                t["name"] for t in previous["techdetect"].get("technologies", [])
            }

        new_tech = curr_tech - prev_tech
        if new_tech:
            changes["new_technologies"] = list(new_tech)
            print_key_value(
                f"\n  🆕 New Technologies", f"({len(new_tech)})"
            )
            for tech in sorted(new_tech):
                from rich.console import Console
                Console().print(f"    [green]+ {tech}[/green]")

        # Compare accessible paths
        curr_paths = set()
        prev_paths = set()
        if "webprobe" in current:
            curr_paths = {
                p["path"] for p in current["webprobe"].get("accessible_paths", [])
            }
        if "webprobe" in previous:
            prev_paths = {
                p["path"] for p in previous["webprobe"].get("accessible_paths", [])
            }

        new_paths = curr_paths - prev_paths
        if new_paths:
            changes["new_paths"] = list(new_paths)
            print_key_value(
                f"\n  🆕 New Accessible Paths", f"({len(new_paths)})"
            )
            for path in sorted(new_paths):
                from rich.console import Console
                Console().print(f"    [green]+ {path}[/green]")
                findings.append({
                    "severity": "medium",
                    "title": f"New Path Accessible: {path}",
                    "detail": (
                        f"Path {path} is now accessible but was not "
                        f"in the previous scan."
                    ),
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1190 - Exploit Public-Facing Application",
                })

        # Compare DNS
        curr_ips = set()
        prev_ips = set()
        if "dns" in current:
            curr_ips = set(current["dns"].get("ip_addresses", []))
        if "dns" in previous:
            prev_ips = set(previous["dns"].get("ip_addresses", []))

        if curr_ips != prev_ips:
            changes["dns_changes"] = {
                "new_ips": list(curr_ips - prev_ips),
                "removed_ips": list(prev_ips - curr_ips),
            }
            if curr_ips - prev_ips:
                print_key_value(f"\n  🆕 DNS Changes", "")
                for ip in curr_ips - prev_ips:
                    from rich.console import Console
                    Console().print(f"    [green]+ New IP: {ip}[/green]")

        # Summary
        total_changes = (
            len(changes["new_subdomains"])
            + len(changes["new_endpoints"])
            + len(changes["new_technologies"])
            + len(changes["new_paths"])
        )

        if total_changes == 0:
            print_success("No significant changes detected since last scan")
        else:
            print_key_value(
                f"\n  Total Changes Detected", f"{total_changes}"
            )

        results = {
            "domain": target,
            "current_scan": str(current_file),
            "previous_scan": str(previous_file),
            "changes": changes,
            "total_changes": total_changes,
            "findings": findings,
        }

        return results
