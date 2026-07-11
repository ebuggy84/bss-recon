"""
BSS Recon - Wayback Machine Module

Queries the Internet Archive's Wayback Machine CDX API to discover
historical URLs for a target domain. Finds deleted pages, old API
endpoints, JavaScript files, config files, and other content that
may still be accessible or reveal sensitive information.

Mode: PASSIVE (queries web.archive.org, not the target)
API Key: None required
"""
import requests
import time
from collections import defaultdict
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_success,
    print_warning,
    print_error,
    print_progress,
    print_key_value,
    console,
)


@register_module
class WaybackModule(BaseModule):
    name = "wayback"
    description = "Wayback Machine historical URL discovery"
    requires_api_key = False
    mode = "passive"

    # File extensions worth highlighting
    INTERESTING_EXTENSIONS = {
        'high': ['.env', '.sql', '.bak', '.backup', '.config', '.conf',
                 '.key', '.pem', '.p12', '.pfx', '.jks', '.keystore',
                 '.log', '.csv', '.xml', '.json', '.yml', '.yaml',
                 '.sh', '.bash', '.bat', '.ps1', '.py', '.rb', '.php',
                 '.zip', '.tar', '.gz', '.rar', '.7z',
                 '.swp', '.swo', '.old', '.orig', '.save', '.tmp'],
        'medium': ['.js', '.map', '.ts', '.jsx', '.vue',
                   '.htaccess', '.htpasswd', '.gitignore',
                   '.dockerfile', '.dockerignore',
                   '.txt', '.md', '.rst', '.doc', '.docx',
                   '.xls', '.xlsx', '.pdf'],
    }

    # URL path patterns worth highlighting
    INTERESTING_PATHS = [
        'admin', 'api', 'config', 'backup', 'debug', 'test',
        'staging', 'dev', 'internal', 'private', 'secret',
        'swagger', 'graphql', 'wp-admin', 'wp-config',
        'phpinfo', 'phpmyadmin', 'console', 'dashboard',
        'login', 'auth', 'token', 'oauth', 'upload',
        '.git', '.svn', '.env', '.aws', 'credentials',
        'sitemap', 'robots.txt', 'security.txt',
    ]

    def run(self, target):
        print_section("Wayback Machine Discovery", "\U0001F4DA")

        findings = []
        all_urls = []
        stats = defaultdict(int)

        # Query the CDX API
        print_progress(f"Querying Wayback Machine for {target}")

        try:
            urls = self._query_cdx(target)
        except Exception as e:
            print_error(f"Wayback Machine query failed: {e}")
            return {"domain": target, "findings": findings, "urls": [], "error": str(e)}

        if not urls:
            print_warning(f"No archived URLs found for {target}")
            return {"domain": target, "findings": findings, "urls": []}

        # Deduplicate and analyze
        unique_urls = list(set(urls))
        print_success(f"Found {len(unique_urls)} unique archived URLs (from {len(urls)} total snapshots)")

        # Categorize URLs
        high_interest = []
        medium_interest = []
        api_endpoints = []
        js_files = []
        interesting_paths = []

        for url in unique_urls:
            url_lower = url.lower()

            # Check file extensions
            is_high = False
            is_medium = False
            for ext in self.INTERESTING_EXTENSIONS['high']:
                if url_lower.endswith(ext) or ext + '?' in url_lower:
                    high_interest.append(url)
                    is_high = True
                    break

            if not is_high:
                for ext in self.INTERESTING_EXTENSIONS['medium']:
                    if url_lower.endswith(ext) or ext + '?' in url_lower:
                        if ext in ('.js', '.map', '.ts', '.jsx'):
                            js_files.append(url)
                        medium_interest.append(url)
                        is_medium = True
                        break

            # Check interesting paths
            for path_kw in self.INTERESTING_PATHS:
                if path_kw in url_lower:
                    interesting_paths.append(url)
                    break

            # Check for API endpoints
            if '/api/' in url_lower or '/api?' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower or '/v3/' in url_lower:
                api_endpoints.append(url)

        # Deduplicate each category
        high_interest = sorted(set(high_interest))
        medium_interest = sorted(set(medium_interest))
        api_endpoints = sorted(set(api_endpoints))
        js_files = sorted(set(js_files))
        interesting_paths = sorted(set(interesting_paths))

        # Print results
        console.print(f"\n  [bold]URL Analysis:[/bold]")
        console.print(f"    Total unique URLs:     {len(unique_urls)}")
        console.print(f"    High-interest files:   [red]{len(high_interest)}[/red]")
        console.print(f"    Medium-interest files: [yellow]{len(medium_interest)}[/yellow]")
        console.print(f"    API endpoints:         [cyan]{len(api_endpoints)}[/cyan]")
        console.print(f"    JavaScript files:      {len(js_files)}")
        console.print(f"    Interesting paths:     {len(interesting_paths)}")

        # Show high-interest files
        if high_interest:
            console.print(f"\n  [bold red]High-Interest Files (check if still accessible):[/bold red]")
            for url in high_interest[:20]:
                console.print(f"    [red]\u2022[/red] {url}")
                findings.append({
                    "severity": "high",
                    "title": f"Archived sensitive file: {url.split('/')[-1]}",
                    "detail": f"The Wayback Machine has archived a potentially sensitive file at: {url}. Check if this file is still accessible on the live server. If it was removed, the archived version may still contain sensitive data.",
                    "owasp": "A01:2021 Broken Access Control",
                    "mitre": "T1083 - File and Directory Discovery",
                    "remediation": "Verify this file is no longer accessible. If it contained secrets, rotate them. Consider requesting removal from the Wayback Machine if needed.",
                })
            if len(high_interest) > 20:
                console.print(f"    [dim]... and {len(high_interest) - 20} more[/dim]")

        # Show API endpoints
        if api_endpoints:
            console.print(f"\n  [bold cyan]Archived API Endpoints:[/bold cyan]")
            for url in api_endpoints[:15]:
                console.print(f"    [cyan]\u2022[/cyan] {url}")
            if len(api_endpoints) > 15:
                console.print(f"    [dim]... and {len(api_endpoints) - 15} more[/dim]")

            findings.append({
                "severity": "info",
                "title": f"Discovered {len(api_endpoints)} historical API endpoints",
                "detail": f"The Wayback Machine reveals API endpoints that may still be active or have been replaced. Old API versions may lack security controls present in newer versions.",
                "owasp": "A01:2021 Broken Access Control",
                "mitre": "T1190 - Exploit Public-Facing Application",
                "remediation": "Review all discovered API endpoints. Ensure old/deprecated APIs are decommissioned and not still accessible.",
            })

        # Show interesting paths
        if interesting_paths:
            console.print(f"\n  [bold yellow]Interesting Paths Found:[/bold yellow]")
            shown = set()
            for url in interesting_paths[:15]:
                # Normalize to avoid near-duplicates
                path_key = url.split('?')[0].rstrip('/')
                if path_key not in shown:
                    shown.add(path_key)
                    console.print(f"    [yellow]\u2022[/yellow] {url}")
            remaining = len(interesting_paths) - len(shown)
            if remaining > 0:
                console.print(f"    [dim]... and {remaining} more[/dim]")

        # Show JS files (useful for secret scanning)
        if js_files:
            console.print(f"\n  [bold]JavaScript Files (old versions may contain secrets):[/bold]")
            shown_js = set()
            for url in js_files[:10]:
                base = url.split('?')[0]
                if base not in shown_js:
                    shown_js.add(base)
                    console.print(f"    \u2022 {url}")
            if len(js_files) > 10:
                console.print(f"    [dim]... and {len(js_files) - 10} more[/dim]")

            if js_files:
                findings.append({
                    "severity": "low",
                    "title": f"Found {len(js_files)} archived JavaScript files",
                    "detail": "Old JavaScript files may contain API keys, internal endpoints, or debug code that was later removed. Download archived versions and compare with current versions.",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1552 - Unsecured Credentials",
                    "remediation": "Review archived JS files for leaked secrets. Rotate any credentials found in historical versions.",
                })

        # Summary for medium interest
        if medium_interest and not high_interest:
            findings.append({
                "severity": "info",
                "title": f"Found {len(medium_interest)} archived files of interest",
                "detail": "The Wayback Machine has archived various files that may provide useful reconnaissance data including documentation, configuration examples, and scripts.",
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1083 - File and Directory Discovery",
                "remediation": "Review archived content for information disclosure.",
            })

        return {
            "domain": target,
            "findings": findings,
            "total_urls": len(unique_urls),
            "high_interest": high_interest,
            "medium_interest": medium_interest,
            "api_endpoints": api_endpoints,
            "js_files": js_files,
            "interesting_paths": interesting_paths,
        }

    def _query_cdx(self, target):
        """Query the Wayback Machine CDX API for all URLs."""
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{target}/*",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "5000",
        }

        try:
            resp = requests.get(
                cdx_url,
                params=params,
                timeout=30,
                headers={"User-Agent": self.config.get("scan", {}).get("user_agent", "BSS-Recon/1.0")},
            )
            resp.raise_for_status()

            urls = [line.strip() for line in resp.text.strip().split('\n') if line.strip()]
            return urls

        except requests.exceptions.Timeout:
            print_warning("Wayback Machine request timed out (30s). The archive may be slow today.")
            return []
        except requests.exceptions.RequestException as e:
            raise Exception(f"CDX API error: {e}")
