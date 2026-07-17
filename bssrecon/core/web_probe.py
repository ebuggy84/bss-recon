"""
Web Prober Module (v2 - Smart Response Diff)

Actively probes a target website for common files and paths that
reveal information about the site structure, hidden directories,
and potential security issues.

v2 Enhancement: Before probing, requests a random non-existent path to
fingerprint the server's "not found" response. Any probe result that
matches this baseline fingerprint is automatically filtered as a soft-404,
eliminating false positives from WAFs and custom error pages.

No API key required - standard HTTP requests.
"""
import re
import random
import string
import hashlib
import requests
from urllib.parse import urljoin
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_finding,
    print_key_value,
    print_error,
    print_progress,
    print_warning,
    print_success,
    console,
)


# Paths to check and what they mean
PROBE_PATHS = {
    # Standard files
    "/robots.txt": {
        "description": "Search engine crawl rules (may reveal hidden paths)",
        "severity": "info",
        "parse": True,
    },
    "/sitemap.xml": {
        "description": "Site structure map",
        "severity": "info",
        "parse": False,
    },
    "/.well-known/security.txt": {
        "description": "Security contact information",
        "severity": "info",
        "parse": False,
    },
    "/humans.txt": {
        "description": "Developer credits (may reveal team info)",
        "severity": "info",
        "parse": False,
    },

    # Exposed admin panels
    "/wp-admin/": {
        "description": "WordPress admin panel",
        "severity": "medium",
        "finding": True,
    },
    "/wp-login.php": {
        "description": "WordPress login page",
        "severity": "medium",
        "finding": True,
    },
    "/administrator/": {
        "description": "Joomla admin panel",
        "severity": "medium",
        "finding": True,
    },
    "/admin/": {
        "description": "Admin panel",
        "severity": "medium",
        "finding": True,
    },
    "/admin/login": {
        "description": "Admin login page",
        "severity": "medium",
        "finding": True,
    },
    "/cpanel": {
        "description": "cPanel hosting control panel",
        "severity": "high",
        "finding": True,
    },
    "/phpmyadmin/": {
        "description": "phpMyAdmin database manager",
        "severity": "high",
        "finding": True,
    },

    # Exposed version control
    "/.git/config": {
        "description": "Git repository exposed - source code leak",
        "severity": "critical",
        "finding": True,
    },
    "/.svn/entries": {
        "description": "SVN repository exposed - source code leak",
        "severity": "critical",
        "finding": True,
    },
    "/.hg/": {
        "description": "Mercurial repository exposed",
        "severity": "critical",
        "finding": True,
    },

    # Exposed config/env files
    "/.env": {
        "description": "Environment file (may contain credentials)",
        "severity": "critical",
        "finding": True,
    },
    "/config.php": {
        "description": "PHP configuration file",
        "severity": "high",
        "finding": True,
    },
    "/config.yml": {
        "description": "YAML configuration file",
        "severity": "high",
        "finding": True,
    },
    "/web.config": {
        "description": "IIS/ASP.NET configuration file",
        "severity": "high",
        "finding": True,
    },
    "/.htaccess": {
        "description": "Apache configuration file",
        "severity": "medium",
        "finding": True,
    },
    "/wp-config.php.bak": {
        "description": "WordPress config backup (may contain DB credentials)",
        "severity": "critical",
        "finding": True,
    },
    "/wp-config.php~": {
        "description": "WordPress config editor backup",
        "severity": "critical",
        "finding": True,
    },

    # API documentation
    "/swagger/": {
        "description": "Swagger API documentation",
        "severity": "medium",
        "finding": True,
    },
    "/swagger-ui.html": {
        "description": "Swagger UI",
        "severity": "medium",
        "finding": True,
    },
    "/api-docs": {
        "description": "API documentation",
        "severity": "medium",
        "finding": True,
    },
    "/graphql": {
        "description": "GraphQL endpoint",
        "severity": "medium",
        "finding": True,
    },
    "/api/v1/": {
        "description": "API version 1 endpoint",
        "severity": "info",
        "finding": True,
    },
    "/api/v2/": {
        "description": "API version 2 endpoint",
        "severity": "info",
        "finding": True,
    },

    # WordPress specific
    "/wp-json/wp/v2/users": {
        "description": "WordPress user enumeration endpoint",
        "severity": "medium",
        "finding": True,
    },
    "/xmlrpc.php": {
        "description": "WordPress XML-RPC (brute force / DDoS vector)",
        "severity": "medium",
        "finding": True,
    },
    "/wp-content/debug.log": {
        "description": "WordPress debug log (may contain sensitive info)",
        "severity": "high",
        "finding": True,
    },
    "/wp-includes/": {
        "description": "WordPress includes directory listing",
        "severity": "low",
        "finding": True,
    },

    # Backup files
    "/backup/": {
        "description": "Backup directory",
        "severity": "high",
        "finding": True,
    },
    "/backup.sql": {
        "description": "Database backup file",
        "severity": "critical",
        "finding": True,
    },
    "/backup.zip": {
        "description": "Site backup archive",
        "severity": "critical",
        "finding": True,
    },
    "/db.sql": {
        "description": "Database dump",
        "severity": "critical",
        "finding": True,
    },

    # Server info
    "/server-status": {
        "description": "Apache server status page",
        "severity": "high",
        "finding": True,
    },
    "/server-info": {
        "description": "Apache server info page",
        "severity": "high",
        "finding": True,
    },
    "/phpinfo.php": {
        "description": "PHP information page (leaks server config)",
        "severity": "high",
        "finding": True,
    },
    "/info.php": {
        "description": "PHP info page",
        "severity": "high",
        "finding": True,
    },
    "/.DS_Store": {
        "description": "macOS directory listing file",
        "severity": "low",
        "finding": True,
    },
}


class ResponseFingerprint:
    """Fingerprints an HTTP response for soft-404 detection."""

    def __init__(self, status_code, content_length, word_count, content_hash, title=None):
        self.status_code = status_code
        self.content_length = content_length
        self.word_count = word_count
        self.content_hash = content_hash
        self.title = title

    def matches(self, other, tolerance=0.05):
        """Check if another fingerprint matches this baseline.

        Uses a tolerance for content_length (default 5%) to account for
        dynamic content like timestamps or session tokens in error pages.
        """
        # Exact hash match = definitely the same page
        if self.content_hash == other.content_hash:
            return True

        # Same status code + similar content length + similar word count
        if self.status_code == other.status_code:
            # Check content length within tolerance
            if self.content_length > 0:
                length_ratio = abs(self.content_length - other.content_length) / max(self.content_length, 1)
                if length_ratio <= tolerance:
                    # Also check word count similarity
                    if self.word_count > 0:
                        word_ratio = abs(self.word_count - other.word_count) / max(self.word_count, 1)
                        if word_ratio <= tolerance:
                            return True

            # Same title tag = likely same page
            if self.title and other.title and self.title == other.title:
                return True

        return False

    def __repr__(self):
        return (
            f"Fingerprint(status={self.status_code}, "
            f"length={self.content_length}, "
            f"words={self.word_count}, "
            f"title='{self.title}')"
        )


def fingerprint_response(resp):
    """Create a fingerprint from an HTTP response."""
    content = resp.content
    text = resp.text if resp.text else ""

    # Extract title tag if present
    title = None
    title_match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()[:100]

    # Count words (rough but effective)
    word_count = len(text.split())

    # Content hash (MD5 of body, ignoring whitespace variations)
    normalized = re.sub(r'\s+', ' ', text).strip()
    content_hash = hashlib.md5(normalized.encode()).hexdigest()

    return ResponseFingerprint(
        status_code=resp.status_code,
        content_length=len(content),
        word_count=word_count,
        content_hash=content_hash,
        title=title,
    )


@register_module
class WebProbeModule(BaseModule):
    name = "webprobe"
    description = "Web path probing (robots.txt, admin panels, exposed files)"
    requires_api_key = False
    mode = "active"

    def run(self, target: str) -> dict:
        print_section("Web Path Probing", "\U0001F526")

        base_url = f"https://{target}"
        findings = []
        accessible_paths = []
        robots_entries = []
        sitemap_urls = []
        filtered_soft404 = 0

        headers = {
            "User-Agent": self.config.get("scan", {}).get(
                "user_agent", "BSS-Recon/1.0"
            )
        }

        # === SMART RESPONSE DIFF: Fingerprint baseline ===
        baseline_fingerprints = self._get_baseline_fingerprints(base_url, headers)

        if baseline_fingerprints:
            console.print(
                f"  [dim]Baseline fingerprint captured "
                f"(soft-404 detection active)[/dim]"
            )
            for bp in baseline_fingerprints:
                console.print(
                    f"  [dim]  {bp.status_code} | "
                    f"{bp.content_length} bytes | "
                    f"{bp.word_count} words | "
                    f"title='{bp.title or 'none'}'[/dim]"
                )
        else:
            console.print(
                f"  [dim]Could not establish baseline "
                f"(soft-404 filtering disabled)[/dim]"
            )

        total_paths = len(PROBE_PATHS)
        checked = 0
        ctrl = self.concurrency   # profile-governed pacing between probes

        for path, info in PROBE_PATHS.items():
            checked += 1
            ctrl.throttle_sync()
            url = urljoin(base_url, path)

            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=headers,
                    verify=False,
                )

                if resp.status_code == 200:
                    content_length = len(resp.content)

                    # Skip empty responses
                    if content_length < 10:
                        continue

                    # === SMART RESPONSE DIFF: Check against baseline ===
                    is_finding = info.get("finding", False)
                    if is_finding and baseline_fingerprints:
                        probe_fp = fingerprint_response(resp)
                        is_soft_404 = any(
                            bp.matches(probe_fp)
                            for bp in baseline_fingerprints
                        )

                        if is_soft_404:
                            filtered_soft404 += 1
                            console.print(
                                f"    [dim]\u2718 Filtered (soft-404): {path} "
                                f"({content_length} bytes - matches baseline)[/dim]"
                            )
                            continue

                    accessible_paths.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": content_length,
                        "description": info["description"],
                    })

                    severity = info.get("severity", "info")

                    if is_finding:
                        print_finding(
                            severity,
                            f"Accessible: {path}",
                            info["description"],
                        )
                        findings.append({
                            "severity": severity,
                            "title": f"Exposed Path: {path}",
                            "detail": (
                                f"{info['description']}. "
                                f"Path returned HTTP 200 with {content_length} bytes. "
                                f"Verified: response differs from baseline 404 page."
                            ),
                            "owasp": "A05:2021 Security Misconfiguration",
                            "mitre": "T1190 - Exploit Public-Facing Application",
                            "remediation": (
                                f"Restrict access to {path} using authentication, "
                                f"IP whitelisting, or remove it from the public "
                                f"web server if not needed."
                            ),
                        })
                    else:
                        console.print(
                            f"    [green]\u2713 Found:[/green] {path} "
                            f"[dim]({content_length} bytes)[/dim]"
                        )

                    # Parse robots.txt for hidden paths
                    if path == "/robots.txt" and info.get("parse"):
                        robots_entries = self._parse_robots(resp.text)

                    # Note sitemap
                    if path == "/sitemap.xml":
                        sitemap_urls = self._count_sitemap_urls(resp.text)

                elif resp.status_code == 403:
                    console.print(
                        f"    [yellow]\u26a0 Restricted (403):[/yellow] {path} "
                        f"[dim]({info['description']})[/dim]"
                    )
                    accessible_paths.append({
                        "path": path,
                        "status": 403,
                        "size": 0,
                        "description": f"RESTRICTED - {info['description']}",
                    })

            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        # Print robots.txt findings
        if robots_entries:
            print_key_value(f"\n  robots.txt Disallowed Paths", "")
            for entry in robots_entries[:20]:
                console.print(f"    [yellow]\u2192 {entry}[/yellow]")

                interesting_keywords = [
                    "admin", "login", "backup", "config", "private",
                    "secret", "internal", "api", "debug", "test",
                    "staging", "dev", "old", "temp", "upload",
                ]
                for keyword in interesting_keywords:
                    if keyword in entry.lower():
                        findings.append({
                            "severity": "info",
                            "title": f"robots.txt Disallows: {entry}",
                            "detail": (
                                f"The path '{entry}' is blocked in robots.txt, "
                                f"suggesting it exists and may contain "
                                f"sensitive content worth investigating."
                            ),
                            "owasp": "A05:2021 Security Misconfiguration",
                            "mitre": "T1595.003 - Active Scanning: Wordlist Scanning",
                            "remediation": (
                                "Review robots.txt entries. Sensitive paths "
                                "should be protected with authentication, "
                                "not just hidden from crawlers."
                            ),
                        })
                        break

        if sitemap_urls:
            print_key_value(f"  Sitemap URLs", f"{len(sitemap_urls)} pages found")

        # Summary
        print_key_value(f"\n  Paths Checked", f"{checked}")
        print_key_value(f"  Accessible", f"{len(accessible_paths)}")
        print_key_value(f"  Findings", f"{len(findings)}")
        if filtered_soft404 > 0:
            console.print(
                f"  [green]\u2713 Filtered {filtered_soft404} soft-404 "
                f"false positives[/green]"
            )

        results = {
            "domain": target,
            "accessible_paths": accessible_paths,
            "robots_entries": robots_entries,
            "sitemap_url_count": len(sitemap_urls),
            "findings": findings,
            "paths_checked": checked,
            "soft_404_filtered": filtered_soft404,
        }

        return results

    def _get_baseline_fingerprints(self, base_url, headers):
        """Request random non-existent paths to fingerprint the 404 response.

        Makes multiple requests with different random paths to build a
        reliable baseline. Some servers return slightly different pages
        each time, so we capture multiple samples.
        """
        fingerprints = []

        for _ in range(3):
            random_path = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=12
            ))
            random_url = f"{base_url}/{random_path}_not_exist_{random.randint(1000,9999)}"

            try:
                resp = requests.get(
                    random_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=headers,
                    verify=False,
                )

                # Only fingerprint if server returns 200 (custom error page)
                # or 404 (standard). If 301/302/403, different behavior.
                if resp.status_code in (200, 404):
                    fp = fingerprint_response(resp)
                    # Deduplicate by hash
                    if not any(fp.content_hash == existing.content_hash for existing in fingerprints):
                        fingerprints.append(fp)

            except Exception:
                continue

        return fingerprints

    def _parse_robots(self, content):
        """Extract disallowed paths from robots.txt."""
        entries = []
        for line in content.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    entries.append(path)
            elif line.lower().startswith("sitemap:"):
                entries.append(f" {line.split(':', 1)[1].strip()}")
        return entries

    def _count_sitemap_urls(self, content):
        """Count URLs in a sitemap."""
        urls = re.findall(r'<loc>(.*?)</loc>', content)
        return urls
