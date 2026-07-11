"""
JavaScript Analyzer Module

Fetches and analyzes JavaScript files from the target to extract:
- API endpoints and routes
- Hardcoded API keys, tokens, and secrets
- Hidden admin/debug functionality
- Internal URLs and IPs
- Cloud storage buckets (S3, GCS, Azure)
- Comments with sensitive info

No API key required.

This is the #1 technique that separates top bug bounty hunters
from beginners. Every SPA (React, Vue, Angular) bundles its
API routes and sometimes secrets right in the JavaScript.
Companies deploy code and forget that everything in client-side
JS is visible to anyone who reads the source.
"""
import re
import requests
from urllib.parse import urljoin, urlparse
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


# Patterns to search for in JavaScript files
SECRET_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws_secret_access_key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth Token": r'ya29\.[0-9A-Za-z\-_]+',
    "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    "Basic Auth": r'(?i)basic\s+[a-zA-Z0-9+/]+=*',
    "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
    "Twilio API Key": r'SK[0-9a-fA-F]{32}',
    "Square Access Token": r'sq0atp-[0-9A-Za-z\-_]{22}',
    "Stripe Key": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
    "Heroku API Key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "SendGrid API Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
}

ENDPOINT_PATTERNS = [
    r'["\'](/api/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/graphql[a-zA-Z0-9_/\-]*)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/auth/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/admin/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/internal/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/debug/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/private/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/hidden/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/test/[a-zA-Z0-9_/\-{}]+)["\']',
    r'["\'](/staging/[a-zA-Z0-9_/\-{}]+)["\']',
    r'(?:fetch|axios|xhr|ajax)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[=:]\s*["\']([^"\']+)["\']',
]

CLOUD_BUCKET_PATTERNS = {
    "AWS S3 Bucket": r'[a-zA-Z0-9.-]+\.s3\.amazonaws\.com',
    "AWS S3 Path": r's3://[a-zA-Z0-9.\-_]+',
    "Google Cloud Storage": r'storage\.googleapis\.com/[a-zA-Z0-9.\-_]+',
    "Azure Blob Storage": r'[a-zA-Z0-9]+\.blob\.core\.windows\.net',
    "Firebase Storage": r'firebasestorage\.googleapis\.com/[^\s"\']+',
}

INTERNAL_PATTERNS = {
    "Internal IP": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    "Internal URL": r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|intranet|staging|dev|test)[^\s"\']*',
    "Hardcoded Password": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
    "Hardcoded Secret": r'(?i)(?:secret|token|apikey|api_key)\s*[=:]\s*["\']([^"\']{8,})["\']',
}


@register_module
class JsAnalyzerModule(BaseModule):
    name = "jsanalyze"
    description = "JavaScript file analysis (API endpoints, secrets, hidden routes)"
    requires_api_key = False
    mode = "active"

    def run(self, target: str) -> dict:
        print_section("JavaScript Analysis", "📜")

        findings = []
        all_endpoints = set()
        all_secrets = []
        all_buckets = []
        all_internals = []
        js_files_found = []

        # First, get the main page HTML to find JS files
        base_url = f"https://{target}"
        try:
            print_progress(f"Fetching {base_url} to discover JS files")
            resp = requests.get(
                base_url,
                timeout=self.timeout,
                headers={
                    "User-Agent": self.config.get("scan", {}).get(
                        "user_agent", "BSS-Recon/1.0"
                    )
                },
            )
            html = resp.text
        except Exception as e:
            print_error(f"Could not fetch {base_url}: {str(e)}")
            return {"error": str(e), "domain": target}

        # Extract JS file URLs from HTML
        js_urls = set()

        # Script src attributes
        src_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            js_url = match.group(1)
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = urljoin(base_url, js_url)
            elif not js_url.startswith("http"):
                js_url = urljoin(base_url, js_url)
            js_urls.add(js_url)

        # Also check for inline scripts with interesting content
        inline_scripts = re.findall(
            r'<script[^>]*>(.*?)</script>', html, re.DOTALL
        )

        print_key_value("JS Files Found", len(js_urls))
        print_key_value("Inline Scripts", len(inline_scripts))

        # Analyze each JS file
        for js_url in list(js_urls)[:20]:  # Cap at 20 files
            try:
                parsed = urlparse(js_url)
                filename = parsed.path.split("/")[-1]

                # Skip common third-party libraries
                skip_patterns = [
                    "jquery", "bootstrap", "font-awesome", "google",
                    "analytics", "gtm", "facebook", "twitter",
                    "recaptcha", "cloudflare", "cdn.jsdelivr",
                    "cdnjs.cloudflare", "unpkg.com",
                ]
                if any(s in js_url.lower() for s in skip_patterns):
                    continue

                resp = requests.get(
                    js_url,
                    timeout=self.timeout,
                    headers={
                        "User-Agent": self.config.get("scan", {}).get(
                            "user_agent", "BSS-Recon/1.0"
                        )
                    },
                )
                js_content = resp.text
                js_size = len(js_content)

                if js_size < 100:
                    continue

                js_files_found.append({
                    "url": js_url,
                    "size": js_size,
                    "filename": filename,
                })

                # Search for secrets
                for secret_name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        secret_val = match if isinstance(match, str) else match
                        # Mask the secret for display
                        masked = secret_val[:8] + "..." if len(secret_val) > 8 else secret_val
                        all_secrets.append({
                            "type": secret_name,
                            "value_masked": masked,
                            "file": filename,
                            "url": js_url,
                        })

                # Search for API endpoints
                for pattern in ENDPOINT_PATTERNS:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if len(match) > 3 and not match.endswith(".js"):
                            all_endpoints.add(match)

                # Search for cloud buckets
                for bucket_type, pattern in CLOUD_BUCKET_PATTERNS.items():
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        all_buckets.append({
                            "type": bucket_type,
                            "value": match,
                            "file": filename,
                        })

                # Search for internal references
                for ref_type, pattern in INTERNAL_PATTERNS.items():
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        val = match if isinstance(match, str) else match
                        all_internals.append({
                            "type": ref_type,
                            "value": val,
                            "file": filename,
                        })

            except Exception:
                continue

        # Also analyze inline scripts
        for script in inline_scripts:
            if len(script.strip()) < 50:
                continue

            for pattern in ENDPOINT_PATTERNS:
                matches = re.findall(pattern, script)
                for match in matches:
                    if len(match) > 3:
                        all_endpoints.add(match)

            for secret_name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, script)
                for match in matches:
                    masked = match[:8] + "..." if len(match) > 8 else match
                    all_secrets.append({
                        "type": secret_name,
                        "value_masked": masked,
                        "file": "inline",
                    })

        # Display results
        if js_files_found:
            print_key_value(f"\n  JS Files Analyzed", f"{len(js_files_found)}")
            for jsf in js_files_found:
                size_kb = round(jsf["size"] / 1024, 1)
                from rich.console import Console
                Console().print(
                    f"    [dim]{jsf['filename']} ({size_kb}KB)[/dim]"
                )

        if all_endpoints:
            sorted_endpoints = sorted(all_endpoints)
            print_key_value(
                f"\n  API Endpoints Discovered",
                f"({len(sorted_endpoints)})"
            )
            for ep in sorted_endpoints[:30]:
                from rich.console import Console
                Console().print(f"    [cyan]{ep}[/cyan]")

            findings.append({
                "severity": "info",
                "title": f"{len(sorted_endpoints)} API Endpoints Found in JavaScript",
                "detail": (
                    f"Analysis of JavaScript files revealed "
                    f"{len(sorted_endpoints)} API endpoints. These should "
                    f"be tested for authentication, authorization, and "
                    f"injection vulnerabilities."
                ),
                "owasp": "A01:2021 Broken Access Control",
                "mitre": "T1190 - Exploit Public-Facing Application",
                "remediation": (
                    "Review all discovered API endpoints for proper "
                    "authentication and authorization controls."
                ),
            })

            if len(sorted_endpoints) > 30:
                from rich.console import Console
                Console().print(
                    f"    [dim]... and {len(sorted_endpoints) - 30} more "
                    f"(see JSON output)[/dim]"
                )

        if all_secrets:
            print_key_value(
                f"\n  ⚠ Potential Secrets Found",
                f"({len(all_secrets)})"
            )
            for secret in all_secrets:
                from rich.console import Console
                Console().print(
                    f"    [red]⚠ {secret['type']}:[/red] "
                    f"[yellow]{secret['value_masked']}[/yellow] "
                    f"[dim](in {secret['file']})[/dim]"
                )

            findings.append({
                "severity": "critical",
                "title": f"Potential Secrets Exposed in JavaScript ({len(all_secrets)})",
                "detail": (
                    f"JavaScript analysis found {len(all_secrets)} "
                    f"potential secrets including API keys, tokens, or "
                    f"credentials embedded in client-side code."
                ),
                "owasp": "A02:2021 Cryptographic Failures",
                "mitre": "T1552.001 - Unsecured Credentials: Credentials In Files",
                "remediation": (
                    "Remove all secrets from client-side JavaScript. "
                    "Use server-side environment variables and proxy "
                    "API calls through your backend."
                ),
            })

        if all_buckets:
            print_key_value(
                f"\n  Cloud Storage References",
                f"({len(all_buckets)})"
            )
            for bucket in all_buckets:
                from rich.console import Console
                Console().print(
                    f"    [yellow]{bucket['type']}:[/yellow] "
                    f"{bucket['value']} [dim](in {bucket['file']})[/dim]"
                )

            findings.append({
                "severity": "medium",
                "title": f"Cloud Storage Buckets Found in JavaScript",
                "detail": (
                    f"Found {len(all_buckets)} cloud storage references. "
                    f"These should be checked for public access and "
                    f"misconfigured permissions."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1530 - Data from Cloud Storage",
                "remediation": (
                    "Verify all cloud storage buckets have proper "
                    "access controls and are not publicly accessible."
                ),
            })

        if all_internals:
            print_key_value(
                f"\n  Internal References",
                f"({len(all_internals)})"
            )
            for ref in all_internals[:10]:
                from rich.console import Console
                Console().print(
                    f"    [yellow]{ref['type']}:[/yellow] "
                    f"{ref['value']} [dim](in {ref['file']})[/dim]"
                )

        if not all_endpoints and not all_secrets and not all_buckets:
            print_key_value(
                "Result",
                "No significant findings in JavaScript analysis"
            )

        results = {
            "domain": target,
            "js_files_analyzed": len(js_files_found),
            "js_files": js_files_found,
            "endpoints": sorted(all_endpoints),
            "endpoint_count": len(all_endpoints),
            "secrets": all_secrets,
            "secret_count": len(all_secrets),
            "cloud_buckets": all_buckets,
            "internal_references": all_internals,
            "findings": findings,
        }

        return results
