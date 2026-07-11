"""
HTTP Security Header Analyzer Module

Checks a target's HTTP response headers for security misconfigurations.
This is Level 2 recon - it tells you what security controls are missing,
which directly maps to what you should test during a pentest.

No API key required - just makes a standard HTTP request.

Every missing header is a potential finding in your report and a real
attack vector. For example:
- Missing Content-Security-Policy = potential XSS
- Missing X-Frame-Options = clickjacking possible
- Server header leaking version = version-specific CVE lookup
"""
import requests
from bssrecon.core import BaseModule, register_module
from bssrecon.utils.display import (
    print_section,
    print_finding,
    print_key_value,
    print_error,
    print_progress,
    print_table,
    print_warning,
)


# Security headers we check for and what they mean
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "severity_if_missing": "high",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1557 - Adversary-in-the-Middle",
        "risk": (
            "Without HSTS, users can be downgraded to HTTP and intercepted "
            "via man-in-the-middle attacks. Attackers on the same network "
            "can strip SSL and see all traffic in plain text."
        ),
        "remediation": (
            "Add the Strict-Transport-Security header with a minimum "
            "max-age of 31536000 (1 year). Consider adding includeSubDomains "
            "and preload directives."
        ),
    },
    "Content-Security-Policy": {
        "description": "Controls resource loading to prevent XSS",
        "severity_if_missing": "high",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "risk": (
            "Without CSP, the application is more vulnerable to Cross-Site "
            "Scripting (XSS) attacks. Attackers can inject malicious scripts "
            "that steal session tokens, credentials, or redirect users."
        ),
        "remediation": (
            "Implement a Content-Security-Policy header. Start with a "
            "report-only policy to identify issues, then enforce. "
            "At minimum, set default-src 'self' and restrict script-src."
        ),
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding",
        "severity_if_missing": "medium",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1189 - Drive-by Compromise",
        "risk": (
            "Without X-Frame-Options, the site can be embedded in an "
            "iframe on a malicious page. Attackers can overlay invisible "
            "frames to trick users into clicking hidden buttons "
            "(clickjacking)."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN. Also consider "
            "using the frame-ancestors directive in Content-Security-Policy."
        ),
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity_if_missing": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1203 - Exploitation for Client Execution",
        "risk": (
            "Without nosniff, browsers may interpret files as a different "
            "MIME type than declared, potentially executing malicious "
            "content disguised as harmless file types."
        ),
        "remediation": "Set X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (older browsers)",
        "severity_if_missing": "info",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059.007 - Command and Scripting Interpreter: JavaScript",
        "risk": (
            "While modern browsers have deprecated this header in favor "
            "of CSP, older browsers may still benefit from it."
        ),
        "remediation": "Set X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity_if_missing": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1557 - Adversary-in-the-Middle",
        "risk": (
            "Without a Referrer-Policy, the full URL including query "
            "parameters may be leaked to third-party sites. This can "
            "expose session tokens or sensitive data in URLs."
        ),
        "remediation": (
            "Set Referrer-Policy to strict-origin-when-cross-origin "
            "or no-referrer."
        ),
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, etc)",
        "severity_if_missing": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1189 - Drive-by Compromise",
        "risk": (
            "Without Permissions-Policy, embedded content may access "
            "browser features like camera, microphone, or geolocation "
            "without explicit restriction."
        ),
        "remediation": (
            "Set Permissions-Policy to disable unused features. "
            "Example: camera=(), microphone=(), geolocation=()"
        ),
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls Flash/PDF cross-domain access",
        "severity_if_missing": "info",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1189 - Drive-by Compromise",
        "risk": "Flash/Acrobat may load data across domains without restriction.",
        "remediation": "Set X-Permitted-Cross-Domain-Policies: none",
    },
}

# Headers that leak information when present
INFORMATION_LEAK_HEADERS = {
    "Server": {
        "description": "May leak web server software and version",
        "severity": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
    "X-Powered-By": {
        "description": "Leaks backend technology (PHP, ASP.NET, etc)",
        "severity": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
    "X-AspNet-Version": {
        "description": "Leaks ASP.NET framework version",
        "severity": "medium",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
    "X-AspNetMvc-Version": {
        "description": "Leaks ASP.NET MVC version",
        "severity": "medium",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
    "X-Generator": {
        "description": "Leaks CMS or site generator",
        "severity": "low",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
}


@register_module
class HeadersModule(BaseModule):
    name = "headers"
    description = "HTTP security header analysis"
    requires_api_key = False
    mode = "active"

    def run(self, target: str) -> dict:
        print_section("HTTP Security Headers", "🛡️")

        findings = []
        headers_present = {}
        headers_missing = []

        # Try HTTPS first, fall back to HTTP
        urls = [f"https://{target}", f"http://{target}"]
        response = None
        used_url = None

        for url in urls:
            try:
                print_progress(f"Requesting {url}")
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={
                        "User-Agent": self.config.get("scan", {}).get(
                            "user_agent", "BSS-Recon/1.0"
                        )
                    },
                )
                used_url = url
                break
            except requests.exceptions.SSLError:
                print_warning(f"SSL error on {url}, trying HTTP...")
                continue
            except requests.exceptions.ConnectionError:
                print_warning(f"Connection failed on {url}")
                continue
            except requests.exceptions.Timeout:
                print_warning(f"Timeout on {url}")
                continue

        if not response:
            print_error(f"Could not connect to {target} on HTTP or HTTPS")
            return {"error": f"Connection failed for {target}"}

        print_key_value("URL", used_url)
        print_key_value("Status Code", response.status_code)
        print_key_value("Final URL", response.url)

        # Check if HTTP redirects to HTTPS
        if used_url.startswith("http://") and response.url.startswith("https://"):
            print_key_value("HTTP->HTTPS Redirect", "✓ Yes")
        elif used_url.startswith("http://"):
            findings.append({
                "severity": "high",
                "title": "No HTTP to HTTPS Redirect",
                "detail": (
                    "The site does not redirect HTTP to HTTPS. Users "
                    "accessing via HTTP are not protected by encryption."
                ),
                "owasp": "A02:2021 Cryptographic Failures",
                "mitre": "T1557 - Adversary-in-the-Middle",
                "remediation": (
                    "Configure the web server to redirect all HTTP "
                    "requests to HTTPS with a 301 permanent redirect."
                ),
            })
            print_finding("high", "No HTTP to HTTPS Redirect",
                         "Users on HTTP are unprotected")

        resp_headers = response.headers

        # Check for missing security headers
        print_key_value("\n  Security Headers", "")
        for header_name, header_info in SECURITY_HEADERS.items():
            value = resp_headers.get(header_name)
            if value:
                headers_present[header_name] = value
                from rich.console import Console
                Console().print(
                    f"    [green]✓ {header_name}:[/green] "
                    f"[dim]{value[:80]}[/dim]"
                )
            else:
                headers_missing.append(header_name)
                severity = header_info["severity_if_missing"]
                from rich.console import Console
                Console().print(
                    f"    [red]✗ {header_name}[/red] "
                    f"[dim]({header_info['description']})[/dim]"
                )
                findings.append({
                    "severity": severity,
                    "title": f"Missing {header_name} Header",
                    "detail": header_info["risk"],
                    "owasp": header_info["owasp"],
                    "mitre": header_info["mitre"],
                    "remediation": header_info["remediation"],
                })

        # Check for information leaking headers
        print_key_value("\n  Information Disclosure", "")
        leaked_info = {}
        for header_name, header_info in INFORMATION_LEAK_HEADERS.items():
            value = resp_headers.get(header_name)
            if value:
                leaked_info[header_name] = value
                from rich.console import Console
                Console().print(
                    f"    [yellow]⚠ {header_name}:[/yellow] "
                    f"[white]{value}[/white] "
                    f"[dim]({header_info['description']})[/dim]"
                )
                findings.append({
                    "severity": header_info["severity"],
                    "title": f"Information Disclosure: {header_name}",
                    "detail": (
                        f"The {header_name} header exposes: {value}. "
                        f"{header_info['description']}."
                    ),
                    "owasp": header_info["owasp"],
                    "mitre": header_info["mitre"],
                    "remediation": (
                        f"Remove or suppress the {header_name} header "
                        f"in the web server configuration."
                    ),
                })
            else:
                from rich.console import Console
                Console().print(
                    f"    [green]✓ {header_name} not exposed[/green]"
                )

        # Check for cookies without security flags
        cookie_findings = self._check_cookies(response)
        findings.extend(cookie_findings)

        # Score the security posture
        total_headers = len(SECURITY_HEADERS)
        present_count = len(headers_present)
        score = round((present_count / total_headers) * 100)

        print_key_value(
            f"\n  Header Security Score",
            f"{score}% ({present_count}/{total_headers} headers present)"
        )

        results = {
            "domain": target,
            "url": used_url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers_present": headers_present,
            "headers_missing": headers_missing,
            "information_disclosure": leaked_info,
            "security_score": score,
            "findings": findings,
            "all_headers": dict(resp_headers),
        }

        return results

    def _check_cookies(self, response):
        """Check cookies for missing security flags."""
        findings = []
        cookies = response.cookies

        if not cookies:
            return findings

        print_key_value("\n  Cookie Security", "")

        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                # Check raw Set-Cookie header for HttpOnly
                set_cookie = response.headers.get("Set-Cookie", "")
                if "httponly" not in set_cookie.lower():
                    issues.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                set_cookie = response.headers.get("Set-Cookie", "")
                if "samesite" not in set_cookie.lower():
                    issues.append("Missing SameSite flag")

            if issues:
                from rich.console import Console
                Console().print(
                    f"    [yellow]⚠ Cookie '{cookie.name}':[/yellow] "
                    f"{', '.join(issues)}"
                )
                findings.append({
                    "severity": "medium",
                    "title": f"Insecure Cookie: {cookie.name}",
                    "detail": (
                        f"Cookie '{cookie.name}' is missing: "
                        f"{', '.join(issues)}. This may allow session "
                        f"hijacking or cross-site attacks."
                    ),
                    "owasp": "A05:2021 Security Misconfiguration",
                    "mitre": "T1539 - Steal Web Session Cookie",
                    "remediation": (
                        "Set Secure, HttpOnly, and SameSite=Strict (or Lax) "
                        "flags on all session cookies."
                    ),
                })
            else:
                from rich.console import Console
                Console().print(
                    f"    [green]✓ Cookie '{cookie.name}' - properly secured[/green]"
                )

        return findings
