"""
Technology Stack Detection Module

Identifies what technologies a website is running by analyzing HTTP
response headers, HTML content, cookies, and JavaScript references.

No API key required - just analyzes the HTTP response.

Why this matters for pentesting:
- WordPress site? Check for wp-admin, xmlrpc.php, known plugin vulns
- Running PHP 7.2? Look up CVEs for that version
- Using jQuery 2.x? Known XSS vulnerabilities
- React SPA? Test for API endpoint exposure
- Each technology has its own set of known attack vectors
"""
import re
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


# Technology fingerprints - what to look for and where
TECH_SIGNATURES = {
    # CMS Platforms
    "WordPress": {
        "category": "CMS",
        "headers": {"X-Powered-By": r"WordPress"},
        "html": [
            r'wp-content/',
            r'wp-includes/',
            r'<meta name="generator" content="WordPress',
            r'/wp-json/',
            r'wp-emoji-release\.min\.js',
        ],
        "cookies": ["wordpress_", "wp-"],
        "pentest_notes": (
            "Check /wp-admin, /xmlrpc.php, /wp-login.php, "
            "/wp-json/wp/v2/users (user enumeration). "
            "Run WPScan for plugin/theme vulnerabilities."
        ),
    },
    "Drupal": {
        "category": "CMS",
        "headers": {"X-Generator": r"Drupal", "X-Drupal-Cache": r".*"},
        "html": [
            r'sites/default/files',
            r'Drupal\.settings',
            r'<meta name="Generator" content="Drupal',
            r'/core/misc/drupal\.js',
        ],
        "cookies": ["Drupal.visitor", "SSESS"],
        "pentest_notes": (
            "Check /user/login, /admin, /CHANGELOG.txt for version. "
            "Test for Drupalgeddon variants."
        ),
    },
    "Joomla": {
        "category": "CMS",
        "headers": {},
        "html": [
            r'/media/system/js/',
            r'<meta name="generator" content="Joomla',
            r'/administrator/',
            r'com_content',
        ],
        "cookies": [],
        "pentest_notes": (
            "Check /administrator/, /configuration.php~, "
            "/README.txt for version info."
        ),
    },
    "Shopify": {
        "category": "E-Commerce",
        "headers": {"X-ShopId": r".*", "X-Shopify-Stage": r".*"},
        "html": [
            r'cdn\.shopify\.com',
            r'Shopify\.theme',
            r'myshopify\.com',
        ],
        "cookies": ["_shopify"],
        "pentest_notes": (
            "Hosted platform - limited server-side testing. "
            "Focus on GraphQL API, checkout flow, and custom scripts."
        ),
    },
    "Wix": {
        "category": "Website Builder",
        "headers": {"X-Wix-Request-Id": r".*"},
        "html": [
            r'static\.wixstatic\.com',
            r'wix-code-sdk',
            r'_wix_browser_sess',
        ],
        "cookies": [],
        "pentest_notes": "Hosted platform. Focus on Wix APIs and custom code.",
    },
    "Squarespace": {
        "category": "Website Builder",
        "headers": {},
        "html": [
            r'squarespace\.com',
            r'static1\.squarespace\.com',
            r'Squarespace\.afterBodyLoad',
        ],
        "cookies": ["SS_MID"],
        "pentest_notes": "Hosted platform. Limited attack surface.",
    },

    # Web Servers
    "Nginx": {
        "category": "Web Server",
        "headers": {"Server": r"nginx"},
        "html": [],
        "cookies": [],
        "pentest_notes": (
            "Check for version-specific CVEs. Test for misconfigured "
            "alias traversal, off-by-slash issues."
        ),
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"Server": r"Apache"},
        "html": [],
        "cookies": [],
        "pentest_notes": (
            "Check for mod_status (/server-status), mod_info, "
            ".htaccess bypass, version-specific CVEs."
        ),
    },
    "IIS": {
        "category": "Web Server",
        "headers": {"Server": r"Microsoft-IIS"},
        "html": [],
        "cookies": [],
        "pentest_notes": (
            "Check for short filename enumeration (tilde ~), "
            "WebDAV, trace/track methods, .aspx test files."
        ),
    },
    "Cloudflare": {
        "category": "CDN/WAF",
        "headers": {"Server": r"cloudflare", "CF-RAY": r".*"},
        "html": [],
        "cookies": ["__cf_bm", "__cflb", "cf_clearance"],
        "pentest_notes": (
            "Site is behind Cloudflare WAF/CDN. Direct IP may be "
            "different. Check for origin IP leaks in DNS history, "
            "email headers, or certificate transparency logs."
        ),
    },

    # Backend Technologies
    "PHP": {
        "category": "Backend",
        "headers": {"X-Powered-By": r"PHP"},
        "html": [r'\.php[\?\s"\']'],
        "cookies": ["PHPSESSID"],
        "pentest_notes": (
            "Check for phpinfo(), exposed .php files, "
            "file inclusion vulnerabilities, type juggling."
        ),
    },
    "ASP.NET": {
        "category": "Backend",
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"},
        "html": [r'__VIEWSTATE', r'__EVENTVALIDATION', r'\.aspx'],
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "pentest_notes": (
            "Check for ViewState deserialization, padding oracle, "
            "trace.axd, elmah.axd, exposed web.config."
        ),
    },
    "Express/Node.js": {
        "category": "Backend",
        "headers": {"X-Powered-By": r"Express"},
        "html": [],
        "cookies": ["connect.sid"],
        "pentest_notes": (
            "Check for prototype pollution, SSRF, NoSQL injection "
            "if using MongoDB, exposed package.json or .env."
        ),
    },

    # JavaScript Frameworks
    "React": {
        "category": "Frontend Framework",
        "headers": {},
        "html": [
            r'react\.production\.min\.js',
            r'data-reactroot',
            r'__NEXT_DATA__',
            r'_react[A-Z]',
            r'reactjs\.org',
        ],
        "cookies": [],
        "pentest_notes": (
            "Single Page App - check for exposed API endpoints, "
            "source maps (.map files), hardcoded API keys in JS bundles."
        ),
    },
    "Next.js": {
        "category": "Frontend Framework",
        "headers": {"X-Next-Page": r".*", "X-Nextjs-Page": r".*"},
        "html": [
            r'__NEXT_DATA__',
            r'_next/static',
            r'/_next/',
        ],
        "cookies": [],
        "pentest_notes": (
            "Check /_next/data/ for API routes, "
            "exposed getServerSideProps data, source maps."
        ),
    },
    "Vue.js": {
        "category": "Frontend Framework",
        "headers": {},
        "html": [
            r'vue\.runtime\.min\.js',
            r'vue\.min\.js',
            r'data-v-[a-f0-9]',
            r'__vue__',
        ],
        "cookies": [],
        "pentest_notes": "SPA - check for exposed API endpoints and source maps.",
    },
    "jQuery": {
        "category": "JavaScript Library",
        "headers": {},
        "html": [
            r'jquery[.-](\d+\.\d+[\.\d]*)',
            r'jquery\.min\.js',
            r'code\.jquery\.com',
        ],
        "cookies": [],
        "pentest_notes": (
            "Check jQuery version. Versions before 3.5.0 have known "
            "XSS vulnerabilities. Look for DOM-based XSS via $.html()."
        ),
    },

    # Analytics/Marketing
    "Google Analytics": {
        "category": "Analytics",
        "headers": {},
        "html": [
            r'google-analytics\.com/analytics\.js',
            r'googletagmanager\.com',
            r'gtag\(',
            r'UA-\d+-\d+',
            r'G-[A-Z0-9]+',
        ],
        "cookies": ["_ga", "_gid"],
        "pentest_notes": "Tracking ID can be used for OSINT correlation.",
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "headers": {},
        "html": [
            r'googletagmanager\.com/gtm\.js',
            r'GTM-[A-Z0-9]+',
        ],
        "cookies": [],
        "pentest_notes": (
            "GTM containers can sometimes be inspected for data layer "
            "info and custom event triggers."
        ),
    },
}


@register_module
class TechDetectModule(BaseModule):
    name = "techdetect"
    description = "Technology stack detection and fingerprinting"
    requires_api_key = False
    mode = "active"

    def run(self, target: str) -> dict:
        print_section("Technology Stack Detection", "🔬")

        # Fetch the page
        urls = [f"https://{target}", f"http://{target}"]
        response = None
        used_url = None

        for url in urls:
            try:
                print_progress(f"Fetching {url}")
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
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue

        if not response:
            print_error(f"Could not connect to {target}")
            return {"error": f"Connection failed for {target}"}

        detected = []
        findings = []
        html_body = response.text
        resp_headers = response.headers
        cookie_names = [c.name for c in response.cookies]

        for tech_name, tech_info in TECH_SIGNATURES.items():
            matched = False
            match_sources = []

            # Check headers
            for header_name, pattern in tech_info.get("headers", {}).items():
                header_val = resp_headers.get(header_name, "")
                if header_val and re.search(pattern, header_val, re.IGNORECASE):
                    matched = True
                    match_sources.append(f"header:{header_name}")

            # Check HTML content
            for pattern in tech_info.get("html", []):
                if re.search(pattern, html_body, re.IGNORECASE):
                    matched = True
                    match_sources.append("html")
                    break  # One HTML match is enough

            # Check cookies
            for cookie_prefix in tech_info.get("cookies", []):
                for cn in cookie_names:
                    if cn.startswith(cookie_prefix) or cn == cookie_prefix:
                        matched = True
                        match_sources.append(f"cookie:{cn}")
                        break

            if matched:
                version = self._extract_version(
                    tech_name, resp_headers, html_body
                )
                detected.append({
                    "name": tech_name,
                    "category": tech_info["category"],
                    "version": version,
                    "detected_via": list(set(match_sources)),
                    "pentest_notes": tech_info["pentest_notes"],
                })

        # Display results
        if detected:
            # Group by category
            categories = {}
            for tech in detected:
                cat = tech["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(tech)

            for category, techs in categories.items():
                print_key_value(f"\n  {category}", "")
                for tech in techs:
                    version_str = f" {tech['version']}" if tech["version"] else ""
                    via = ", ".join(tech["detected_via"])
                    from rich.console import Console
                    Console().print(
                        f"    [cyan]{tech['name']}{version_str}[/cyan] "
                        f"[dim](via {via})[/dim]"
                    )
                    if tech["pentest_notes"]:
                        Console().print(
                            f"      [yellow]→ {tech['pentest_notes']}[/yellow]"
                        )

            # Generate findings for version disclosures
            for tech in detected:
                if tech["version"]:
                    findings.append({
                        "severity": "low",
                        "title": (
                            f"Technology Detected: {tech['name']} "
                            f"{tech['version']}"
                        ),
                        "detail": (
                            f"{tech['name']} version {tech['version']} "
                            f"was identified via {', '.join(tech['detected_via'])}. "
                            f"Version information helps attackers identify "
                            f"known vulnerabilities."
                        ),
                        "owasp": "A05:2021 Security Misconfiguration",
                        "mitre": (
                            "T1592.002 - Gather Victim Host Information: Software"
                        ),
                        "remediation": (
                            f"Suppress version information for {tech['name']} "
                            f"in server configuration where possible."
                        ),
                    })

        else:
            print_key_value("Result", "No technologies confidently identified")

        # Check for interesting paths
        interesting_paths = self._check_paths(target, response)

        results = {
            "domain": target,
            "url": used_url,
            "technologies": detected,
            "tech_count": len(detected),
            "interesting_paths": interesting_paths,
            "findings": findings,
        }

        return results

    def _extract_version(self, tech_name, headers, html):
        """Try to extract version numbers from headers or HTML."""
        version = ""

        # Check Server header for version
        server = headers.get("Server", "")
        if tech_name in ("Nginx", "Apache", "IIS"):
            match = re.search(r'[\d]+\.[\d]+\.?[\d]*', server)
            if match:
                version = match.group()

        # Check X-Powered-By for version
        powered_by = headers.get("X-Powered-By", "")
        if tech_name == "PHP" and "PHP" in powered_by:
            match = re.search(r'PHP/([\d]+\.[\d]+\.?[\d]*)', powered_by)
            if match:
                version = match.group(1)
        elif tech_name == "ASP.NET" and "ASP.NET" in powered_by:
            aspnet_ver = headers.get("X-AspNet-Version", "")
            if aspnet_ver:
                version = aspnet_ver

        # Check HTML for jQuery version
        if tech_name == "jQuery":
            match = re.search(
                r'jquery[.-]([\d]+\.[\d]+\.[\d]+)', html, re.IGNORECASE
            )
            if match:
                version = match.group(1)

        # WordPress version from meta generator
        if tech_name == "WordPress":
            match = re.search(
                r'content="WordPress ([\d.]+)"', html, re.IGNORECASE
            )
            if match:
                version = match.group(1)

        return version

    def _check_paths(self, target, response):
        """Check for interesting paths revealed in the HTML."""
        interesting = []
        html = response.text

        # Look for common interesting paths in links and references
        path_patterns = {
            r'/robots\.txt': "Robots.txt (may reveal hidden paths)",
            r'/sitemap\.xml': "Sitemap (reveals site structure)",
            r'/\.git': "Git repository potentially exposed",
            r'/\.env': "Environment file potentially exposed",
            r'/wp-admin': "WordPress admin panel",
            r'/wp-login\.php': "WordPress login",
            r'/administrator': "Joomla admin panel",
            r'/admin': "Admin panel",
            r'/api/': "API endpoint",
            r'/graphql': "GraphQL endpoint",
            r'/swagger': "Swagger API documentation",
            r'/api-docs': "API documentation",
            r'/phpinfo': "PHP info page",
            r'/server-status': "Apache server status",
            r'/debug': "Debug endpoint",
        }

        for pattern, description in path_patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                interesting.append({
                    "path": pattern.replace("\\", ""),
                    "description": description,
                })

        if interesting:
            print_key_value(f"\n  Interesting Paths Found", "")
            for item in interesting:
                from rich.console import Console
                Console().print(
                    f"    [yellow]→ {item['path']}[/yellow] "
                    f"[dim]({item['description']})[/dim]"
                )

        return interesting
