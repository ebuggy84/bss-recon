"""
OWASP Top 10 (2021) Framework Mapping

Maps findings to OWASP categories. Used by modules to tag their findings
and by the report generator to organize results by OWASP category.

Reference: https://owasp.org/Top10/
"""

OWASP_TOP_10 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "description": (
            "Access control enforces policy such that users cannot act outside "
            "of their intended permissions. Failures typically lead to "
            "unauthorized information disclosure, modification, or destruction "
            "of data, or performing a business function outside the user's limits."
        ),
        "cwe_examples": ["CWE-200", "CWE-201", "CWE-352", "CWE-639"],
        "test_checks": [
            "IDOR (Insecure Direct Object References)",
            "Missing function-level access controls",
            "CORS misconfiguration",
            "Elevation of privilege",
            "Metadata manipulation (JWT, cookies)",
            "Force browsing to authenticated pages",
            "API missing access controls for POST/PUT/DELETE",
            "Multi-tenant isolation bypass",
        ],
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "description": (
            "Failures related to cryptography (or lack thereof) which often "
            "lead to exposure of sensitive data."
        ),
        "cwe_examples": ["CWE-259", "CWE-327", "CWE-331"],
        "test_checks": [
            "Data transmitted in clear text (HTTP)",
            "Weak/old cryptographic algorithms",
            "Default or weak crypto keys",
            "Missing certificate validation",
            "Weak SSL/TLS protocols (TLSv1.0, SSLv3)",
            "Passwords stored in plain text or weak hashes",
            "Missing encryption at rest",
            "Weak random number generation",
        ],
    },
    "A03:2021": {
        "name": "Injection",
        "description": (
            "An application is vulnerable to injection when user-supplied data "
            "is not validated, filtered, or sanitized by the application."
        ),
        "cwe_examples": ["CWE-79", "CWE-89", "CWE-73"],
        "test_checks": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "LDAP Injection",
            "XPath Injection",
            "NoSQL Injection",
            "Template Injection (SSTI)",
            "Header Injection",
        ],
    },
    "A04:2021": {
        "name": "Insecure Design",
        "description": (
            "Insecure design is a broad category representing different "
            "weaknesses expressed as missing or ineffective control design."
        ),
        "cwe_examples": ["CWE-209", "CWE-256", "CWE-501"],
        "test_checks": [
            "Missing rate limiting",
            "Business logic flaws",
            "Missing anti-automation",
            "Trust boundary violations",
            "Insufficient threat modeling",
            "Missing security controls in user stories",
        ],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "description": (
            "The application might be vulnerable if missing appropriate "
            "security hardening, unnecessary features enabled, default "
            "accounts/passwords unchanged, error handling revealing info."
        ),
        "cwe_examples": ["CWE-16", "CWE-611"],
        "test_checks": [
            "Default credentials",
            "Unnecessary features enabled",
            "Missing security headers",
            "Verbose error messages",
            "Exposed admin interfaces",
            "Directory listing enabled",
            "Missing patches/updates",
            "Cloud storage misconfiguration",
            "SSL certificate issues",
            "Missing DMARC/SPF/DKIM",
        ],
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "description": (
            "Components such as libraries, frameworks, and other software "
            "modules run with the same privileges as the application. If a "
            "vulnerable component is exploited, it can cause serious data "
            "loss or server takeover."
        ),
        "cwe_examples": ["CWE-1104"],
        "test_checks": [
            "Known CVEs in server software",
            "Outdated frameworks/libraries",
            "Unsupported software versions",
            "Missing security patches",
            "Components with known vulnerabilities (Shodan/CVE)",
        ],
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "description": (
            "Confirmation of the user's identity, authentication, and "
            "session management is critical to protect against "
            "authentication-related attacks."
        ),
        "cwe_examples": ["CWE-287", "CWE-384", "CWE-798"],
        "test_checks": [
            "Brute force / credential stuffing",
            "Weak password policies",
            "Missing MFA",
            "Session fixation",
            "Session ID in URL",
            "Password reset flaws",
            "Default credentials",
        ],
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "description": (
            "Software and data integrity failures relate to code and "
            "infrastructure that does not protect against integrity violations."
        ),
        "cwe_examples": ["CWE-829", "CWE-494", "CWE-502"],
        "test_checks": [
            "Insecure deserialization",
            "Unsigned updates/deployments",
            "Untrusted CDN/sources",
            "CI/CD pipeline integrity",
            "Missing Subresource Integrity (SRI)",
        ],
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "description": (
            "Without logging and monitoring, breaches cannot be detected."
        ),
        "cwe_examples": ["CWE-117", "CWE-223", "CWE-778"],
        "test_checks": [
            "Missing audit logs",
            "Logs not monitored",
            "Logs stored locally only",
            "No alerting on suspicious activity",
            "Missing intrusion detection",
        ],
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "SSRF flaws occur whenever a web application fetches a remote "
            "resource without validating the user-supplied URL."
        ),
        "cwe_examples": ["CWE-918"],
        "test_checks": [
            "URL parameter manipulation",
            "Internal service access",
            "Cloud metadata endpoint access",
            "File URL schema abuse",
        ],
    },
}


def get_owasp_category(category_id):
    """Get full details for an OWASP category."""
    return OWASP_TOP_10.get(category_id)


def get_checklist(category_id=None):
    """Get test checklist items for one or all categories."""
    if category_id:
        cat = OWASP_TOP_10.get(category_id, {})
        return cat.get("test_checks", [])

    # Return all checks grouped by category
    all_checks = {}
    for cat_id, cat_data in OWASP_TOP_10.items():
        all_checks[f"{cat_id} {cat_data['name']}"] = cat_data["test_checks"]
    return all_checks


def map_finding_to_owasp(finding_text):
    """
    Attempt to map a finding description to an OWASP category.
    Returns the best matching category ID or None.
    """
    text = finding_text.lower()

    keyword_map = {
        "A01:2021": ["access control", "idor", "authorization", "privilege",
                      "cors", "tenant", "permission"],
        "A02:2021": ["ssl", "tls", "certificate", "encryption", "crypto",
                      "cipher", "hash", "cleartext", "http://"],
        "A03:2021": ["injection", "sqli", "xss", "script", "command inject",
                      "ldap", "xpath", "template inject"],
        "A04:2021": ["rate limit", "business logic", "design flaw",
                      "anti-automation"],
        "A05:2021": ["misconfig", "default", "header", "directory listing",
                      "error message", "verbose", "spf", "dmarc", "dkim",
                      "admin panel", "exposed"],
        "A06:2021": ["cve-", "outdated", "vulnerable component", "patch",
                      "version", "end of life", "eol"],
        "A07:2021": ["authentication", "password", "credential", "brute",
                      "session", "mfa", "login", "reset"],
        "A08:2021": ["deserialization", "integrity", "unsigned", "cdn",
                      "pipeline"],
        "A09:2021": ["logging", "monitoring", "audit", "detection", "alert"],
        "A10:2021": ["ssrf", "server-side request", "metadata", "internal url"],
    }

    for cat_id, keywords in keyword_map.items():
        if any(kw in text for kw in keywords):
            return cat_id

    return None
