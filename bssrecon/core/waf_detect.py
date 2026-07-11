"""
WAF Detection Module — sends canary probes before active scanning to identify
WAF/CDN vendors. Runs as an active module so it only fires when --active is set.
Other active modules (webprobe, jsanalyze) can read the waf result from the
scan context to adapt their behaviour (e.g. slow down, skip payloads).
"""

import time
import requests
from urllib.parse import urljoin

from bssrecon.core import BaseModule, register_module


# Canary paths/payloads that WAFs commonly intercept
_CANARY_PAYLOADS = [
    "/?id=1'%20OR%20'1'='1",          # SQLi canary
    "/<script>alert(1)</script>",       # XSS canary
    "/../../../etc/passwd",             # LFI canary
]

# Header fingerprints: (header_name_lower, value_fragment, vendor_name)
_WAF_HEADER_SIGS: list[tuple[str, str, str]] = [
    ("cf-ray",                      "",              "Cloudflare"),
    ("server",                      "cloudflare",    "Cloudflare"),
    ("x-amzn-requestid",            "",              "AWS WAF"),
    ("x-amz-cf-id",                 "",              "AWS CloudFront"),
    ("x-amz-apigw-id",              "",              "AWS API Gateway"),
    ("x-azure-ref",                 "",              "Azure Front Door"),
    ("x-ms-request-id",             "",              "Azure"),
    ("x-akamai-transformed",        "",              "Akamai"),
    ("x-check-cacheable",           "",              "Akamai"),
    ("x-sucuri-id",                 "",              "Sucuri"),
    ("server",                      "sucuri",        "Sucuri"),
    ("x-fw-hash",                   "",              "Fastly WAF"),
    ("x-served-by",                 "cache-",        "Fastly CDN"),
    ("server",                      "barracuda",     "Barracuda WAF"),
    ("server",                      "f5",            "F5 ASM"),
    ("x-avi-version",               "",              "Avi Networks"),
    ("server",                      "imperva",       "Imperva Incapsula"),
    ("x-iinfo",                     "",              "Imperva Incapsula"),
    ("server",                      "incapsula",     "Imperva Incapsula"),
    ("x-cdn",                       "incapsula",     "Imperva Incapsula"),
    ("server",                      "pepyaka",       "Wix CDN"),
    ("x-wix-dispatcher-cache-hit",  "",              "Wix"),
    ("server",                      "ddos-guard",    "DDoS-Guard"),
    ("x-ddos-protection",           "",              "DDoS-Guard"),
]

# Body fragments that indicate a WAF block page
_WAF_BODY_SIGS: list[tuple[str, str]] = [
    ("cloudflare",          "Cloudflare"),
    ("attention required",  "Cloudflare"),
    ("ray id",              "Cloudflare"),
    ("aws waf",             "AWS WAF"),
    ("request blocked",     "AWS WAF"),
    ("akamai",              "Akamai"),
    ("incapsula incident",  "Imperva Incapsula"),
    ("sucuri website firewall", "Sucuri"),
    ("barracuda networks",  "Barracuda WAF"),
    ("access denied",       "Generic WAF"),
    ("your ip has been blocked", "Generic WAF"),
    ("ddos protection",     "Generic WAF"),
    ("are you a robot",     "Bot Protection"),
]

# Status codes that WAFs commonly return for blocked requests
_BLOCK_CODES = {403, 406, 412, 429, 503}


def _detect_from_headers(headers: dict) -> str | None:
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for name, fragment, vendor in _WAF_HEADER_SIGS:
        value = h_lower.get(name, "")
        if value and (not fragment or fragment in value):
            return vendor
    return None


def _detect_from_body(body: str) -> str | None:
    b_lower = body.lower()
    for fragment, vendor in _WAF_BODY_SIGS:
        if fragment in b_lower:
            return vendor
    return None


@register_module
class WafDetect(BaseModule):
    name = "wafdetect"
    description = "WAF/CDN canary detection before active scanning"
    requires_api_key = False
    api_key_name = None
    mode = "active"

    def run(self, target: str) -> dict:
        base_url = f"https://{target}"
        session = requests.Session()
        session.headers.update(self._request_headers())
        session.verify = False

        vendors_seen: set[str] = set()
        evidence: list[dict] = []
        blocked_count = 0

        # First probe the homepage to get baseline headers
        try:
            resp = session.get(base_url, timeout=10, allow_redirects=True)
            vendor = _detect_from_headers(dict(resp.headers))
            if vendor:
                vendors_seen.add(vendor)
                evidence.append({
                    "probe": "baseline",
                    "url": base_url,
                    "status": resp.status_code,
                    "signal": f"header fingerprint: {vendor}",
                })
        except requests.RequestException:
            pass

        # Send canary payloads and watch for WAF responses
        for payload in _CANARY_PAYLOADS:
            url = urljoin(base_url + "/", payload.lstrip("/"))
            try:
                resp = session.get(url, timeout=8, allow_redirects=False)
                vendor = _detect_from_headers(dict(resp.headers))
                if not vendor and resp.status_code in _BLOCK_CODES:
                    try:
                        body = resp.text[:4000]
                        vendor = _detect_from_body(body)
                    except Exception:
                        body = ""

                if resp.status_code in _BLOCK_CODES:
                    blocked_count += 1

                if vendor:
                    vendors_seen.add(vendor)
                    evidence.append({
                        "probe": payload,
                        "url": url,
                        "status": resp.status_code,
                        "signal": vendor,
                    })
            except requests.RequestException:
                pass

            time.sleep(0.5)

        detected = sorted(vendors_seen)
        waf_present = bool(detected)

        findings = []
        if waf_present:
            vendor_str = ", ".join(detected)
            findings.append({
                "severity": "info",
                "title": f"WAF/CDN Detected: {vendor_str}",
                "detail": (
                    f"Target is behind {vendor_str}. "
                    f"{blocked_count}/{len(_CANARY_PAYLOADS)} canary probes were blocked. "
                    "Active scanning payloads may be filtered — reduce rate and avoid "
                    "signature-heavy probes."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1590.005 - Gather Victim Network Information: IP Addresses",
                "remediation": (
                    "WAF detection is informational. Ensure WAF rules are up-to-date "
                    "and not bypassable via IP direct-access or HTTP/2 downgrade."
                ),
            })
        else:
            findings.append({
                "severity": "info",
                "title": "No WAF/CDN Detected",
                "detail": (
                    "No WAF or CDN fingerprint found in response headers or block pages. "
                    "Active modules will run without rate-limiting adjustments."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1590.005 - Gather Victim Network Information: IP Addresses",
                "remediation": (
                    "Consider deploying a WAF or CDN to protect the origin server from "
                    "automated scanning and common web attacks."
                ),
            })

        return {
            "domain": target,
            "waf_detected": waf_present,
            "vendors": detected,
            "blocked_probes": blocked_count,
            "total_probes": len(_CANARY_PAYLOADS),
            "evidence": evidence,
            "findings": findings,
        }

    def _request_headers(self) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BSS-Recon/1.5 Security Assessment)",
        }
        # HackerOne researcher header — injected by BaseModule when configured
        h1 = getattr(self, "hackerone_username", None) or (
            self.config.get("bug_bounty", {}).get("hackerone_username") if hasattr(self, "config") else None
        )
        if h1:
            headers["X-HackerOne-Researcher"] = h1
        return headers
