"""
Nuclei Scan Module — wraps the Nuclei vulnerability scanner (projectdiscovery.io).

Runs nuclei with default templates against the target, parses the JSONL output,
and converts each finding into the standard bss-recon findings format.

Requires nuclei to be installed and on PATH. Install:
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates

Mode: active — only runs when --active flag is passed. Requires authorization.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from bssrecon.core import BaseModule, register_module


# ---------------------------------------------------------------------------
# Severity mapping — Nuclei uses its own labels; normalise to bss-recon set
# ---------------------------------------------------------------------------

_NUCLEI_SEV_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

# Finding types that are purely informational fingerprints — downgrade to info
# so they don't pollute the high/medium counts in the executive summary.
_INFO_TAGS = frozenset({
    "tech", "detect", "version-detect", "fingerprint", "favicon",
    "waf-detect", "ssl", "dns", "network",
})

# ---------------------------------------------------------------------------
# OWASP Top 10 2021 — mapped from Nuclei tags / CWE IDs
# ---------------------------------------------------------------------------

_TAG_TO_OWASP: list[tuple[frozenset, str]] = [
    (frozenset({"sqli", "sql-injection"}),          "A03:2021 Injection"),
    (frozenset({"xss", "cross-site-scripting"}),    "A03:2021 Injection"),
    (frozenset({"ssti", "template-injection"}),     "A03:2021 Injection"),
    (frozenset({"lfi", "rfi", "path-traversal"}),  "A01:2021 Broken Access Control"),
    (frozenset({"idor", "auth-bypass", "unauth"}),  "A01:2021 Broken Access Control"),
    (frozenset({"ssrf"}),                           "A10:2021 Server-Side Request Forgery"),
    (frozenset({"xxe"}),                            "A05:2021 Security Misconfiguration"),
    (frozenset({"rce", "command-injection"}),       "A03:2021 Injection"),
    (frozenset({"jwt", "token", "oauth"}),          "A07:2021 Identification and Authentication Failures"),
    (frozenset({"default-login", "weak-password"}), "A07:2021 Identification and Authentication Failures"),
    (frozenset({"cors"}),                           "A05:2021 Security Misconfiguration"),
    (frozenset({"exposure", "disclosure",
                "config", "backup", "debug"}),      "A05:2021 Security Misconfiguration"),
    (frozenset({"cve"}),                            "A06:2021 Vulnerable and Outdated Components"),
    (frozenset({"log4j", "log4shell"}),             "A06:2021 Vulnerable and Outdated Components"),
    (frozenset({"open-redirect"}),                  "A01:2021 Broken Access Control"),
    (frozenset({"crypto", "ssl", "tls", "weak"}),  "A02:2021 Cryptographic Failures"),
    (frozenset({"xxe", "xml"}),                     "A05:2021 Security Misconfiguration"),
    (frozenset({"upload", "file-upload"}),          "A04:2021 Insecure Design"),
    (frozenset({"deserialization"}),                "A08:2021 Software and Data Integrity Failures"),
    (frozenset({"supply-chain", "dependency"}),     "A08:2021 Software and Data Integrity Failures"),
    (frozenset({"misconfig", "misconfiguration"}),  "A05:2021 Security Misconfiguration"),
    (frozenset({"api-key", "secret", "token-leak"}),"A02:2021 Cryptographic Failures"),
]

_CWE_TO_OWASP: dict[str, str] = {
    "CWE-89":  "A03:2021 Injection",
    "CWE-79":  "A03:2021 Injection",
    "CWE-22":  "A01:2021 Broken Access Control",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-78":  "A03:2021 Injection",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-306": "A07:2021 Identification and Authentication Failures",
    "CWE-200": "A05:2021 Security Misconfiguration",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-601": "A01:2021 Broken Access Control",
    "CWE-434": "A04:2021 Insecure Design",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK — mapped from Nuclei tags
# ---------------------------------------------------------------------------

_TAG_TO_MITRE: list[tuple[frozenset, str]] = [
    (frozenset({"rce", "command-injection"}),        "T1059 - Command and Scripting Interpreter"),
    (frozenset({"sqli", "sql-injection"}),           "T1190 - Exploit Public-Facing Application"),
    (frozenset({"xss"}),                             "T1059.007 - JavaScript"),
    (frozenset({"ssrf"}),                            "T1090 - Proxy"),
    (frozenset({"lfi", "path-traversal"}),           "T1083 - File and Directory Discovery"),
    (frozenset({"default-login", "weak-password"}),  "T1078 - Valid Accounts"),
    (frozenset({"exposure", "disclosure", "backup"}), "T1552 - Unsecured Credentials"),
    (frozenset({"api-key", "secret", "token-leak"}), "T1552.001 - Credentials in Files"),
    (frozenset({"cve", "log4j"}),                    "T1190 - Exploit Public-Facing Application"),
    (frozenset({"open-redirect"}),                   "T1566 - Phishing"),
    (frozenset({"cors"}),                            "T1185 - Browser Session Hijacking"),
    (frozenset({"jwt", "token", "oauth"}),           "T1528 - Steal Application Access Token"),
    (frozenset({"upload", "file-upload"}),           "T1105 - Ingress Tool Transfer"),
    (frozenset({"deserialization"}),                 "T1059 - Command and Scripting Interpreter"),
    (frozenset({"misconfig", "misconfiguration",
                "config", "debug"}),                 "T1082 - System Information Discovery"),
    (frozenset({"ssl", "crypto", "tls"}),            "T1040 - Network Sniffing"),
]

_DEFAULT_MITRE = "T1190 - Exploit Public-Facing Application"
_DEFAULT_OWASP = "A05:2021 Security Misconfiguration"


def _resolve_owasp(tags: set[str], cwe_ids: list[str]) -> str:
    tag_lower = {t.lower() for t in tags}
    for cwe in cwe_ids:
        if cwe in _CWE_TO_OWASP:
            return _CWE_TO_OWASP[cwe]
    for mapping_tags, owasp in _TAG_TO_OWASP:
        if mapping_tags & tag_lower:
            return owasp
    return _DEFAULT_OWASP


def _resolve_mitre(tags: set[str]) -> str:
    tag_lower = {t.lower() for t in tags}
    for mapping_tags, mitre in _TAG_TO_MITRE:
        if mapping_tags & tag_lower:
            return mitre
    return _DEFAULT_MITRE


def _is_info_type(tags: set[str]) -> bool:
    return bool(_INFO_TAGS & {t.lower() for t in tags})


# ---------------------------------------------------------------------------
# Nuclei JSONL parser
#
# Nuclei v3 JSONL schema (one JSON object per line):
#   template-id   : str
#   template-url  : str
#   info          : {
#       name        : str
#       author      : list[str]
#       tags        : list[str]
#       description : str
#       reference   : list[str]
#       severity    : str  (info|low|medium|high|critical|unknown)
#       classification: {
#           cvss-metrics : str
#           cvss-score   : float
#           cve-id       : list[str]   e.g. ["CVE-2021-44228"]
#           cwe-id       : list[str]   e.g. ["CWE-502"]
#       }
#       remediation : str   (present on some templates)
#   }
#   type          : str  (http|dns|ssl|network|headless|...)
#   host          : str  (bare hostname)
#   matched-at    : str  (full URL / endpoint that matched)
#   extracted-results : list[str]
#   matcher-name  : str
#   timestamp     : str  (RFC3339)
#   curl-command  : str
#   ip            : str
# ---------------------------------------------------------------------------

def _parse_nuclei_line(line: str) -> dict | None:
    """Parse one JSONL line from nuclei -jsonl output. Returns None on error."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Nuclei v3 uses a custom JSON library where the `info` struct may be inlined
    # (fields promoted to top-level) or nested under "info" depending on the build.
    # Handle both by preferring the nested block when present, then falling back to
    # reading the same keys directly from the top-level object.
    nested_info = raw.get("info")
    if isinstance(nested_info, dict):
        info = nested_info
    else:
        # Inlined — the info fields live at the top level alongside template-id, type, etc.
        info = raw

    classification = info.get("classification", {}) or {}

    tags: list[str] = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    cve_ids: list[str] = classification.get("cve-id", []) or []
    cwe_ids: list[str] = classification.get("cwe-id", []) or []

    raw_sev = info.get("severity", "info").lower()
    severity = _NUCLEI_SEV_MAP.get(raw_sev, "info")

    # Downgrade pure fingerprint/detection findings to info
    if _is_info_type(set(tags)):
        severity = "info"

    template_id  = raw.get("template-id", "unknown")
    template_name = info.get("name", template_id)
    matched_at   = raw.get("matched-at", raw.get("host", ""))
    description  = info.get("description", "").strip()
    remediation  = info.get("remediation", "").strip()
    cvss_score   = classification.get("cvss-score")
    epss_score   = classification.get("epss-score")
    extracted    = raw.get("extracted-results", []) or []

    # Build title
    title = template_name
    if cve_ids:
        title = f"{', '.join(cve_ids)} — {template_name}"

    # Build detail
    detail_parts = []
    if description:
        detail_parts.append(description)
    detail_parts.append(f"Template: {template_id}")
    detail_parts.append(f"Matched at: {matched_at}")
    if cvss_score:
        detail_parts.append(f"CVSS Score: {cvss_score}")
    if epss_score:
        detail_parts.append(f"EPSS Score: {epss_score}")
    if cve_ids:
        detail_parts.append(f"CVE(s): {', '.join(cve_ids)}")
    if cwe_ids:
        detail_parts.append(f"CWE(s): {', '.join(cwe_ids)}")
    if extracted:
        detail_parts.append(f"Extracted: {'; '.join(str(e) for e in extracted[:5])}")

    owasp = _resolve_owasp(set(tags), cwe_ids)
    mitre = _resolve_mitre(set(tags))

    if not remediation:
        remediation = (
            f"Review the {template_id} template finding and apply vendor-recommended "
            "patches or configuration hardening. Refer to the CVE/CWE references for "
            "specific guidance."
        )

    return {
        "severity":    severity,
        "title":       title,
        "detail":      "  ".join(detail_parts),
        "owasp":       owasp,
        "mitre":       mitre,
        "remediation": remediation,
        # Extra fields preserved for downstream use / diff tracking
        "_nuclei": {
            "template_id":  template_id,
            "matched_at":   matched_at,
            "tags":         tags,
            "cve_ids":      cve_ids,
            "cwe_ids":      cwe_ids,
            "cvss_score":   cvss_score,
            "epss_score":   epss_score,
            "type":         raw.get("type", ""),
            "ip":           raw.get("ip", ""),
            "matcher_name": raw.get("matcher-name", ""),
            "timestamp":    raw.get("timestamp", ""),
        },
    }


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

@register_module
class NucleiScan(BaseModule):
    name = "nuclei"
    description = "Nuclei vulnerability scanner — default template set"
    requires_api_key = False
    api_key_name = None
    mode = "active"

    def run(self, target: str) -> dict:
        if not shutil.which("nuclei"):
            return {
                "domain": target,
                "nuclei_available": False,
                "findings": [{
                    "severity": "info",
                    "title": "Nuclei Not Installed",
                    "detail": (
                        "nuclei binary not found on PATH. Install with: "
                        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  "
                        "then run: nuclei -update-templates"
                    ),
                    "owasp": "",
                    "mitre": "",
                    "remediation": "Install Nuclei and re-run with --active.",
                }],
            }

        scan_cfg = self.config.get("scan", {}) if hasattr(self, "config") else {}
        timeout_secs = int(scan_cfg.get("timeout", 10)) * 60  # config timeout is per-request; give nuclei minutes

        # Build command
        # -target / -u : single target URL
        # -jsonl       : one JSON object per finding line
        # -silent      : no banner/progress to stdout (findings only)
        # -rl          : rate-limit requests per second
        # -timeout     : per-request timeout in seconds
        # -no-interactsh: disable OOB callbacks (no external dependency in passive mode)
        rate_limit = scan_cfg.get("rate_limit", 1.0)
        user_agent = scan_cfg.get("user_agent", "BSS-Recon/1.5 (Security Assessment)")

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            output_file = tmp.name

        cmd = [
            "nuclei",
            "-target", f"https://{target}",
            "-jsonl",
            "-output", output_file,
            "-silent",
            "-no-interactsh",
            "-timeout", str(scan_cfg.get("timeout", 10)),
            "-H", f"User-Agent: {user_agent}",
        ]

        # Concurrency (-c) + rate-limit (-rl) come from the active scan profile
        # (stealth/balanced/aggressive) so the operator controls scan intensity.
        cmd += self.concurrency.nuclei_flags()

        # Inject HackerOne researcher header if configured
        h1 = None
        if hasattr(self, "config"):
            h1 = self.config.get("bug_bounty", {}).get("hackerone_username", "").strip()
        if h1:
            cmd += ["-H", f"X-HackerOne-Researcher: {h1}"]

        try:
            subprocess.run(
                cmd,
                timeout=timeout_secs,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pass   # partial results are still usable
        except FileNotFoundError:
            # Race between shutil.which check and execution — shouldn't happen
            return {
                "domain": target,
                "nuclei_available": False,
                "findings": [],
            }

        # Parse output
        findings: list[dict] = []
        raw_count = 0
        out_path = Path(output_file)

        if out_path.exists():
            for line in out_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                raw_count += 1
                parsed = _parse_nuclei_line(line)
                if parsed:
                    findings.append(parsed)

            try:
                out_path.unlink()
            except OSError:
                pass

        # Sort critical → info
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: _sev_rank.get(f["severity"], 5))

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            severity_counts[f.get("severity", "info")] = (
                severity_counts.get(f.get("severity", "info"), 0) + 1
            )

        return {
            "domain": target,
            "nuclei_available": True,
            "raw_finding_count": raw_count,
            "findings": findings,
            "severity_counts": severity_counts,
        }
