"""
Nuclei Scan Module — wraps the Nuclei vulnerability scanner (projectdiscovery.io).

Runs nuclei with its template library against the target, parses the JSONL
output, and converts each finding into the standard bss-recon findings format.

Requires nuclei to be installed and on PATH. Install:
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates
If the binary is missing the module skips gracefully (it never crashes a scan).

────────────────────────────────────────────────────────────────────────────
SAFETY — READ BEFORE EDITING
────────────────────────────────────────────────────────────────────────────
This module sends REAL probes at a target. Three guardrails are mandatory:

1. SCOPE ENFORCEMENT. Every target passes ScopeGuard.check_target() BEFORE a
   single template fires. Out-of-scope targets are quarantined and logged, and
   nuclei is never invoked. If the scope file exists but is malformed we FAIL
   CLOSED (refuse to scan) — a broken scope file must never silently degrade
   into "no enforcement". If no scope file is configured at all we warn loudly
   and record that the scan ran unenforced.

2. ACTIVE-ONLY. mode = "active", so the CLI (without --active/--accept-roe) and
   the dashboard's "Passive mode only (OSINT)" toggle both exclude this module
   entirely. Never change mode to "passive".

3. RATE LIMITING. Requests/sec come from the scan profile (stealth/balanced/
   aggressive) and can be overridden with config nuclei.rate_limit, so the
   operator controls how hard the target is hit.

────────────────────────────────────────────────────────────────────────────
TEMPLATE FRESHNESS
────────────────────────────────────────────────────────────────────────────
Nuclei's detection power comes from a community template library that ships
separately from the binary and changes daily. Nuclei can self-update it.
This module deliberately runs scans with -duc (disable-update-check) so a scan
never stalls or silently changes behaviour mid-engagement, and instead offers
an explicit refresh: set config nuclei.update_templates: true (or call
update_templates()) to run `nuclei -update-templates` before scanning. Keep
templates current — stale templates silently miss new CVEs.

Mode: active — only runs when --active flag is passed. Requires authorization.
"""

import json
import shutil
import subprocess
import sys
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
# Safety helpers — scope enforcement, template freshness, KEV cross-reference
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"[BSS Nuclei] {msg}", file=sys.stderr)


def update_templates(timeout: int = 180) -> bool:
    """Refresh the nuclei template library (`nuclei -update-templates`).

    Best-effort: returns True on success, False otherwise. Never raises — a
    failed template refresh degrades detection coverage but must not break a
    scan.
    """
    if not shutil.which("nuclei"):
        return False
    try:
        proc = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            timeout=timeout, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False,
        )
        ok = proc.returncode == 0
        _log("template library updated" if ok else "template update returned non-zero")
        return ok
    except Exception as exc:
        _log(f"template update failed ({exc}); continuing with existing templates")
        return False


def _kev_cross_reference(findings: list[dict], config: dict | None) -> int:
    """Escalate any CVE nuclei found that is on the CISA KEV catalog.

    Nuclei reports its own severity from the template; a CVE that is actively
    exploited in the wild outranks that, so it gets bumped to critical by the
    shared KEV engine. Returns the number escalated. Never raises.
    """
    try:
        from bssrecon.kev_check import escalate_findings
        return len(escalate_findings(findings, config))
    except Exception as exc:
        _log(f"KEV cross-reference skipped: {exc}")
        return 0


def _quarantine_result(target: str, reason: str, scope_path) -> dict:
    """Result returned when a target FAILS the scope check. Nuclei is not run."""
    _log(f"BLOCKED — refusing to scan out-of-scope target '{target}': {reason}")
    return {
        "domain": target,
        "status": "QUARANTINED",
        "nuclei_available": True,
        "nuclei_ran": False,
        "scope_enforced": True,
        "scope_file": str(scope_path) if scope_path else None,
        "out_of_scope_reason": reason,
        "findings": [{
            "severity": "info",
            "title": "Nuclei skipped — target out of scope",
            "detail": (
                f"Active scanning of '{target}' was blocked by the engagement scope "
                f"guard before any probe was sent. Reason: {reason}"
            ),
            "owasp": "",
            "mitre": "",
            "remediation": (
                "If this target is genuinely in scope, add it to the scope file's "
                "allowed_domains (and allowed_cidrs if IP-restricted). Otherwise "
                "leave it blocked — scanning it may be unauthorised."
            ),
        }],
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

    def _scope_gate(self, target: str) -> tuple[bool, dict | None, dict]:
        """MANDATORY pre-flight scope check. Nothing may probe `target` until
        this returns allowed=True.

        Returns (allowed, blocked_result_or_None, scope_meta). Fails CLOSED on
        any guard error: if we cannot prove a target is in scope, we do not
        scan it.
        """
        config = getattr(self, "config", {}) or {}

        try:
            from bssrecon.scope_guard import load_guard, ScopeFileError
        except Exception as exc:
            reason = (f"Scope guard unavailable ({exc}); refusing to run active "
                      f"scanning without scope enforcement")
            return False, _quarantine_result(target, reason, None), {"scope_enforced": True}

        try:
            guard, scope_path = load_guard(config)
        except ScopeFileError as exc:
            # Malformed scope file → fail closed. Never downgrade to "unenforced".
            return False, _quarantine_result(target, str(exc), None), {"scope_enforced": True}

        if guard is None:
            # No scope file configured anywhere. Allowed, but loudly flagged.
            _log("WARNING: no scope file configured — active scanning is running "
                 "WITHOUT scope enforcement. Create scope.yaml (see "
                 "bssrecon/scope.example.yaml) before engagement work.")
            return True, None, {
                "scope_enforced": False,
                "scope_file": None,
                "scope_warning": (
                    "Active scanning ran without scope enforcement — no scope file "
                    "configured."
                ),
            }

        ok, reason = guard.check_target(target)
        if not ok:
            return False, _quarantine_result(target, reason, scope_path), {"scope_enforced": True}

        _log(f"scope OK for '{target}' ({guard.program_name}): {reason}")
        return True, None, {
            "scope_enforced": True,
            "scope_file": str(scope_path),
            "scope_program": guard.program_name,
            "scope_reason": reason,
        }

    def run(self, target: str) -> dict:
        # ── GUARDRAIL 1: scope enforcement ────────────────────────────────
        # This MUST stay first. No nuclei template may fire at a target that
        # has not passed the engagement scope guard.
        allowed, blocked, scope_meta = self._scope_gate(target)
        if not allowed:
            return blocked

        if not shutil.which("nuclei"):
            return {
                "domain": target,
                "nuclei_available": False,
                "nuclei_ran": False,
                **scope_meta,
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
        nuclei_cfg = self.config.get("nuclei", {}) if hasattr(self, "config") else {}

        # Template freshness is opt-in so a scan never stalls on a surprise
        # multi-minute update mid-engagement (see TEMPLATE FRESHNESS above).
        if nuclei_cfg.get("update_templates", False):
            update_templates(int(nuclei_cfg.get("update_timeout", 180)))
        timeout_secs = int(scan_cfg.get("timeout", 10)) * 60  # config timeout is per-request; give nuclei minutes

        # Build command
        # -target / -u : single target URL
        # -jsonl       : one JSON object per finding line
        # -silent      : no banner/progress to stdout (findings only)
        # -rl          : rate-limit requests per second
        # -timeout     : per-request timeout in seconds
        # -duc         : never auto-update mid-scan (see TEMPLATE FRESHNESS)
        # -no-interactsh: disable OOB callbacks (no external dependency in passive mode)
        user_agent = scan_cfg.get("user_agent", "BSS-Recon/1.5 (Security Assessment)")

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            output_file = tmp.name

        # Pass the BARE host by default so nuclei probes both http and https.
        # (Hardcoding https:// silently produced zero findings against hosts that
        # serve plain HTTP or have 443 closed.) Override with nuclei.target_url.
        target_arg = nuclei_cfg.get("target_url") or target

        cmd = [
            "nuclei",
            "-target", target_arg,
            "-jsonl",
            "-output", output_file,
            "-silent",
            "-no-interactsh",
            "-duc",
            "-timeout", str(scan_cfg.get("timeout", 10)),
            "-H", f"User-Agent: {user_agent}",
        ]

        # ── GUARDRAIL 3: rate limiting ────────────────────────────────────
        # Concurrency (-c) + rate-limit (-rl) come from the active scan profile
        # (stealth/balanced/aggressive) so the operator controls scan intensity.
        profile_flags = list(self.concurrency.nuclei_flags())

        # Explicit config override wins over the profile, so an operator can
        # dial politeness per engagement (e.g. a target behind a twitchy WAF):
        #   nuclei: {rate_limit: 10, concurrency: 5}
        rate_override = nuclei_cfg.get("rate_limit")
        conc_override = nuclei_cfg.get("concurrency")
        for flag, value in (("-rl", rate_override), ("-c", conc_override)):
            if value is None:
                continue
            if flag in profile_flags:
                profile_flags[profile_flags.index(flag) + 1] = str(int(value))
            else:
                profile_flags += [flag, str(int(value))]
        cmd += profile_flags
        effective_rate = (profile_flags[profile_flags.index("-rl") + 1]
                          if "-rl" in profile_flags else "default")

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

        # Cross-reference nuclei's CVEs against CISA KEV — an actively-exploited
        # CVE outranks whatever severity the template assigned, so it gets
        # escalated to critical and badged in the dashboard.
        kev_escalated = _kev_cross_reference(findings, getattr(self, "config", None))

        # Surface the "ran without scope enforcement" warning as a visible
        # finding (info severity — it's an operator-config issue, not a flaw in
        # the target, so it must not distort the target's risk score).
        if scope_meta.get("scope_warning"):
            findings.append({
                "severity": "info",
                "title": "Active scan ran without scope enforcement",
                "detail": (
                    f"Nuclei actively scanned '{target}' but no engagement scope file "
                    f"was configured, so no scope guard was applied. Create scope.yaml "
                    f"(see bssrecon/scope.example.yaml) and re-run for enforced scanning."
                ),
                "owasp": "",
                "mitre": "",
                "remediation": (
                    "Define allowed_domains/allowed_cidrs in scope.yaml before running "
                    "active modules during an engagement."
                ),
            })

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
            "nuclei_ran": True,
            "raw_finding_count": raw_count,
            "kev_escalated": kev_escalated,
            "rate_limit": effective_rate,
            **scope_meta,
            "findings": findings,
            "severity_counts": severity_counts,
        }
