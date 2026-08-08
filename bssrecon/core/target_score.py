"""
Target Scoring Module — reads all other module outputs from the scan's output
directory and ranks the target by attack surface. Runs after all other modules.

Because this module reads saved JSON output (not live network), it is passive.
The score and priority list appear in the final report just like any other module.
"""

import json
import glob
import os
from pathlib import Path

from bssrecon.core import BaseModule, register_module
from bssrecon.config import get_output_dir


# Points per signal — tuned for bug-bounty triage priority
_WEIGHTS = {
    # Findings by severity from any module
    "finding_critical":       100,
    "finding_high":            50,
    "finding_medium":          20,
    "finding_low":              5,
    "finding_info":             1,

    # Subdomain surface
    "subdomain_each":           3,
    "subdomain_10plus":        15,   # bonus for large subdomain count

    # SSL/TLS issues
    "ssl_expired":             40,
    "ssl_self_signed":         30,
    "ssl_weak_cipher":         20,

    # Email security gaps (easy wins for phishing/spoofing bugs)
    "no_spf":                  25,
    "no_dmarc":                25,
    "no_dkim":                 15,

    # Web exposure from webprobe
    "exposed_git":             80,
    "exposed_env":             80,
    "exposed_admin":           40,
    "exposed_swagger":         35,
    "exposed_backup":          35,
    "exposed_debug":           30,
    "exposed_phpinfo":         30,

    # JS secrets from jsanalyze
    "js_secret_each":          50,

    # WAF absent (easier to exploit)
    "no_waf":                  10,

    # Tech stack signals (widened attack surface)
    "wordpress":               20,
    "php":                     10,
    "jquery_old":              10,
}

# Keywords in webprobe path/title that map to weight keys
_PATH_WEIGHTS: list[tuple[str, str]] = [
    (".git",         "exposed_git"),
    (".env",         "exposed_env"),
    ("admin",        "exposed_admin"),
    ("swagger",      "exposed_swagger"),
    ("openapi",      "exposed_swagger"),
    ("backup",       "exposed_backup"),
    (".bak",         "exposed_backup"),
    (".sql",         "exposed_backup"),
    ("debug",        "exposed_debug"),
    ("phpinfo",      "exposed_phpinfo"),
    ("php_info",     "exposed_phpinfo"),
]


def _load_current_scan(output_dir: Path, target: str) -> dict:
    """Fallback for standalone use: return the most recent saved scan for this
    target as a {module_name: result} dict.

    The CLI saves scans as "<target-with-dots-as-underscores>_<timestamp>.json"
    (e.g. scanme_nmap_org_20260801_130958.json), so the glob MUST use the
    underscore form — matching on the raw dotted domain never hit anything,
    which is why the score used to come back 0."""
    prefix = target.replace(".", "_")
    files = sorted(
        glob.glob(str(output_dir / f"{prefix}_*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    for f in files:
        try:
            data = json.loads(Path(f).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _tier(total_score: int) -> str:
    """Human-readable priority tier for a composite score."""
    if total_score >= 250:
        return "CRITICAL — test immediately"
    if total_score >= 120:
        return "HIGH — high-value target"
    if total_score >= 50:
        return "MEDIUM — worth investigating"
    if total_score > 0:
        return "LOW — minimal surface"
    return "MINIMAL — low attack surface"


def _score_results(results: dict) -> tuple[int, dict, list]:
    """Score a scan's {module_name: result} mapping by the severity and count of
    its findings (plus a subdomain-surface bonus). This is the fix: the score
    now reflects what every module actually found, instead of always being 0."""
    total = 0
    breakdown: dict[str, int] = {}
    priority: list[dict] = []
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for module_name, data in (results or {}).items():
        if not isinstance(data, dict):
            continue
        # Never let the score module's own summary finding inflate the score
        # (matters on the disk-fallback path, where a saved scan already holds
        # a prior score finding).
        if str(module_name).lower() == "score":
            continue

        findings = data.get("findings", []) or []
        fscore = _score_findings(findings)
        if fscore:
            breakdown[str(module_name)] = breakdown.get(str(module_name), 0) + fscore
            total += fscore
        for f in findings:
            s = str(f.get("severity", "info")).lower()
            if s in sev_totals:
                sev_totals[s] += 1

        # Subdomain surface is a count, not a finding — score it separately.
        if "subdomain" in str(module_name).lower():
            pts, subs = _score_subdomains(data)
            if pts:
                breakdown["subdomain_surface"] = breakdown.get("subdomain_surface", 0) + pts
                total += pts
                if subs:
                    priority.append({
                        "category": "Subdomain Exposure",
                        "detail": f"{len(subs)} subdomains discovered",
                        "points": pts,
                    })

    for sev in ("critical", "high", "medium"):
        if sev_totals[sev]:
            priority.append({
                "category": f"{sev.title()}-severity findings",
                "detail": f"{sev_totals[sev]} {sev}-severity finding(s)",
                "points": sev_totals[sev] * _WEIGHTS[f"finding_{sev}"],
            })

    priority.sort(key=lambda x: x.get("points", 0), reverse=True)
    return total, breakdown, priority


def _score_findings(findings: list[dict]) -> int:
    score = 0
    for f in findings:
        sev = f.get("severity", "").lower()
        score += _WEIGHTS.get(f"finding_{sev}", 0)
    return score


def _score_subdomains(data: dict) -> tuple[int, list[str]]:
    subs = data.get("subdomains", [])
    count = len(subs)
    pts = count * _WEIGHTS["subdomain_each"]
    if count >= 10:
        pts += _WEIGHTS["subdomain_10plus"]
    return pts, subs


def _score_ssl(data: dict) -> int:
    score = 0
    issues = data.get("issues", []) + data.get("findings", [])
    for item in issues:
        detail = str(item.get("detail", "") + item.get("title", "")).lower()
        if "expired" in detail:
            score += _WEIGHTS["ssl_expired"]
        if "self-signed" in detail or "self signed" in detail:
            score += _WEIGHTS["ssl_self_signed"]
        if "weak" in detail or "rc4" in detail or "des" in detail:
            score += _WEIGHTS["ssl_weak_cipher"]
    return score


def _score_dns(data: dict) -> tuple[int, list[str]]:
    score = 0
    gaps = []
    for field, key, label in [
        ("spf_record", "no_spf", "Missing SPF"),
        ("dmarc_record", "no_dmarc", "Missing DMARC"),
        ("dkim_record", "no_dkim", "Missing DKIM"),
    ]:
        if not data.get(field):
            score += _WEIGHTS[key]
            gaps.append(label)
    return score, gaps


def _score_webprobe(data: dict) -> tuple[int, list[str]]:
    score = 0
    hits: list[str] = []
    paths_found = data.get("paths_found", [])
    for entry in paths_found:
        path = str(entry.get("path", "") + entry.get("url", "")).lower()
        for fragment, weight_key in _PATH_WEIGHTS:
            if fragment in path:
                score += _WEIGHTS[weight_key]
                hits.append(path)
                break
    return score, hits


def _score_js(data: dict) -> int:
    count = len(data.get("secrets", []) + data.get("findings", []))
    return count * _WEIGHTS["js_secret_each"]


def _score_waf(data: dict) -> int:
    if not data.get("waf_detected", True):
        return _WEIGHTS["no_waf"]
    return 0


def _score_tech(data: dict) -> int:
    score = 0
    tech_str = " ".join(data.get("technologies", [])).lower()
    if "wordpress" in tech_str:
        score += _WEIGHTS["wordpress"]
    if "php" in tech_str:
        score += _WEIGHTS["php"]
    if "jquery" in tech_str:
        score += _WEIGHTS["jquery_old"]
    return score


@register_module
class TargetScore(BaseModule):
    name = "score"
    description = "Attack-surface scoring — ranks target by exploitability"
    requires_api_key = False
    api_key_name = None
    mode = "passive"

    def run(self, target: str) -> dict:
        # Prefer the CURRENT scan's in-memory results, injected by the runner
        # (cli.py / dashboard) right before this module runs. Falls back to the
        # most recent saved scan on disk for standalone/report use.
        results = getattr(self, "scan_results", None)
        if not results:
            output_dir = get_output_dir(getattr(self, "config", {}) or {}, create=False)
            results = _load_current_scan(output_dir, target)

        total_score, breakdown, priority_items = _score_results(results)
        tier = _tier(total_score)

        findings = [
            {
                "severity": "info",
                "title": f"Attack Surface Score: {total_score} pts — {tier}",
                "detail": (
                    f"Composite attack-surface score for {target}. "
                    f"Score breakdown: {json.dumps(breakdown)}. "
                    f"Top items: {'; '.join(i['detail'] for i in priority_items[:5]) or 'none'}."
                ),
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1595 - Active Scanning",
                "remediation": (
                    "Address high-scoring findings first: exposed sensitive paths, "
                    "missing email security records, and leaked secrets in JS files "
                    "represent the highest-value low-hanging fruit."
                ),
            }
        ]

        return {
            "domain": target,
            "total_score": total_score,
            "tier": tier,
            "breakdown": breakdown,
            "priority_items": priority_items,
            "findings": findings,
        }
