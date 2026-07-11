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


def _load_latest_output(output_dir: Path, target: str) -> list[dict]:
    """Return all JSON output files for this target from the output directory."""
    pattern = str(output_dir / f"{target}_*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    results = []
    for f in files:
        try:
            results.append(json.loads(Path(f).read_text(encoding="utf-8")))
        except Exception:
            pass
    return results


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
        output_dir = Path(
            self.config.get("output", {}).get("output_dir", "./output")
            if hasattr(self, "config") else "./output"
        )

        module_data = _load_latest_output(output_dir, target)

        total_score = 0
        breakdown: dict[str, int] = {}
        priority_items: list[dict] = []

        for data in module_data:
            module_name = data.get("module", data.get("domain", "unknown"))
            findings = data.get("findings", [])

            # Universal finding score
            fscore = _score_findings(findings)
            if fscore:
                breakdown[f"{module_name}_findings"] = fscore
                total_score += fscore

            # Module-specific bonus scoring
            if "subdomains" in str(module_name):
                pts, subs = _score_subdomains(data)
                if pts:
                    breakdown["subdomains"] = pts
                    total_score += pts
                    if subs:
                        priority_items.append({
                            "category": "Subdomain Exposure",
                            "detail": f"{len(subs)} subdomains discovered",
                            "points": pts,
                        })

            elif "ssl" in str(module_name):
                pts = _score_ssl(data)
                if pts:
                    breakdown["ssl"] = pts
                    total_score += pts

            elif "dns" in str(module_name):
                pts, gaps = _score_dns(data)
                if pts:
                    breakdown["dns_email_security"] = pts
                    total_score += pts
                    for g in gaps:
                        priority_items.append({
                            "category": "Email Security Gap",
                            "detail": g,
                            "points": _WEIGHTS.get(f"no_{g.split()[-1].lower()}", 0),
                        })

            elif "webprobe" in str(module_name):
                pts, hits = _score_webprobe(data)
                if pts:
                    breakdown["exposed_paths"] = pts
                    total_score += pts
                    for h in hits:
                        priority_items.append({
                            "category": "Exposed Sensitive Path",
                            "detail": h,
                            "points": 0,
                        })

            elif "jsanalyze" in str(module_name):
                pts = _score_js(data)
                if pts:
                    breakdown["js_secrets"] = pts
                    total_score += pts
                    priority_items.append({
                        "category": "Potential JS Secrets",
                        "detail": f"{data.get('total_secrets', '?')} patterns matched",
                        "points": pts,
                    })

            elif "wafdetect" in str(module_name):
                pts = _score_waf(data)
                if pts:
                    breakdown["no_waf"] = pts
                    total_score += pts

            elif "techdetect" in str(module_name):
                pts = _score_tech(data)
                if pts:
                    breakdown["tech_stack"] = pts
                    total_score += pts

        # Sort priority items highest-scoring first
        priority_items.sort(key=lambda x: x.get("points", 0), reverse=True)

        # Derive a human-readable priority tier
        if total_score >= 300:
            tier = "CRITICAL — test immediately"
        elif total_score >= 150:
            tier = "HIGH — high-value target"
        elif total_score >= 75:
            tier = "MEDIUM — worth investigating"
        elif total_score >= 20:
            tier = "LOW — minimal surface"
        else:
            tier = "MINIMAL — low attack surface"

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
