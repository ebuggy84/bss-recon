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

    # Actively-exploited (CISA KEV) — extra weight ON TOP of the critical the
    # finding is escalated to, so a known-exploited CVE dominates the score.
    "kev_actively_exploited":  75,

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


def _normalize_score(raw: int) -> int:
    """Map an unbounded triage total to a 0-100 headline that reads on the same
    scale as the dashboard's attack-surface ring.

    Uses a saturating curve 100*raw/(raw+K): a few low/medium findings land in
    the teens, a cluster of high-severity findings climbs the mid-band, and a
    large mass of high/critical findings saturates near 100. K=300 is tuned so
    the common cases line up with the ring (e.g. 3 DNS gaps ≈ low teens; 119
    high-severity CVEs ≈ mid-90s). The raw total is preserved separately."""
    if raw <= 0:
        return 0
    return round(100 * raw / (raw + 300))


def _tier(score: int) -> str:
    """Human-readable tier for a 0-100 score, aligned with the ring's risk
    zones (0-30 low, 31-60 moderate, 61-80 high, 81-100 critical)."""
    if score >= 81:
        return "CRITICAL — test immediately"
    if score >= 61:
        return "HIGH — high-value target"
    if score >= 31:
        return "MODERATE — worth investigating"
    if score > 0:
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
    kev_count = 0

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
            if isinstance(f, dict) and f.get("kev"):
                kev_count += 1

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

    # Actively-exploited (CISA KEV) bonus — makes known-exploited CVEs weigh
    # heavily, on top of the critical severity they were escalated to.
    if kev_count:
        kev_bonus = kev_count * _WEIGHTS["kev_actively_exploited"]
        breakdown["kev_actively_exploited"] = kev_bonus
        total += kev_bonus
        priority.append({
            "category": "Actively Exploited (CISA KEV)",
            "detail": f"{kev_count} CVE(s) on the CISA Known Exploited Vulnerabilities catalog",
            "points": kev_bonus,
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

        raw_score, breakdown, priority_items = _score_results(results)
        score = _normalize_score(raw_score)   # 0-100 headline (ring scale)
        tier = _tier(score)

        findings = [
            {
                "severity": "info",
                "title": f"Attack Surface Score: {score}/100 — {tier}",
                "detail": (
                    f"Normalized attack-surface score for {target}: {score}/100 "
                    f"({raw_score} raw triage points). "
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
            "score": score,                 # 0-100 normalized headline
            "raw_score": raw_score,         # unbounded triage total (secondary)
            "total_score": raw_score,       # back-compat alias for raw_score
            "tier": tier,
            "breakdown": breakdown,
            "priority_items": priority_items,
            "findings": findings,
        }
