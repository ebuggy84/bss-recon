"""
BSS Bridge Engine — Attack Surface → Compliance Control Mapping
================================================================
Sits between BSS Recon (offensive findings) and BSS Compliance (GRC controls).

Takes a BSS Recon scan JSON and enriches each finding with:
  - the NIST 800-53 control(s) it implicates
  - the CIS Control it maps to
  - the SOC 2 Trust Services Criterion at risk
  - a plain-language governance impact + remediation pointer

Output: a unified "Attack Surface Compliance Report" that speaks BOTH
offensive findings and GRC language in one artifact. Framework-agnostic
mapping table so you can extend to PCI-DSS, HIPAA, ISO 27001 later.

Usage:
    from control_bridge import bridge_scan
    report = bridge_scan("output/example_com_20260807_221823.json")
    print(report["summary"])
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# =============================================================================
# MAPPING TABLE
# Each rule matches a condition in the recon JSON and maps it to controls.
# Keyed by a "signal" the bridge detects. Extend by adding entries.
# =============================================================================

# severity weights for the composite governance risk score
SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}


@dataclass
class ControlMapping:
    signal: str                 # internal id of what was detected
    title: str                  # human title
    severity: str               # critical/high/medium/low/info
    nist_800_53: list[str]      # e.g. ["SC-12", "SC-13"]
    cis_control: list[str]      # e.g. ["3.10"]
    soc2_tsc: list[str]         # e.g. ["CC6.1", "A1.2"]
    governance_impact: str      # plain-language why-it-matters for a GRC audience
    remediation: str            # what to do


# The knowledge base. This is the heart of the bridge — it encodes the
# offense→governance translation. Add rows to teach it new findings.
MAPPINGS: dict[str, ControlMapping] = {

    "expired_or_expiring_cert": ControlMapping(
        signal="expired_or_expiring_cert",
        title="TLS certificate expired or expiring soon",
        severity="high",
        nist_800_53=["SC-12", "SC-17"],
        cis_control=["3.10"],
        soc2_tsc=["CC6.1", "A1.2"],
        governance_impact="Expired/expiring certificates break confidentiality-in-transit guarantees and cause availability outages. Auditors treat lapsed certs as a failure of cryptographic key/certificate management.",
        remediation="Renew and automate certificate lifecycle (e.g. ACME/auto-renew); add expiry monitoring with alerting well before expiration."
    ),

    "no_waf": ControlMapping(
        signal="no_waf",
        title="Public asset with no Web Application Firewall detected",
        severity="medium",
        nist_800_53=["SC-7", "SI-4"],
        cis_control=["13.10"],
        soc2_tsc=["CC6.6", "CC7.1"],
        governance_impact="An internet-facing asset without perimeter filtering weakens boundary protection and reduces the org's ability to detect/prevent application-layer attacks — a boundary-protection control gap.",
        remediation="Place the asset behind a WAF/CDN with managed rule sets; ensure logging feeds the SIEM for monitoring."
    ),

    "exposed_sensitive_ports": ControlMapping(
        signal="exposed_sensitive_ports",
        title="Sensitive management/service ports exposed to the internet",
        severity="high",
        nist_800_53=["SC-7", "AC-17", "CM-7"],
        cis_control=["4.1", "12.3"],
        soc2_tsc=["CC6.1", "CC6.6"],
        governance_impact="Exposed management ports (RDP, SSH, DB, admin panels) violate least-functionality and secure-configuration baselines, and expand the attack surface auditors expect to be minimized.",
        remediation="Restrict via firewall/security groups to known IPs or VPN; disable unused services; enforce a hardened baseline configuration."
    ),

    "leaked_secret_in_js": ControlMapping(
        signal="leaked_secret_in_js",
        title="Potential API key / secret exposed in client-side JavaScript",
        severity="critical",
        nist_800_53=["IA-5", "SC-28", "SA-15"],
        cis_control=["3.11", "16.11"],
        soc2_tsc=["CC6.1", "CC6.3"],
        governance_impact="Hardcoded secrets in shipped code are a direct failure of credential management and secure development. If validated live, this is a reportable exposure and likely a breach-notification trigger under many frameworks.",
        remediation="Rotate the exposed credential immediately; move secrets to a vault/secret manager; add secret-scanning to the CI/CD pipeline."
    ),

    "subdomain_takeover_risk": ControlMapping(
        signal="subdomain_takeover_risk",
        title="Dangling DNS / subdomain takeover risk",
        severity="high",
        nist_800_53=["CM-8", "SC-20"],
        cis_control=["4.1", "7.1"],
        soc2_tsc=["CC6.1", "CC7.1"],
        governance_impact="Unmanaged/dangling DNS entries reflect an incomplete asset inventory and DNS hygiene gap — attackers can claim the endpoint to serve malicious content under the org's trusted domain.",
        remediation="Remove stale DNS records; maintain an authoritative asset inventory; monitor for dangling CNAMEs."
    ),

    "domain_expiring": ControlMapping(
        signal="domain_expiring",
        title="Domain registration expiring soon",
        severity="medium",
        nist_800_53=["CM-8", "CP-2"],
        cis_control=["7.1"],
        soc2_tsc=["A1.2"],
        governance_impact="Imminent domain expiry is an availability and continuity risk; loss of the domain can cause outage and enable hijacking, indicating weak asset/lifecycle management.",
        remediation="Enable auto-renew and registrar lock; add domain expiry to the monitored asset inventory."
    ),

    "weak_email_auth": ControlMapping(
        signal="weak_email_auth",
        title="Missing or weak email authentication (SPF/DKIM/DMARC)",
        severity="medium",
        nist_800_53=["SC-8", "SI-8"],
        cis_control=["9.5"],
        soc2_tsc=["CC6.7"],
        governance_impact="Absent SPF/DKIM/DMARC lets attackers spoof the org's domain for phishing/BEC — a spam/anti-phishing control gap directly tied to the BEC incidents auditors scrutinize.",
        remediation="Publish SPF, enable DKIM signing, and enforce a DMARC policy (start p=quarantine, move to p=reject)."
    ),

    "malicious_reputation": ControlMapping(
        signal="malicious_reputation",
        title="Domain/IP flagged by threat intelligence vendors",
        severity="high",
        nist_800_53=["SI-4", "RA-5"],
        cis_control=["13.7"],
        soc2_tsc=["CC7.1", "CC7.2"],
        governance_impact="A flagged reputation indicates possible compromise or blocklisting, impacting monitoring, deliverability, and the org's control over its assets.",
        remediation="Investigate the flagging source, remediate any compromise, and request delisting once clean."
    ),
}


# =============================================================================
# DETECTORS — read the recon JSON and emit which signals fired.
# Each detector is defensive about missing keys (recon output varies).
# =============================================================================

def _detect(scan: dict) -> list[dict]:
    """Return a list of fired findings: {signal, evidence}."""
    fired = []

    # --- certificate checks ---
    ssl = scan.get("ssl", {}) or {}
    days = ssl.get("days_until_expiry")
    if isinstance(days, (int, float)):
        if days <= 0:
            fired.append({"signal": "expired_or_expiring_cert",
                          "evidence": f"Certificate for {ssl.get('domain','?')} is EXPIRED ({days} days)."})
        elif days <= 30:
            fired.append({"signal": "expired_or_expiring_cert",
                          "evidence": f"Certificate for {ssl.get('domain','?')} expires in {days} days."})

    # --- domain expiry ---
    who = scan.get("whois", {}) or {}
    dexp = who.get("days_until_expiry")
    if isinstance(dexp, (int, float)) and dexp <= 30:
        fired.append({"signal": "domain_expiring",
                      "evidence": f"Domain {who.get('domain','?')} registration expires in {dexp} days."})

    # --- exposed sensitive ports (from shodan) ---
    shodan = scan.get("shodan", {}) or {}
    ports = shodan.get("ports", []) or []
    SENSITIVE = {21:"FTP",22:"SSH",23:"Telnet",135:"RPC",139:"NetBIOS",445:"SMB",
                 1433:"MSSQL",1521:"Oracle",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
                 5900:"VNC",6379:"Redis",9200:"Elasticsearch",27017:"MongoDB"}
    hits = [f"{p} ({SENSITIVE[p]})" for p in ports if p in SENSITIVE]
    if hits:
        fired.append({"signal": "exposed_sensitive_ports",
                      "evidence": f"Exposed sensitive ports on {shodan.get('ip','?')}: {', '.join(hits)}."})

    # --- WAF presence (webprobe/headers or a waf field) ---
    waf = scan.get("waf") or scan.get("webprobe", {}).get("waf") if isinstance(scan.get("webprobe"), dict) else scan.get("waf")
    if waf is not None and (waf is False or (isinstance(waf, dict) and not waf.get("detected", True)) or waf == "none"):
        fired.append({"signal": "no_waf",
                      "evidence": "No WAF detected on a public-facing asset."})

    # --- leaked secrets in JS (jsanalyzer / secrets module) ---
    for keyname in ("jsanalyzer", "js_analyzer", "secrets", "webprobe"):
        mod = scan.get(keyname)
        if isinstance(mod, dict):
            secrets = mod.get("secrets") or mod.get("leaked_keys") or mod.get("api_keys")
            if secrets:
                fired.append({"signal": "leaked_secret_in_js",
                              "evidence": f"Potential secret(s) found via {keyname}: {str(secrets)[:120]}."})

    # --- email auth ---
    phish = scan.get("phishing_analyzer") or scan.get("email_auth") or {}
    if isinstance(phish, dict):
        spf = phish.get("spf"); dkim = phish.get("dkim"); dmarc = phish.get("dmarc")
        if any(v in (False, "fail", "none", "missing") for v in (spf, dkim, dmarc)):
            fired.append({"signal": "weak_email_auth",
                          "evidence": f"Email auth gap — SPF:{spf} DKIM:{dkim} DMARC:{dmarc}."})

    # --- reputation ---
    vt = scan.get("virustotal", {}) or {}
    if isinstance(vt, dict) and (vt.get("malicious_count", 0) or 0) > 0:
        fired.append({"signal": "malicious_reputation",
                      "evidence": f"{vt.get('malicious_count')} vendor(s) flagged {vt.get('domain','?')} as malicious."})

    # --- subdomain takeover heuristic (interesting subdomains w/ dangling markers) ---
    subs = scan.get("subdomains", {}) or {}
    interesting = subs.get("interesting") or []
    if interesting:
        fired.append({"signal": "subdomain_takeover_risk",
                      "evidence": f"{len(interesting)} interesting subdomain(s) flagged for review: {', '.join(map(str, interesting[:5]))}."})

    return fired


# =============================================================================
# BRIDGE — combine detectors + mappings into a unified report
# =============================================================================

def bridge_scan(json_path: str) -> dict:
    scan = json.loads(Path(json_path).read_text())
    target = (scan.get("whois", {}) or {}).get("domain") or scan.get("target") or "unknown-target"

    fired = _detect(scan)
    findings = []
    risk_score = 0
    framework_hits = {"NIST 800-53": set(), "CIS": set(), "SOC 2": set()}

    for f in fired:
        m = MAPPINGS.get(f["signal"])
        if not m:
            continue
        risk_score += SEV_WEIGHT.get(m.severity, 1)
        framework_hits["NIST 800-53"].update(m.nist_800_53)
        framework_hits["CIS"].update(m.cis_control)
        framework_hits["SOC 2"].update(m.soc2_tsc)
        findings.append({
            "title": m.title,
            "severity": m.severity,
            "evidence": f["evidence"],
            "nist_800_53": m.nist_800_53,
            "cis_control": m.cis_control,
            "soc2_tsc": m.soc2_tsc,
            "governance_impact": m.governance_impact,
            "remediation": m.remediation,
        })

    # order by severity
    order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    findings.sort(key=lambda x: order.get(x["severity"], 9))

    tier = ("CRITICAL" if risk_score >= 80 else
            "HIGH" if risk_score >= 45 else
            "MODERATE" if risk_score >= 20 else
            "LOW" if risk_score > 0 else "CLEAN")

    return {
        "target": target,
        "compliance_risk_score": risk_score,
        "risk_tier": tier,
        "frameworks_implicated": {k: sorted(v) for k, v in framework_hits.items()},
        "finding_count": len(findings),
        "findings": findings,
        "summary": (f"{target}: {len(findings)} attack-surface findings mapped to "
                    f"{len(framework_hits['NIST 800-53'])} NIST controls, "
                    f"{len(framework_hits['CIS'])} CIS controls, "
                    f"{len(framework_hits['SOC 2'])} SOC 2 criteria. "
                    f"Compliance risk: {tier} ({risk_score} pts).")
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "output/example_com_latest.json"
    rpt = bridge_scan(path)
    print(json.dumps(rpt, indent=2))
