"""
Markdown Report Generator

Generates professional penetration test / OSINT assessment reports
in Markdown format. Can be converted to PDF via pandoc or used directly.

The report structure follows what clients on Upwork are asking for:
- Executive Summary
- Methodology
- Findings by severity (with CVSS, OWASP, MITRE mappings)
- Remediation recommendations
"""
import json
import os
from datetime import datetime
from pathlib import Path


def generate_markdown_report(target, results, config=None):
    """
    Generate a professional Markdown assessment report.

    Args:
        target: The domain/target assessed
        results: Dict of module_name -> module_results
        config: Application config

    Returns:
        Path to the generated report file
    """
    config = config or {}
    report_config = config.get("reporting", {})
    company = report_config.get("company_name", "Burgohy Security Solutions")
    analyst = report_config.get("analyst_name", "Emilio Burgohy")
    report_dir = report_config.get("report_dir", "./reports")

    # Ensure report directory exists
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d")
    filename = f"{target.replace('.', '_')}_assessment_{timestamp}.md"
    filepath = Path(report_dir) / filename

    # Collect all findings across modules
    all_findings = []
    for module_name, module_results in results.items():
        if isinstance(module_results, dict):
            findings = module_results.get("findings", [])
            for f in findings:
                f["module"] = module_name
                all_findings.append(f)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    # Count by severity
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Build report
    lines = []

    # Header
    lines.append(f"# External Security Assessment Report")
    lines.append(f"## {target}")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Client** | {target} |")
    lines.append(f"| **Assessment Date** | {timestamp} |")
    lines.append(f"| **Analyst** | {analyst} |")
    lines.append(f"| **Company** | {company} |")
    lines.append(f"| **Classification** | Confidential |")
    lines.append(f"| **Report Version** | 1.0 |")
    lines.append("")

    # Executive Summary
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(
        f"{company} was engaged to perform an external security assessment "
        f"of **{target}**. This assessment was conducted using passive "
        f"reconnaissance techniques and open-source intelligence (OSINT) "
        f"gathering to evaluate the target's external security posture "
        f"without interacting directly with the target's systems in an "
        f"intrusive manner."
    )
    lines.append("")

    # Findings summary
    total = len(all_findings)
    lines.append(f"The assessment identified **{total} finding(s)**:")
    lines.append("")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🔵", "info": "⚪"
            }.get(sev, "⚪")
            lines.append(f"- {emoji} **{sev.upper()}**: {count}")
    lines.append("")

    if severity_counts.get("critical", 0) > 0:
        lines.append(
            "> **⚠️ Critical findings require immediate attention.** "
            "These issues pose a significant risk to the organization's "
            "security posture and should be remediated as soon as possible."
        )
        lines.append("")

    # Methodology
    lines.append("## 2. Methodology")
    lines.append("")
    lines.append(
        "This assessment followed the OWASP Testing Guide and PTES "
        "(Penetration Testing Execution Standard) methodologies. The "
        "following reconnaissance modules were executed:"
    )
    lines.append("")
    for module_name in results.keys():
        lines.append(f"- **{module_name}**")
    lines.append("")
    lines.append(
        "All testing was conducted passively using publicly available "
        "information sources. No active exploitation or intrusive scanning "
        "was performed unless specifically authorized."
    )
    lines.append("")
    lines.append(
        "Findings are mapped to the **OWASP Top 10 (2021)** and "
        "**MITRE ATT&CK** frameworks for standardized risk classification."
    )
    lines.append("")

    # Detailed Findings
    lines.append("## 3. Findings")
    lines.append("")

    if not all_findings:
        lines.append("No significant findings were identified during this assessment.")
        lines.append("")
    else:
        for i, finding in enumerate(all_findings, 1):
            sev = finding.get("severity", "info").upper()
            title = finding.get("title", "Untitled Finding")
            detail = finding.get("detail", "")
            owasp = finding.get("owasp", "N/A")
            mitre = finding.get("mitre", "N/A")
            module = finding.get("module", "unknown")

            lines.append(f"### 3.{i} [{sev}] {title}")
            lines.append("")
            lines.append(f"| Attribute | Value |")
            lines.append(f"|-----------|-------|")
            lines.append(f"| **Severity** | {sev} |")
            lines.append(f"| **OWASP** | {owasp} |")
            lines.append(f"| **MITRE ATT&CK** | {mitre} |")
            lines.append(f"| **Source Module** | {module} |")
            lines.append("")

            if detail:
                lines.append(f"**Description:** {detail}")
                lines.append("")

            # Add remediation recommendation based on finding type
            remediation = _get_remediation(finding)
            if remediation:
                lines.append(f"**Remediation:** {remediation}")
                lines.append("")

    # Module Details
    lines.append("## 4. Reconnaissance Details")
    lines.append("")

    # WHOIS
    if "whois" in results and not results["whois"].get("error"):
        wd = results["whois"]
        lines.append("### 4.1 WHOIS Registration")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        for key in ["registrar", "creation_date", "expiration_date", "org", "country"]:
            val = wd.get(key, "N/A")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(f"| **{key.replace('_', ' ').title()}** | {val} |")
        lines.append("")

    # DNS
    if "dns" in results and not results["dns"].get("error"):
        dd = results["dns"]
        lines.append("### 4.2 DNS Records")
        lines.append("")
        lines.append(f"| Type | Value | TTL |")
        lines.append(f"|------|-------|-----|")
        for rec in dd.get("records", [])[:30]:
            lines.append(
                f"| {rec['type']} | {rec['value']} | {rec.get('ttl', '')} |"
            )
        lines.append("")

        # Email security
        es = dd.get("email_security", {})
        lines.append("**Email Security Posture:**")
        lines.append("")
        for proto in ["spf", "dmarc", "dkim"]:
            status = "✓ Configured" if es.get(proto) else "✗ Missing"
            lines.append(f"- {proto.upper()}: {status}")
        lines.append("")

    # Subdomains
    if "subdomains" in results and not results["subdomains"].get("error"):
        sd = results["subdomains"]
        total_subs = sd.get("total_found", 0)
        lines.append(f"### 4.3 Subdomain Enumeration ({total_subs} found)")
        lines.append("")
        lines.append(f"Source: {sd.get('source', 'Certificate Transparency')}")
        lines.append("")

        interesting = sd.get("interesting", [])
        if interesting:
            lines.append("**Notable Subdomains:**")
            lines.append("")
            lines.append(f"| Subdomain | Category | First Seen |")
            lines.append(f"|-----------|----------|------------|")
            for sub in interesting[:20]:
                lines.append(
                    f"| {sub['name']} | {sub.get('category', '')} | "
                    f"{sub.get('first_seen', '')} |"
                )
            lines.append("")

    # SSL
    if "ssl" in results and not results["ssl"].get("error"):
        sl = results["ssl"]
        lines.append("### 4.4 SSL/TLS Certificate")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        for key in ["subject", "issuer", "not_before", "not_after",
                     "days_until_expiry", "protocol", "cipher_suite"]:
            val = sl.get(key, "N/A")
            lines.append(f"| **{key.replace('_', ' ').title()}** | {val} |")
        lines.append("")

    # Disclaimer
    lines.append("---")
    lines.append("")
    lines.append("## 5. Disclaimer")
    lines.append("")
    lines.append(
        "This report is provided for informational purposes and represents "
        "the findings at the time of assessment. The security landscape "
        "changes continuously, and new vulnerabilities may emerge after "
        "this assessment was conducted. This report should not be considered "
        "a guarantee of security. The assessment was limited to the scope "
        "defined above and may not identify all vulnerabilities."
    )
    lines.append("")
    lines.append(f"---")
    lines.append(f"*Generated by BSS Recon | {company} | {timestamp}*")

    # Write report
    report_content = "\n".join(lines)
    with open(filepath, "w") as f:
        f.write(report_content)

    return str(filepath)


def _get_remediation(finding):
    """Generate remediation advice based on finding type."""
    title = finding.get("title", "").lower()
    owasp = finding.get("owasp", "").lower()

    remediations = {
        "expired": (
            "Renew the SSL certificate immediately and implement automated "
            "certificate monitoring to prevent future expiration incidents."
        ),
        "expiring soon": (
            "Renew the SSL certificate before expiration. Consider "
            "implementing automated renewal via Let's Encrypt or similar."
        ),
        "weak tls": (
            "Disable TLS 1.0, TLS 1.1, and SSLv3. Configure the server "
            "to only accept TLS 1.2 and TLS 1.3 with strong cipher suites."
        ),
        "self-signed": (
            "Replace the self-signed certificate with one issued by a "
            "trusted Certificate Authority (CA)."
        ),
        "spf": (
            "Implement SPF, DMARC, and DKIM records to prevent email "
            "spoofing and improve email deliverability."
        ),
        "dmarc": (
            "Configure a DMARC policy to protect against email spoofing. "
            "Start with p=none for monitoring, then progress to p=reject."
        ),
        "exposed": (
            "Restrict access to this service using firewall rules, VPN, "
            "or network segmentation. If public access is required, "
            "ensure strong authentication and monitoring are in place."
        ),
        "rdp": (
            "Disable direct RDP exposure to the internet. Use a VPN or "
            "jump box for remote access. Enable Network Level Authentication."
        ),
        "database": (
            "Database services should never be directly exposed to the "
            "internet. Place behind a firewall and restrict access to "
            "application servers only."
        ),
        "telnet": (
            "Disable Telnet and replace with SSH for encrypted remote access."
        ),
        "cve": (
            "Review the identified CVE(s) and apply vendor patches or "
            "mitigations as soon as possible. Prioritize based on CVSS score "
            "and exploitability."
        ),
    }

    for keyword, advice in remediations.items():
        if keyword in title or keyword in owasp:
            return advice

    return (
        "Review this finding and implement appropriate controls based on "
        "the identified risk level and organizational context."
    )
