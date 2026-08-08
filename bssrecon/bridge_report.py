"""
BSS Bridge Report — renders bridge_scan() output as a branded HTML report.
Produces a client-grade "Attack Surface Compliance Report" that a vCISO
could hand to a client or auditor.

Usage:
    python3 bridge_report.py output/scan.json report.html
"""
import json, sys, datetime
from pathlib import Path
try:
    # When imported as part of the bssrecon package (e.g. from the dashboard).
    from bssrecon.control_bridge import bridge_scan
except ImportError:
    # When run standalone from the directory containing control_bridge.py.
    from control_bridge import bridge_scan

SEV_COLOR = {"critical":"#8B3430","high":"#B5602A","medium":"#B8933B","low":"#5C7A4C","info":"#6A6A6A"}
TIER_COLOR = {"CRITICAL":"#8B3430","HIGH":"#B5602A","MODERATE":"#B8933B","LOW":"#5C7A4C","CLEAN":"#5C7A4C"}

def render(rpt: dict) -> str:
    now = datetime.datetime.now().strftime("%B %d, %Y")
    tier = rpt["risk_tier"]
    fw = rpt["frameworks_implicated"]
    rows = ""
    for f in rpt["findings"]:
        c = SEV_COLOR.get(f["severity"], "#666")
        rows += f"""
        <div class="finding">
          <div class="fhead">
            <span class="sev" style="background:{c}">{f['severity'].upper()}</span>
            <h3>{f['title']}</h3>
          </div>
          <p class="evidence">{f['evidence']}</p>
          <div class="ctrls">
            <span class="chip nist">NIST: {', '.join(f['nist_800_53'])}</span>
            <span class="chip cis">CIS: {', '.join(f['cis_control'])}</span>
            <span class="chip soc">SOC 2: {', '.join(f['soc2_tsc'])}</span>
          </div>
          <p class="impact"><strong>Governance impact.</strong> {f['governance_impact']}</p>
          <p class="rem"><strong>Remediation.</strong> {f['remediation']}</p>
        </div>"""

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Surface Compliance Report — {rpt['target']}</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a2233;margin:0;background:#f4f4ef;}}
  .wrap{{max-width:820px;margin:0 auto;background:#fff;box-shadow:0 2px 20px rgba(0,0,0,.08);}}
  .hdr{{background:#0F1E3D;color:#fff;padding:36px 40px;border-bottom:4px solid #B8933B;}}
  .hdr .kicker{{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#B8933B;font-weight:700;}}
  .hdr h1{{margin:8px 0 4px;font-size:26px;}}
  .hdr .sub{{color:#9fb0cc;font-size:13px;}}
  .scoreband{{display:flex;align-items:center;gap:20px;padding:24px 40px;background:#0c1830;color:#fff;}}
  .tier{{font-size:34px;font-weight:800;color:{TIER_COLOR.get(tier,'#B8933B')};}}
  .tierlbl{{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:#9fb0cc;}}
  .scoreband .pts{{font-size:14px;color:#cdd6e6;}}
  .fwsummary{{display:flex;gap:14px;padding:22px 40px;background:#f7f6f1;border-bottom:1px solid #e5e2d6;flex-wrap:wrap;}}
  .fwbox{{flex:1;min-width:150px;background:#fff;border:1px solid #e5e2d6;border-radius:4px;padding:14px 16px;}}
  .fwbox .n{{font-size:22px;font-weight:800;color:#0F1E3D;}}
  .fwbox .l{{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#8a8a72;margin-top:2px;}}
  .fwbox .codes{{font-size:11px;color:#666;margin-top:8px;line-height:1.5;font-family:ui-monospace,monospace;}}
  .body{{padding:28px 40px 40px;}}
  .body h2{{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#0F1E3D;border-bottom:2px solid #B8933B;padding-bottom:8px;}}
  .finding{{border:1px solid #e5e2d6;border-left:4px solid #B8933B;border-radius:4px;padding:16px 18px;margin:16px 0;background:#fff;}}
  .fhead{{display:flex;align-items:center;gap:10px;}}
  .fhead h3{{margin:0;font-size:16px;}}
  .sev{{color:#fff;font-size:10px;font-weight:700;letter-spacing:.08em;padding:3px 8px;border-radius:3px;}}
  .evidence{{font-family:ui-monospace,monospace;font-size:12.5px;color:#444;background:#f7f6f1;padding:8px 10px;border-radius:3px;}}
  .ctrls{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0;}}
  .chip{{font-size:11px;font-weight:600;padding:3px 9px;border-radius:20px;}}
  .chip.nist{{background:#e7edf7;color:#26456f;}} .chip.cis{{background:#eef3e7;color:#4a6636;}} .chip.soc{{background:#f7efe0;color:#8a6a1f;}}
  .impact,.rem{{font-size:13px;line-height:1.5;margin:6px 0;}}
  .rem{{color:#2a4a2a;}}
  .foot{{padding:20px 40px;background:#0F1E3D;color:#9fb0cc;font-size:11px;text-align:center;}}
</style></head><body><div class="wrap">
  <div class="hdr">
    <div class="kicker">Burgohy Security Solutions</div>
    <h1>Attack Surface Compliance Report</h1>
    <div class="sub">{rpt['target']} &middot; Generated {now}</div>
  </div>
  <div class="scoreband">
    <div><div class="tier">{tier}</div><div class="tierlbl">Compliance Risk Tier</div></div>
    <div class="pts">{rpt['finding_count']} findings mapped &middot; composite risk score {rpt['compliance_risk_score']}</div>
  </div>
  <div class="fwsummary">
    <div class="fwbox"><div class="n">{len(fw['NIST 800-53'])}</div><div class="l">NIST 800-53 controls</div><div class="codes">{', '.join(fw['NIST 800-53'])}</div></div>
    <div class="fwbox"><div class="n">{len(fw['CIS'])}</div><div class="l">CIS controls</div><div class="codes">{', '.join(fw['CIS'])}</div></div>
    <div class="fwbox"><div class="n">{len(fw['SOC 2'])}</div><div class="l">SOC 2 criteria</div><div class="codes">{', '.join(fw['SOC 2'])}</div></div>
  </div>
  <div class="body">
    <h2>Findings &amp; Control Mapping</h2>
    {rows}
  </div>
  <div class="foot">Generated by BSS Bridge Engine &middot; Attack surface findings mapped to NIST 800-53, CIS Controls, and SOC 2 Trust Services Criteria &middot; For authorized assessment use only.</div>
</div></body></html>"""

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "test_scan.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "bridge_report.html"
    rpt = bridge_scan(src)
    Path(out).write_text(render(rpt))
    print(f"Report written: {out}")
    print(rpt["summary"])
