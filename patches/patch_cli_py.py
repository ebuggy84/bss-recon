#!/usr/bin/env python3
"""
Patch script for ~/bss-recon/bssrecon/cli.py

Applies TWO patches:
  1. MONITOR PATCH: Adds --monitor N flag to the scan command that re-runs
     the scan every N hours and diffs results (new/resolved findings).
  2. PDF REPORT PATCH: Adds "pdf" as a working format option in the report
     command using bssrecon.reporting.pdf_report.

Run from Kali:
    cd ~/bss-recon
    python3 patches/patch_cli_py.py
"""
import shutil
from pathlib import Path

CLI_PY = Path.home() / "bss-recon" / "bssrecon" / "cli.py"


# ============================================================
# PATCH 1: Monitor flag on the scan command
# ============================================================

# --- Find the scan command's @click.option block end + def signature ---
OLD_SCAN_DEF = '''@click.option(
    "--active", "-a",
    is_flag=True,
    help="Include active modules (makes requests to target servers - needs authorization)",
)
@click.pass_context
def scan(ctx, target, modules, output, report, active):'''

NEW_SCAN_DEF = '''@click.option(
    "--active", "-a",
    is_flag=True,
    help="Include active modules (makes requests to target servers - needs authorization)",
)
@click.option(
    "--monitor",
    default=0,
    type=int,
    metavar="HOURS",
    help="Re-run scan every N hours and alert on changes (0 = run once).",
)
@click.pass_context
def scan(ctx, target, modules, output, report, active, monitor):'''

# --- The monitor loop + diff functions to add after scan() ---
MONITOR_FUNCTIONS = '''

# ---------------------------------------------------------------------------
# Monitor mode — continuous scan + diff
# ---------------------------------------------------------------------------

def _monitor_loop(target, interval_hours, active, modules, recursive, first_report_path, config):
    """Re-run scan every interval_hours, diff against previous results, print changes."""
    from rich.table import Table as RichTable

    prev_path = first_report_path
    cycle = 1

    console.print(
        f"\\n  [bold cyan]Monitor mode:[/bold cyan] re-scanning every "
        f"{interval_hours}h. Ctrl+C to stop.\\n"
    )

    while True:
        try:
            sleep_secs = interval_hours * 3600
            console.print(f"  [dim]Next scan in {interval_hours}h (sleeping {sleep_secs}s)...[/dim]")
            time.sleep(sleep_secs)
        except KeyboardInterrupt:
            console.print("\\n  [yellow]Monitor stopped by user.[/yellow]")
            return

        cycle += 1
        console.print(f"\\n  [bold cyan]Monitor cycle {cycle}[/bold cyan] — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Re-run scan via CliRunner so we stay in-process
        try:
            from click.testing import CliRunner
            runner = CliRunner()
            args = [target, "-r"]
            if active:
                args.append("--active")
            if modules:
                args.extend(["-m", modules])
            result = runner.invoke(scan, args, obj={"config": config}, catch_exceptions=False)
            if result.output:
                console.print(result.output)
        except KeyboardInterrupt:
            console.print("\\n  [yellow]Monitor stopped by user.[/yellow]")
            return
        except Exception as e:
            print_error(f"Monitor scan failed: {e}")
            continue

        # Find the latest report
        new_path = _find_latest_report(target, config)
        if not new_path or new_path == prev_path:
            console.print("  [dim]No new report file found for diff.[/dim]")
            continue

        # Diff
        diff = _diff_reports(prev_path, new_path)
        if diff:
            _print_diff_table(diff, cycle)
        else:
            console.print("  [green]No changes detected.[/green]")

        prev_path = new_path


def _find_latest_report(target, config):
    """Find the most recent JSON output file for a target."""
    output_dir = config.get("output", {}).get("output_dir", "./output")
    prefix = target.replace(".", "_")
    json_files = sorted(
        Path(output_dir).glob(f"{prefix}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(json_files[0]) if json_files else None


def _diff_reports(old_path, new_path):
    """Compare two scan JSON files and return a diff dict."""
    try:
        with open(old_path) as f:
            old = json.load(f)
        with open(new_path) as f:
            new = json.load(f)
    except Exception:
        return None

    def _extract_findings(data):
        """Extract findings from either nested module dict or flat list."""
        findings = set()
        if isinstance(data, dict):
            for mod_name, mod_data in data.items():
                if isinstance(mod_data, dict):
                    for f in mod_data.get("findings", []):
                        key = f"{f.get('severity', 'info').lower()}|{f.get('title', '').strip()}"
                        findings.add(key)
                    # Also check flat findings list
                    if "findings" not in mod_data and "error" not in mod_data:
                        continue
        elif isinstance(data, list):
            for f in data:
                key = f"{f.get('severity', 'info').lower()}|{f.get('title', '').strip()}"
                findings.add(key)
        return findings

    def _extract_subdomains(data):
        subs = set()
        if isinstance(data, dict):
            sub_data = data.get("subdomains", {})
            if isinstance(sub_data, dict):
                for s in sub_data.get("subdomains", []):
                    subs.add(s)
            elif isinstance(sub_data, list):
                subs.update(sub_data)
        return subs

    old_findings = _extract_findings(old)
    new_findings = _extract_findings(new)
    old_subs = _extract_subdomains(old)
    new_subs = _extract_subdomains(new)

    return {
        "new_findings": new_findings - old_findings,
        "resolved_findings": old_findings - new_findings,
        "new_subdomains": new_subs - old_subs,
        "gone_subdomains": old_subs - new_subs,
    }


def _print_diff_table(diff, cycle):
    """Print a Rich table showing what changed between scans."""
    from rich.table import Table as RichTable

    has_changes = any(len(v) > 0 for v in diff.values())
    if not has_changes:
        console.print("  [green]No changes detected.[/green]")
        return

    table = RichTable(title=f"Changes — Cycle {cycle}", show_lines=True)
    table.add_column("Type", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Details")

    for label, key, style in [
        ("New Findings", "new_findings", "bold red"),
        ("Resolved Findings", "resolved_findings", "bold green"),
        ("New Subdomains", "new_subdomains", "yellow"),
        ("Gone Subdomains", "gone_subdomains", "dim"),
    ]:
        items = diff.get(key, set())
        if items:
            detail_list = sorted(items)
            detail_str = ", ".join(detail_list[:5])
            if len(detail_list) > 5:
                detail_str += f" (+{len(detail_list) - 5} more)"
            table.add_row(f"[{style}]{label}[/{style}]", str(len(items)), detail_str)

    console.print(table)
'''

# --- The call at the end of scan() to invoke monitor ---
# We insert this right before the function ends, after the report generation block
OLD_SCAN_REPORT_END = '''    # Auto-generate report if requested
    if report:
        from bssrecon.reporting.markdown_report import generate_markdown_report
        report_path = generate_markdown_report(target, results, config)
        print_success(f"Report generated: {report_path}")'''

NEW_SCAN_REPORT_END = '''    # Auto-generate report if requested
    report_path = None
    if report:
        from bssrecon.reporting.markdown_report import generate_markdown_report
        report_path = generate_markdown_report(target, results, config)
        print_success(f"Report generated: {report_path}")

    # Monitor mode — re-run scan on a loop and diff results
    if monitor > 0:
        json_path_for_monitor = output or os.path.join(
            output_dir,
            f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        _monitor_loop(
            target=target,
            interval_hours=monitor,
            active=active,
            modules=modules,
            recursive=report,
            first_report_path=json_path_for_monitor,
            config=config,
        )'''


# ============================================================
# PATCH 2: PDF format in the report command
# ============================================================

OLD_PDF_PLACEHOLDER = '''    elif fmt == "pdf":
        # PDF generation placeholder - we can add ReportLab PDF later
        print_warning(
            "PDF report generation coming in v1.1. "
            "For now, use markdown and convert with pandoc:\\n"
            "  pandoc report.md -o report.pdf --pdf-engine=xelatex"
        )'''

NEW_PDF_WORKING = '''    elif fmt == "pdf":
        try:
            from bssrecon.reporting.pdf_report import generate_pdf_report
            pdf_config = {
                "reporting": config.get("reporting", {}),
            }
            # Convert results dict to list-of-dicts format expected by pdf_report
            all_results = []
            for mod_name, mod_data in results.items():
                if isinstance(mod_data, dict) and "error" not in mod_data:
                    entry = dict(mod_data)
                    entry["module"] = mod_name
                    all_results.append(entry)

            report_dir = config.get("reporting", {}).get("report_dir", "./reports")
            os.makedirs(report_dir, exist_ok=True)
            pdf_path = os.path.join(
                report_dir,
                f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            )

            generated = generate_pdf_report(target, all_results, pdf_config, output_path=pdf_path)
            print_success(f"PDF report: {generated}")
        except ImportError:
            print_error(
                "PDF report requires reportlab. Install it:\\n"
                "  pip install reportlab"
            )
        except Exception as e:
            print_error(f"PDF generation failed: {e}")'''


def main():
    if not CLI_PY.exists():
        print(f"ERROR: {CLI_PY} not found")
        return

    content = CLI_PY.read_text()

    # Backup
    backup = CLI_PY.with_suffix(".py.bak")
    shutil.copy2(CLI_PY, backup)
    print(f"Backup saved: {backup}")

    patches_applied = 0

    # PATCH 1a: Add --monitor option to scan def
    if OLD_SCAN_DEF in content:
        content = content.replace(OLD_SCAN_DEF, NEW_SCAN_DEF)
        print("PATCH 1a: Added --monitor option to scan command")
        patches_applied += 1
    elif "monitor" in content and "HOURS" in content:
        print("PATCH 1a: --monitor option already present, skipping")
    else:
        print("WARNING: Could not find scan function signature to patch")

    # PATCH 1b: Add monitor call at end of scan()
    if OLD_SCAN_REPORT_END in content:
        content = content.replace(OLD_SCAN_REPORT_END, NEW_SCAN_REPORT_END)
        print("PATCH 1b: Added monitor invocation at end of scan()")
        patches_applied += 1
    elif "_monitor_loop(" in content:
        print("PATCH 1b: Monitor invocation already present, skipping")
    else:
        print("WARNING: Could not find report generation block to patch")

    # PATCH 1c: Add monitor functions after the scan command
    # Insert them right before the @cli.command() for the report command
    if "_monitor_loop" not in content:
        # Find the report command decorator
        report_marker = "\n@cli.command()\n@click.argument(\"target\")\n@click.option(\n    \"--format\""
        if report_marker in content:
            content = content.replace(report_marker, MONITOR_FUNCTIONS + "\n" + report_marker)
            print("PATCH 1c: Added monitor loop + diff functions")
            patches_applied += 1
        else:
            # Try alternate: just append before the report command
            alt_marker = "\n@cli.command()\n@click.argument(\"target\")"
            # Find the second occurrence (first is scan, second is report)
            first_idx = content.find(alt_marker)
            if first_idx >= 0:
                second_idx = content.find(alt_marker, first_idx + 1)
                if second_idx >= 0:
                    content = content[:second_idx] + MONITOR_FUNCTIONS + "\n" + content[second_idx:]
                    print("PATCH 1c: Added monitor loop + diff functions (alt insertion)")
                    patches_applied += 1
                else:
                    print("WARNING: Could not find report command to insert monitor functions before")
            else:
                print("WARNING: Could not find any @cli.command() markers")
    else:
        print("PATCH 1c: Monitor functions already present, skipping")

    # PATCH 2: PDF report format
    if OLD_PDF_PLACEHOLDER in content:
        content = content.replace(OLD_PDF_PLACEHOLDER, NEW_PDF_WORKING)
        print("PATCH 2: Wired pdf_report.py into report command")
        patches_applied += 1
    elif "generate_pdf_report" in content:
        print("PATCH 2: PDF report already wired, skipping")
    else:
        print("WARNING: Could not find PDF placeholder to patch")

    # Write
    CLI_PY.write_text(content)
    print(f"\nWrote {CLI_PY}")
    print(f"Total patches applied: {patches_applied}")
    print("")
    print("New capabilities:")
    print("  bssrecon scan target.com -r --monitor 6      # rescan every 6h, diff results")
    print("  bssrecon scan target.com -r --active --monitor 12")
    print("  bssrecon report target.com -f pdf             # PDF report via ReportLab")
    print("")
    print("Make sure reportlab is installed for PDF:")
    print("  pip install reportlab")


if __name__ == "__main__":
    main()
