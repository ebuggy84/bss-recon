"""
MONITOR FLAG PATCH for bssrecon/cli.py
=======================================
Adds --monitor HOURS to the `scan` command so the tool re-runs on a schedule
and prints a change summary after each cycle. Uses the existing diff module.

HOW TO APPLY
------------
Three edits to bssrecon/cli.py:

  EDIT 1 — add import at the top of the file
  EDIT 2 — add @click.option for --monitor to the scan command decorator
  EDIT 3 — add the loop call at the end of scan(), plus the two helper functions

Each edit shows EXACTLY what to find and what to replace it with.
"""


# =============================================================================
# EDIT 1 — ADD IMPORT
# =============================================================================
#
# Find this block near the top of cli.py (the existing time import may or
# may not be there — add only what is missing):
#
# ── BEFORE ───────────────────────────────────────────────────────────────────
#
#   import json
#   import os
#   from datetime import datetime
#   from pathlib import Path
#
# ── AFTER ────────────────────────────────────────────────────────────────────
#
#   import json
#   import os
#   import time                          # ← ADD THIS LINE
#   from datetime import datetime
#   from pathlib import Path
#
# =============================================================================


# =============================================================================
# EDIT 2 — ADD --monitor OPTION TO THE scan COMMAND DECORATOR
# =============================================================================
#
# Find the existing @cli.command() / @click.option block for `scan`.
# It will look something like this (exact options may differ):
#
# ── BEFORE ───────────────────────────────────────────────────────────────────
#
#   @cli.command()
#   @click.argument("target")
#   @click.option("-r", "--recursive", is_flag=True, ...)
#   @click.option("--active", is_flag=True, ...)
#   @click.option("-m", "--modules", default=None, ...)
#   def scan(target, recursive, active, modules):
#
# ── AFTER ────────────────────────────────────────────────────────────────────
#
#   @cli.command()
#   @click.argument("target")
#   @click.option("-r", "--recursive", is_flag=True, ...)
#   @click.option("--active", is_flag=True, ...)
#   @click.option("-m", "--modules", default=None, ...)
#   @click.option(                                          # ← ADD THESE 7 LINES
#       "--monitor",
#       default=0,
#       type=int,
#       metavar="HOURS",
#       help="Re-run scan every N hours and alert on changes (0 = run once).",
#   )
#   def scan(target, recursive, active, modules, monitor): # ← ADD monitor param
#
# =============================================================================


# =============================================================================
# EDIT 3 — ADD LOOP CALL AT THE END OF scan(), PLUS TWO HELPER FUNCTIONS
# =============================================================================
#
# ── BEFORE (the very last lines of the scan() function) ──────────────────────
#
#   def scan(target, recursive, active, modules, monitor):
#       # ... all the existing scan logic ...
#
#       # (last line before the function ends — often a console.print or return)
#       console.print(f"  report  → {report_path}")
#
#
#   # (next function or end of file)
#
# ── AFTER ────────────────────────────────────────────────────────────────────
#
#   def scan(target, recursive, active, modules, monitor):
#       # ... all the existing scan logic ...
#
#       console.print(f"  report  → {report_path}")
#
#       # ── PASTE FROM HERE ──────────────────────────────────────────────────
#       if monitor > 0:
#           _monitor_loop(
#               target=target,
#               interval_hours=monitor,
#               active=active,
#               modules=modules,
#               recursive=recursive,
#               first_report_path=report_path,   # pass the path cli.py already has
#           )
#       # ── PASTE TO HERE ────────────────────────────────────────────────────
#
#
# Then paste _monitor_loop() and _diff_reports() OUTSIDE the scan() function,
# immediately after it.
#
# =============================================================================


import json
import time
from pathlib import Path


def _monitor_loop(
    target: str,
    interval_hours: int,
    active: bool,
    modules,               # str | None — whatever the -m option received
    recursive: bool,
    first_report_path,     # Path | str — report.json from the scan() that just ran
) -> None:
    """
    Re-run the scan every interval_hours and print a change summary.
    Loops until Ctrl+C.

    Paste this function into cli.py immediately after the scan() function.
    """
    # Import inside function to avoid circular-import issues at module load time.
    from rich.console import Console
    from rich.table import Table
    from rich import box as rich_box

    # Import the Click CLI object so we can invoke scan() programmatically
    # without spawning a subprocess.
    from bssrecon.cli import cli as _bss_cli
    from click.testing import CliRunner

    console = Console()
    interval_secs = interval_hours * 3600
    prev_report_path = Path(first_report_path)
    run_number = 1

    console.print()
    console.print(
        f"[bold cyan]Monitor mode active[/bold cyan] — "
        f"[bold]{target}[/bold] will be re-scanned every "
        f"[bold]{interval_hours}h[/bold]. Press [bold]Ctrl+C[/bold] to stop."
    )

    while True:
        # ── Sleep with a live countdown ───────────────────────────────────
        console.print(
            f"\n[dim]Next scan in {interval_hours}h "
            f"({interval_hours * 60} min). Sleeping...[/dim]"
        )
        try:
            time.sleep(interval_secs)
        except KeyboardInterrupt:
            console.print("\n[bold red]Monitor stopped by user.[/bold red]")
            return

        run_number += 1
        console.print(
            f"\n[bold yellow]{'─' * 60}[/bold yellow]"
            f"\n[bold yellow]Monitor run #{run_number} — {target}[/bold yellow]"
            f"\n[bold yellow]{'─' * 60}[/bold yellow]\n"
        )

        # ── Re-invoke the scan via Click's test runner ────────────────────
        # CliRunner re-enters the CLI in-process (same venv, no subprocess).
        # We catch its output and re-print it so the user sees scan progress.
        args = ["scan", target]
        if recursive:
            args.append("-r")
        if active:
            args.append("--active")
        if modules:
            args += ["-m", modules]
        # Do NOT pass --monitor — avoids infinite recursion.

        runner = CliRunner(mix_stderr=False)
        try:
            result = runner.invoke(_bss_cli, args, catch_exceptions=False)
        except KeyboardInterrupt:
            console.print("\n[bold red]Monitor stopped during scan.[/bold red]")
            return
        except Exception as exc:
            console.print(f"[red]Scan failed on run #{run_number}: {exc}[/red]")
            continue

        if result.output:
            console.print(result.output.rstrip())

        # ── Locate the new report.json ────────────────────────────────────
        # The scan writes report.json inside a timestamped directory under
        # ./output/ or ./reports/ — find the most recently modified one.
        new_report_path = _find_latest_report(target)
        if not new_report_path:
            console.print(
                "[yellow]  Could not locate new report.json — skipping diff.[/yellow]"
            )
            continue

        # ── Diff the two reports ──────────────────────────────────────────
        changes = _diff_reports(prev_report_path, new_report_path)
        prev_report_path = new_report_path

        # ── Print change summary ──────────────────────────────────────────
        console.print()
        console.print(f"[bold]Change summary — run #{run_number}[/bold]")

        if not any(changes.values()):
            console.print("  [green]No changes detected.[/green]")
            continue

        tbl = Table(box=rich_box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column("Category",  style="cyan",  no_wrap=True)
        tbl.add_column("Change",    style="white")
        tbl.add_column("Details",   style="dim",   overflow="fold")

        for row in _format_change_rows(changes):
            tbl.add_row(*row)

        console.print(tbl)

        # Alert on any new high/critical findings
        new_high = [
            f for f in changes.get("new_findings", [])
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if new_high:
            console.print(
                f"[bold red]  ⚠  {len(new_high)} new CRITICAL/HIGH finding(s) — "
                "review immediately.[/bold red]"
            )


def _find_latest_report(target: str) -> Path | None:
    """
    Scan common output locations for the most recently written report.json
    that belongs to *target*.

    Paste this function into cli.py immediately after _monitor_loop().
    """
    safe = target.replace(".", "_").replace(":", "_").replace("/", "_")
    candidates: list[Path] = []

    for base in (Path("./output"), Path("./reports")):
        # Pattern: output/<target>_<timestamp>/report.json
        candidates += list(base.glob(f"{safe}*/report.json"))
        candidates += list(base.glob(f"{target}*/report.json"))
        # Pattern: output/<target>/report.json
        candidates += list((base / target).glob("**/report.json"))
        candidates += list((base / safe).glob("**/report.json"))

    if not candidates:
        return None

    return max(candidates, key=lambda p: p.stat().st_mtime)


def _diff_reports(prev_path: Path, curr_path: Path) -> dict:
    """
    Compare two report.json files and return a structured diff dict.

    Understands the bssrecon report schema:
      {
        "domain": str,
        "modules": {
          "<module_name>": {"findings": [...], ...},
          ...
        }
      }

    Returns:
      {
        "new_findings":     list[finding dict],
        "resolved_findings":list[finding dict],
        "new_subdomains":   list[str],
        "gone_subdomains":  list[str],
        "new_ports":        list[str],   e.g. ["443/tcp", "8080/tcp"]
        "closed_ports":     list[str],
        "finding_delta":    int,         positive = more findings this run
      }

    Paste this function into cli.py immediately after _find_latest_report().
    """

    def _load(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    prev = _load(prev_path)
    curr = _load(curr_path)

    # ── Extract findings from both reports ────────────────────────────────
    def _all_findings(report: dict) -> list[dict]:
        findings = []
        modules = report.get("modules", {})
        if isinstance(modules, dict):
            for mod_data in modules.values():
                if isinstance(mod_data, dict):
                    findings.extend(mod_data.get("findings", []))
        # Flat schema fallback: report has a top-level "findings" list
        findings.extend(report.get("findings", []))
        return findings

    def _finding_key(f: dict) -> str:
        # Stable identity: severity + title (detail may change between runs)
        return f"{f.get('severity','').lower()}|{f.get('title','').lower().strip()}"

    prev_findings = {_finding_key(f): f for f in _all_findings(prev)}
    curr_findings = {_finding_key(f): f for f in _all_findings(curr)}

    new_findings      = [f for k, f in curr_findings.items() if k not in prev_findings]
    resolved_findings = [f for k, f in prev_findings.items() if k not in curr_findings]

    # ── Subdomains ────────────────────────────────────────────────────────
    def _subdomains(report: dict) -> set[str]:
        raw = (
            report.get("subdomains", [])
            or report.get("modules", {}).get("subdomains", {}).get("subdomains", [])
        )
        if isinstance(raw, list):
            return {str(s).lower() for s in raw}
        return set()

    prev_subs = _subdomains(prev)
    curr_subs = _subdomains(curr)
    new_subdomains  = sorted(curr_subs - prev_subs)
    gone_subdomains = sorted(prev_subs - curr_subs)

    # ── Open ports (from nmap module if present) ──────────────────────────
    def _ports(report: dict) -> set[str]:
        ports: set[str] = set()
        nmap_data = report.get("modules", {}).get("nmap", {})
        for f in nmap_data.get("findings", []):
            nmap_meta = f.get("_nmap", {})
            if nmap_meta:
                ports.add(f"{nmap_meta.get('port')}/{nmap_meta.get('protocol','tcp')}")
        return ports

    prev_ports = _ports(prev)
    curr_ports = _ports(curr)
    new_ports    = sorted(curr_ports - prev_ports)
    closed_ports = sorted(prev_ports - curr_ports)

    return {
        "new_findings":      new_findings,
        "resolved_findings": resolved_findings,
        "new_subdomains":    new_subdomains,
        "gone_subdomains":   gone_subdomains,
        "new_ports":         new_ports,
        "closed_ports":      closed_ports,
        "finding_delta":     len(curr_findings) - len(prev_findings),
    }


def _format_change_rows(changes: dict) -> list[tuple[str, str, str]]:
    """
    Convert the diff dict into (category, change, details) row tuples
    suitable for a Rich Table.

    Paste this function into cli.py immediately after _diff_reports().
    """
    rows: list[tuple[str, str, str]] = []
    sev_order = ["critical", "high", "medium", "low", "info"]

    # New findings — grouped by severity
    if changes["new_findings"]:
        by_sev: dict[str, list] = {s: [] for s in sev_order}
        for f in changes["new_findings"]:
            by_sev.setdefault(f.get("severity", "info").lower(), []).append(f)
        for sev in sev_order:
            group = by_sev.get(sev, [])
            if not group:
                continue
            titles = "; ".join(f.get("title", "")[:60] for f in group[:3])
            if len(group) > 3:
                titles += f" (+{len(group) - 3} more)"
            rows.append((
                "New findings",
                f"[red]+{len(group)} {sev}[/red]" if sev in ("critical", "high")
                else f"+{len(group)} {sev}",
                titles,
            ))

    # Resolved findings
    if changes["resolved_findings"]:
        rows.append((
            "Resolved",
            f"[green]-{len(changes['resolved_findings'])}[/green]",
            "; ".join(
                f.get("title", "")[:60]
                for f in changes["resolved_findings"][:3]
            ),
        ))

    # Subdomains
    if changes["new_subdomains"]:
        rows.append((
            "New subdomains",
            f"+{len(changes['new_subdomains'])}",
            ", ".join(changes["new_subdomains"][:5]),
        ))
    if changes["gone_subdomains"]:
        rows.append((
            "Gone subdomains",
            f"-{len(changes['gone_subdomains'])}",
            ", ".join(changes["gone_subdomains"][:5]),
        ))

    # Ports
    if changes["new_ports"]:
        rows.append((
            "New open ports",
            f"[red]+{len(changes['new_ports'])}[/red]",
            ", ".join(changes["new_ports"]),
        ))
    if changes["closed_ports"]:
        rows.append((
            "Closed ports",
            f"[green]-{len(changes['closed_ports'])}[/green]",
            ", ".join(changes["closed_ports"]),
        ))

    return rows
