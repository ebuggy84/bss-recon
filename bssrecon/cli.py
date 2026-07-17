"""
BSS Recon - Main CLI

This is the entry point. All commands go through here.

Usage:
  python -m bssrecon scan example.com
  python -m bssrecon scan example.com --modules whois,dns,subdomains
  python -m bssrecon report example.com
  python -m bssrecon ingest nmap scan_results.xml
  python -m bssrecon checklist
  python -m bssrecon modules
"""
import click
import json
import os
import time
from datetime import datetime
from pathlib import Path

from bssrecon.config import load_config, get_api_key
from bssrecon.utils.display import (
    print_banner,
    print_section,
    print_success,
    print_error,
    print_warning,
    print_progress,
    print_scan_summary,
    print_table,
    print_key_value,
    console,
)


@click.group()
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.pass_context
def cli(ctx, config):
    """BSS Recon - Burgohy Security Solutions Reconnaissance Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.argument("target")
@click.option(
    "--modules", "-m",
    default=None,
    help="Comma-separated list of modules to run (default: all available)",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output JSON results to file",
)
@click.option(
    "--report", "-r",
    is_flag=True,
    help="Auto-generate report after scan",
)
@click.option(
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
def scan(ctx, target, modules, output, report, active, monitor):
    """Run reconnaissance modules against a target domain.

    By default, only PASSIVE modules run (no direct contact with target).
    Use --active to include modules that make requests to the target server.
    Only use --active on targets you have authorization to test.

    Examples:
      bssrecon scan example.com -r              (passive OSINT only)
      bssrecon scan example.com -r --active      (full scan, needs permission)
      bssrecon scan example.com -m whois,dns,ssl (specific modules)
    """
    config = ctx.obj["config"]
    print_banner()

    # Display scan mode
    if active:
        console.print(
            "  Mode:   [bold yellow]ACTIVE[/bold yellow] "
            "[dim](making requests to target - authorization required)[/dim]"
        )
    else:
        console.print(
            "  Mode:   [bold green]PASSIVE[/bold green] "
            "[dim](OSINT only - no direct contact with target)[/dim]"
        )

    console.print(f"  Target: [bold white]{target}[/bold white]")
    console.print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print("")

    # Load available modules
    from bssrecon.core import MODULE_REGISTRY

    # Determine which modules to run
    if modules:
        module_names = [m.strip() for m in modules.split(",")]
    else:
        module_names = config.get("default_modules", list(MODULE_REGISTRY.keys()))

    # Validate module names
    valid_modules = []
    skipped_active = []
    for name in module_names:
        if name in MODULE_REGISTRY:
            module_cls = MODULE_REGISTRY[name]
            module_instance = module_cls(config)

            # Check if this is an active module being run without --active flag
            if module_instance.mode == "active" and not active:
                skipped_active.append(name)
                continue

            if module_instance.is_available():
                valid_modules.append((name, module_instance))
            else:
                print_warning(
                    f"[SKIP] {name} module skipped — no API key configured in config.yaml "
                    f"(set '{module_instance.api_key_name}' in config.yaml)"
                )
        else:
            print_warning(f"Unknown module: '{name}'. Skipping.")

    if skipped_active:
        console.print(
            f"  [dim]Skipped active modules (use --active to enable): "
            f"{', '.join(skipped_active)}[/dim]\n"
        )

    if not valid_modules:
        print_error("No valid modules to run. Check your config.")
        return

    console.print(
        f"  Modules: [cyan]{', '.join(n for n, _ in valid_modules)}[/cyan]\n"
    )

    # Run each module
    results = {}
    start_time = time.time()

    for name, module_instance in valid_modules:
        try:
            module_results = module_instance.run(target)
            results[name] = module_results
        except KeyboardInterrupt:
            print_warning("Scan interrupted by user")
            break
        except Exception as e:
            print_error(f"Module '{name}' crashed: {str(e)}")
            results[name] = {"error": str(e)}

    elapsed = time.time() - start_time
    print_scan_summary(target, results, elapsed)

    # Save raw JSON output
    output_dir = config.get("output", {}).get("output_dir", "./output")
    if config.get("output", {}).get("save_json", True) or output:
        os.makedirs(output_dir, exist_ok=True)
        json_path = output or os.path.join(
            output_dir,
            f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        # Make results JSON serializable
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Results saved: {json_path}")

    # Auto-generate report if requested
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
        )


@cli.command()
@click.argument("target")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["markdown", "md", "pdf"]),
    default="markdown",
    help="Report format",
)
@click.option(
    "--input", "-i", "input_file",
    default=None,
    help="Path to JSON results file (from a previous scan)",
)
@click.pass_context
def report(ctx, target, fmt, input_file):
    """Generate a report from scan results.

    Examples:
      bssrecon report example.com
      bssrecon report example.com -f pdf
      bssrecon report example.com -i output/example_com_20260703.json
    """
    config = ctx.obj["config"]
    print_banner()

    # Load results
    if input_file:
        print_progress(f"Loading results from {input_file}")
        with open(input_file, "r") as f:
            results = json.load(f)
    else:
        # Try to find the most recent scan for this target
        output_dir = config.get("output", {}).get("output_dir", "./output")
        prefix = target.replace(".", "_")
        json_files = sorted(
            Path(output_dir).glob(f"{prefix}_*.json"),
            reverse=True,
        )
        if json_files:
            print_progress(f"Loading most recent scan: {json_files[0]}")
            with open(json_files[0], "r") as f:
                results = json.load(f)
        else:
            print_error(
                f"No scan results found for {target}. "
                f"Run a scan first: bssrecon scan {target}"
            )
            return

    if fmt in ("markdown", "md"):
        from bssrecon.reporting.markdown_report import generate_markdown_report
        report_path = generate_markdown_report(target, results, config)
        print_success(f"Markdown report: {report_path}")
    elif fmt == "pdf":
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
                "PDF report requires reportlab. Install it:\n"
                "  pip install reportlab"
            )
        except Exception as e:
            print_error(f"PDF generation failed: {e}")


@cli.command()
@click.argument("tool_type", type=click.Choice(["nmap", "burp"]))
@click.argument("filepath")
@click.option("--output", "-o", default=None, help="Save parsed results to JSON")
@click.pass_context
def ingest(ctx, tool_type, filepath, output):
    """Import and parse output from external tools.

    Examples:
      bssrecon ingest nmap scan_results.xml
      bssrecon ingest nmap scan_results.xml -o parsed.json
    """
    print_banner()

    if tool_type == "nmap":
        from bssrecon.ingest.nmap_parser import parse_nmap_xml
        results = parse_nmap_xml(filepath)
    elif tool_type == "burp":
        print_warning("Burp Suite parser coming in v1.1")
        return
    else:
        print_error(f"Unknown tool type: {tool_type}")
        return

    if output and results:
        with open(output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print_success(f"Parsed results saved: {output}")


@cli.command()
@click.option("--category", "-c", default=None, help="Filter by OWASP category (e.g. A01)")
def checklist(category):
    """Show OWASP Top 10 testing checklist.

    Use this during engagements to make sure you're covering everything.

    Examples:
      bssrecon checklist
      bssrecon checklist -c A01
    """
    from bssrecon.frameworks.owasp import OWASP_TOP_10

    print_banner()
    print_section("OWASP Top 10 (2021) Testing Checklist", "📋")

    for cat_id, cat_data in OWASP_TOP_10.items():
        if category and not cat_id.startswith(category.upper()):
            continue

        console.print(f"\n  [bold cyan]{cat_id}[/bold cyan] - {cat_data['name']}")
        console.print(f"  {cat_data['description'][:100]}...", style="dim")
        for check in cat_data["test_checks"]:
            console.print(f"    [ ] {check}")


@cli.command(name="modules")
@click.pass_context
def list_modules(ctx):
    """List all available recon modules and their status."""
    config = ctx.obj["config"]
    print_banner()
    print_section("Available Modules", "🧩")

    from bssrecon.core import MODULE_REGISTRY

    rows = []
    for name, cls in MODULE_REGISTRY.items():
        instance = cls(config)
        available = instance.is_available()
        status = "✓ Ready" if available else "✗ Needs API Key"
        status_color = "green" if available else "red"
        mode_tag = (
            "[green]PASSIVE[/green]" if instance.mode == "passive"
            else "[yellow]ACTIVE[/yellow]"
        )
        rows.append((
            name,
            cls.description,
            mode_tag,
            f"[{status_color}]{status}[/{status_color}]",
        ))

    print_table(
        "Registered Modules",
        [("Module", "cyan"), ("Description", "white"), ("Mode", ""), ("Status", "")],
        rows,
    )

    console.print(
        "\n  [green]PASSIVE[/green] = OSINT only, no direct contact with target",
        style="",
    )
    console.print(
        "  [yellow]ACTIVE[/yellow]  = makes requests to target (use --active flag)",
        style="",
    )
    console.print(
        "\n  Usage:",
        style="dim",
    )
    console.print(
        "    bssrecon scan target.com -r            (passive only)",
        style="dim",
    )
    console.print(
        "    bssrecon scan target.com -r --active   (full scan, needs permission)",
        style="dim",
    )


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
