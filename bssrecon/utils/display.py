"""
Terminal display utilities using Rich library.
Makes CLI output look clean and professional.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box
from datetime import datetime

console = Console()


def print_banner():
    """Print the BSS Recon banner."""
    banner = """
 ██████╗ ███████╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝███████╗███████╗    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗╚════██║╚════██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██████╔╝███████║███████║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
    """
    console.print(banner, style="bold cyan")
    console.print(
        "  Burgohy Security Solutions - Reconnaissance Toolkit v1.0",
        style="dim white",
    )
    console.print(
        f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim white"
    )


def print_section(title, icon="🔍"):
    """Print a section header."""
    console.print(f"\n{icon} [bold cyan]{title}[/bold cyan]")
    console.print("─" * 60, style="dim")


def print_finding(severity, title, detail=""):
    """Print a single finding with severity color coding."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim white",
    }
    style = colors.get(severity.lower(), "white")
    severity_tag = f"[{style}][{severity.upper()}][/{style}]"
    console.print(f"  {severity_tag} {title}")
    if detail:
        console.print(f"         {detail}", style="dim")


def print_key_value(key, value, indent=2):
    """Print a key-value pair."""
    spaces = " " * indent
    console.print(f"{spaces}[cyan]{key}:[/cyan] {value}")


def print_table(title, columns, rows):
    """Print a formatted table."""
    table = Table(title=title, box=box.ROUNDED, border_style="cyan")
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)


def print_dns_results(records):
    """Print DNS records in a clean table."""
    if not records:
        console.print("  No DNS records found.", style="dim")
        return

    table = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan")
    table.add_column("Type", style="bold cyan", width=8)
    table.add_column("Record", style="white")
    table.add_column("TTL", style="dim", width=8)

    for record in records:
        table.add_row(
            record.get("type", ""),
            record.get("value", ""),
            str(record.get("ttl", "")),
        )
    console.print(table)


def print_subdomain_results(subdomains):
    """Print subdomain enumeration results."""
    if not subdomains:
        console.print("  No subdomains found.", style="dim")
        return

    table = Table(
        title=f"Subdomains Found ({len(subdomains)})",
        box=box.ROUNDED,
        border_style="cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Subdomain", style="white")
    table.add_column("First Seen", style="dim")

    for i, sub in enumerate(subdomains[:50], 1):  # Show first 50
        table.add_row(
            str(i),
            sub.get("name", ""),
            sub.get("first_seen", ""),
        )

    console.print(table)
    if len(subdomains) > 50:
        console.print(
            f"  ... and {len(subdomains) - 50} more (see full output in JSON)",
            style="dim",
        )


def print_ssl_results(cert_info):
    """Print SSL certificate analysis."""
    if not cert_info:
        console.print("  Could not retrieve SSL certificate.", style="dim")
        return

    panel_content = Text()
    panel_content.append(f"Subject:     {cert_info.get('subject', 'N/A')}\n")
    panel_content.append(f"Issuer:      {cert_info.get('issuer', 'N/A')}\n")
    panel_content.append(f"Valid From:  {cert_info.get('not_before', 'N/A')}\n")
    panel_content.append(f"Valid Until: {cert_info.get('not_after', 'N/A')}\n")
    panel_content.append(f"Serial:      {cert_info.get('serial', 'N/A')}\n")
    panel_content.append(f"Version:     {cert_info.get('version', 'N/A')}\n")

    # Color the expiry status
    days_left = cert_info.get("days_until_expiry", 0)
    if days_left < 0:
        status = f"EXPIRED ({abs(days_left)} days ago)"
        panel_content.append(f"Status:      ", style="white")
        panel_content.append(status, style="bold red")
    elif days_left < 30:
        status = f"EXPIRING SOON ({days_left} days)"
        panel_content.append(f"Status:      ", style="white")
        panel_content.append(status, style="yellow")
    else:
        status = f"Valid ({days_left} days remaining)"
        panel_content.append(f"Status:      ", style="white")
        panel_content.append(status, style="green")

    if cert_info.get("san"):
        panel_content.append(f"\n\nSubject Alt Names:\n")
        for san in cert_info["san"][:20]:
            panel_content.append(f"  • {san}\n")

    console.print(
        Panel(panel_content, title="SSL/TLS Certificate", border_style="cyan")
    )


def print_whois_results(whois_data):
    """Print WHOIS registration data."""
    if not whois_data:
        console.print("  WHOIS lookup failed.", style="dim")
        return

    fields = [
        ("Registrar", "registrar"),
        ("Created", "creation_date"),
        ("Updated", "updated_date"),
        ("Expires", "expiration_date"),
        ("Name Servers", "name_servers"),
        ("Status", "status"),
        ("Registrant Org", "org"),
        ("Registrant Country", "country"),
        ("DNSSEC", "dnssec"),
    ]

    for label, key in fields:
        value = whois_data.get(key, "N/A")
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        print_key_value(label, value)


def print_scan_summary(target, results, elapsed):
    """Print the final scan summary."""
    console.print(f"\n{'═' * 60}", style="cyan")
    console.print(
        f"  Scan Complete: [bold]{target}[/bold]", style="cyan"
    )
    console.print(f"  Duration: {elapsed:.1f}s", style="dim")

    # Count findings by module
    for module_name, module_results in results.items():
        if isinstance(module_results, dict):
            status = "✓" if not module_results.get("error") else "✗"
            color = "green" if status == "✓" else "red"
            console.print(f"  [{color}]{status}[/{color}] {module_name}")

    console.print(f"{'═' * 60}\n", style="cyan")


def print_error(message):
    """Print an error message."""
    console.print(f"  [bold red]ERROR:[/bold red] {message}")


def print_warning(message):
    """Print a warning message."""
    console.print(f"  [yellow]WARNING:[/yellow] {message}")


def print_success(message):
    """Print a success message."""
    console.print(f"  [green]✓[/green] {message}")


def print_progress(message):
    """Print a progress/status message."""
    console.print(f"  [dim]→ {message}[/dim]")
