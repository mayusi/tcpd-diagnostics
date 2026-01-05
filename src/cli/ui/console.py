"""Rich console wrapper and display utilities."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.style import Style
from typing import List

from ...core.result import DiagnosticsReport, ScanResult, Finding, Severity


# Global console instance
console = Console()

# Severity styles
SEVERITY_STYLES = {
    Severity.PASS: Style(color="green", bold=True),
    Severity.INFO: Style(color="blue"),
    Severity.WARNING: Style(color="yellow", bold=True),
    Severity.CRITICAL: Style(color="red", bold=True),
    Severity.UNKNOWN: Style(color="grey50", dim=True),
}

SEVERITY_ICONS = {
    Severity.PASS: "[green][PASS][/green]",
    Severity.INFO: "[blue][INFO][/blue]",
    Severity.WARNING: "[yellow][WARN][/yellow]",
    Severity.CRITICAL: "[red][CRIT][/red]",
    Severity.UNKNOWN: "[dim][????][/dim]",
}


def print_banner():
    """Print the application banner."""
    banner = """
+==============================================================+
|                          TCPD v1.0                           |
|          Tester's Comprehensive PC Diagnostics               |
+==============================================================+
"""
    console.print(banner, style="bold cyan")


def print_admin_status(is_admin: bool):
    """Print admin status indicator."""
    if is_admin:
        console.print("[green][OK] Running with Administrator privileges[/green]")
    else:
        console.print("[yellow][!] Running without Administrator privileges (some checks limited)[/yellow]")
    console.print()


def create_progress() -> Progress:
    """Create a progress bar for scanning."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )


def print_finding(finding: Finding):
    """Print a single finding."""
    icon = SEVERITY_ICONS.get(finding.severity, "[dim][????][/dim]")
    console.print(f"  {icon} {finding.title}")
    if finding.description and finding.severity in (Severity.WARNING, Severity.CRITICAL):
        console.print(f"      [dim]{finding.description}[/dim]")
    if finding.recommendation:
        console.print(f"      [cyan]-> {finding.recommendation}[/cyan]")


def print_scan_result(result: ScanResult):
    """Print results from a single scanner."""
    status = "[green][OK][/green]" if result.success else "[red][X][/red]"
    console.print(f"\n{status} [bold]{result.scanner_name}[/bold] ({result.duration_ms:.0f}ms)")

    if result.error:
        console.print(f"  [red]Error: {result.error}[/red]")
    else:
        for finding in result.findings:
            print_finding(finding)


def print_category_header(category: str):
    """Print a category section header."""
    console.print(f"\n[bold cyan]=== {category.upper()} ===[/bold cyan]")


def print_report(report: DiagnosticsReport):
    """Print the full diagnostics report."""
    console.print()
    print_banner()

    # Group results by category
    categories = {}
    for result in report.results:
        cat = result.category.upper()
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(result)

    # Print each category
    for category, results in categories.items():
        print_category_header(category)
        for result in results:
            print_scan_result(result)

    # Print summary
    print_summary(report)


def print_summary(report: DiagnosticsReport):
    """Print summary statistics."""
    console.print("\n" + "=" * 60)
    console.print("[bold]SUMMARY[/bold]")
    console.print("=" * 60)

    # Stats table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")

    table.add_row("Total Scanners", str(len(report.results)))
    table.add_row("Scan Duration", f"{report.total_duration_ms:.0f}ms")
    table.add_row("[green]Passed[/green]", f"[green]{report.pass_count}[/green]")
    table.add_row("[yellow]Warnings[/yellow]", f"[yellow]{report.warning_count}[/yellow]")
    table.add_row("[red]Critical[/red]", f"[red]{report.critical_count}[/red]")

    console.print(table)

    # Overall status
    console.print()
    if report.critical_count > 0:
        console.print("[red bold][!!] CRITICAL ISSUES FOUND - Immediate attention required![/red bold]")
    elif report.warning_count > 0:
        console.print("[yellow bold][!] Warnings detected - Review recommended[/yellow bold]")
    else:
        console.print("[green bold][OK] System appears healthy[/green bold]")
    console.print()


def print_system_info(info: dict):
    """Print system information table."""
    table = Table(title="System Information", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    for key, value in info.items():
        table.add_row(key, str(value))

    console.print(table)


def print_error(message: str):
    """Print an error message."""
    console.print(f"[red bold]Error:[/red bold] {message}")


def print_success(message: str):
    """Print a success message."""
    console.print(f"[green][OK][/green] {message}")


def print_warning(message: str):
    """Print a warning message."""
    console.print(f"[yellow][!][/yellow] {message}")


def print_info(message: str):
    """Print an info message."""
    console.print(f"[blue][i][/blue] {message}")


def clear_screen():
    """Clear the terminal screen."""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def wait_for_key(message: str = "Press Enter to continue..."):
    """Wait for user to press a key."""
    console.print()
    console.input(f"[dim]{message}[/dim]")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt user for yes/no answer."""
    default_str = "Y/n" if default else "y/N"
    response = console.input(f"{question} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ('y', 'yes')


def prompt_filename(default: str = None) -> str:
    """Prompt user for a filename."""
    if default:
        response = console.input(f"Filename [{default}]: ").strip()
        return response if response else default
    else:
        return console.input("Filename: ").strip()


def print_menu_header():
    """Print the interactive menu header."""
    banner = """
+==============================================================+
|                          TCPD v1.0                           |
|          Use UP/DOWN arrows to navigate, Enter to select     |
+==============================================================+
"""
    console.print(banner, style="bold cyan")
