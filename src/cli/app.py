"""Main CLI application."""
import typer
from typing import Optional
from pathlib import Path
import sys

from ..core.engine import ScanEngine
from ..core.result import DiagnosticsReport
from ..utils.admin import is_admin, request_elevation
from .ui.console import (
    console, print_banner, print_admin_status,
    print_report, print_error, print_success, print_info, print_warning,
    create_progress
)

# Import all scanners
from ..scanners.hardware.cpu import CPUScanner
from ..scanners.hardware.gpu import GPUScanner
from ..scanners.hardware.memory import MemoryScanner
from ..scanners.hardware.storage import StorageScanner
from ..scanners.hardware.battery import BatteryScanner
from ..scanners.hardware.motherboard import MotherboardScanner
from ..scanners.hardware.network_adapters import NetworkAdaptersScanner
from ..scanners.hardware.peripherals import PeripheralsScanner
from ..scanners.security.antivirus import AntivirusScanner
from ..scanners.security.firewall import FirewallScanner
from ..scanners.security.windows_update import WindowsUpdateScanner
from ..scanners.security.ports import PortsScanner
from ..scanners.security.processes import ProcessesScanner
from ..scanners.security.startup import StartupScanner
from ..scanners.security.services import ServicesScanner
from ..scanners.security.users import UsersScanner
from ..scanners.security.bitlocker import BitLockerScanner
from ..scanners.security.secure_boot import SecureBootScanner
from ..scanners.security.uac import UACScanner
from ..scanners.security.password_policy import PasswordPolicyScanner
from ..scanners.security.event_log import EventLogScanner
from ..scanners.system.os_info import OSInfoScanner
# Network scanners
from ..scanners.network.connectivity import ConnectivityScanner
from ..scanners.network.wifi import WiFiScanner
from ..scanners.network.dns import DNSScanner
from ..scanners.network.speed_test import SpeedTestScanner


app = typer.Typer(
    name="tcpd",
    help="TCPD - Tester's Comprehensive PC Diagnostics",
    add_completion=False,
    invoke_without_command=True
)


@app.callback()
def main_callback(ctx: typer.Context):
    """PC Diagnostics Tool - Run without arguments for interactive mode."""
    if ctx.invoked_subcommand is None:
        # No command specified, launch interactive mode
        from .interactive import run_interactive_mode
        run_interactive_mode()


def get_all_scanners():
    """Get instances of all available scanners."""
    return [
        # Hardware
        CPUScanner(),
        GPUScanner(),
        MemoryScanner(),
        StorageScanner(),
        BatteryScanner(),
        MotherboardScanner(),
        NetworkAdaptersScanner(),
        PeripheralsScanner(),
        # Security
        AntivirusScanner(),
        FirewallScanner(),
        WindowsUpdateScanner(),
        PortsScanner(),
        ProcessesScanner(),
        StartupScanner(),
        ServicesScanner(),
        UsersScanner(),
        BitLockerScanner(),
        SecureBootScanner(),
        UACScanner(),
        PasswordPolicyScanner(),
        EventLogScanner(),
        # Network
        ConnectivityScanner(),
        WiFiScanner(),
        DNSScanner(),
        SpeedTestScanner(),
        # System
        OSInfoScanner(),
    ]


@app.command()
def scan(
    mode: str = typer.Option(
        "quick",
        "--mode", "-m",
        help="Scan mode: quick, full, hardware, security, network"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for JSON export"
    ),
    no_elevate: bool = typer.Option(
        False,
        "--no-elevate",
        help="Don't request admin elevation"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed output"
    )
):
    """Run PC diagnostics scan."""

    # Check/request admin
    admin_status = is_admin()
    if not admin_status and not no_elevate:
        print_info("Requesting administrator privileges for full diagnostics...")
        if request_elevation():
            return  # Will restart with admin
        print_warning("Running without admin - some checks will be limited")

    admin_status = is_admin()

    # Print header
    print_banner()
    print_admin_status(admin_status)

    # Initialize engine
    engine = ScanEngine(is_admin=admin_status)
    engine.register_scanners(get_all_scanners())

    print_info(f"Starting {mode} scan with {engine.scanner_count} scanners...")
    console.print()

    # Run scan with progress
    with create_progress() as progress:
        task = progress.add_task(f"Running {mode} scan...", total=100)

        def update_progress(current: int, total: int, name: str):
            if total > 0:
                pct = (current / total) * 100
                progress.update(task, completed=pct, description=f"Scanning: {name}")

        report = engine.run_scan(mode=mode, progress_callback=update_progress)

    # Display results
    print_report(report)

    # Export to JSON if requested
    if output:
        report.save_json(str(output))
        print_success(f"Report saved to {output}")


@app.command()
def quick():
    """Run quick scan (shortcut for --mode quick)."""
    scan(mode="quick")


@app.command()
def full():
    """Run full scan (shortcut for --mode full)."""
    scan(mode="full")


@app.command()
def hardware():
    """Run hardware-only scan."""
    scan(mode="hardware")


@app.command()
def security():
    """Run security-only scan."""
    scan(mode="security")


@app.command()
def network():
    """Run network-only scan."""
    scan(mode="network")


@app.command()
def interactive():
    """Launch interactive TUI mode with arrow-key navigation."""
    from .interactive import run_interactive_mode
    run_interactive_mode()


@app.command()
def version():
    """Show version information."""
    from .. import __version__
    console.print(f"TCPD - Tester's Comprehensive PC Diagnostics v{__version__}")
    console.print("Windows 10/11 compatible")


@app.command()
def list_scanners():
    """List all available scanners."""
    print_banner()
    scanners = get_all_scanners()

    from rich.table import Table
    table = Table(title="Available Scanners")
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Admin Required", style="yellow")

    for scanner in scanners:
        admin_req = "Yes" if scanner.requires_admin else "No"
        table.add_row(scanner.name, scanner.category, admin_req)

    console.print(table)


@app.command()
def install_deps():
    """Install required Python dependencies."""
    from ..utils.dependency_installer import (
        get_dependency_status, install_all_requirements, upgrade_pip
    )
    from rich.table import Table

    print_banner()
    console.print("\n[bold cyan]Dependency Manager[/bold cyan]\n")

    # Get current status
    status = get_dependency_status()

    table = Table(title="Dependency Status", show_header=True)
    table.add_column("Package", style="cyan")
    table.add_column("Status", style="white")

    for import_name, pip_name in status['installed_list']:
        table.add_row(pip_name, "[green][Installed][/green]")

    for import_name, pip_name in status['missing_list']:
        table.add_row(pip_name, "[red][Missing][/red]")

    console.print(table)
    console.print()
    console.print(f"Installed: [green]{status['installed']}[/green] / {status['total']}")
    console.print(f"Missing: [red]{status['missing']}[/red]")
    console.print()

    if status['missing'] == 0:
        print_success("All dependencies are installed!")
        return

    # Install all missing
    print_info("Installing all dependencies...")
    console.print()
    success, msg = install_all_requirements()
    if success:
        print_success(msg)
    else:
        print_error(msg)


@app.command()
def stress_cpu(
    duration: int = typer.Option(60, "--duration", "-d", help="Test duration in seconds")
):
    """Run CPU stress test."""
    from ..stress import CPUStressTest

    print_banner()
    console.print("\n[bold cyan]CPU Stress Test[/bold cyan]\n")

    stress = CPUStressTest()
    console.print(f"Stressing {stress.cpu_count} CPU cores for {duration} seconds...\n")

    with create_progress() as progress:
        task = progress.add_task("CPU Stress Test", total=duration)

        def cpu_progress(elapsed, stats):
            progress.update(task, completed=elapsed)
            temp_str = f"{stats['temperature']:.1f}C" if stats.get('temperature') else "N/A"
            progress.update(task, description=f"CPU: {stats['utilization']:.0f}% | Temp: {temp_str}")

        result = stress.run(duration=duration, progress_callback=cpu_progress)

    console.print()
    if result.passed:
        print_success("CPU Stress Test PASSED")
    else:
        print_error(f"CPU Stress Test FAILED: {result.error}")

    console.print(f"\nResults:")
    console.print(f"  Cores Tested: {result.cores_tested}")
    console.print(f"  Max Utilization: {result.max_utilization:.1f}%")
    if result.max_temperature:
        console.print(f"  Max Temperature: {result.max_temperature:.1f}C")


@app.command()
def stress_gpu(
    duration: int = typer.Option(60, "--duration", "-d", help="Test duration in seconds")
):
    """Run GPU stress test."""
    from ..stress import GPUStressTest

    print_banner()
    console.print("\n[bold cyan]GPU Stress Test[/bold cyan]\n")

    stress = GPUStressTest()
    console.print(f"Running GPU stress test for {duration} seconds...\n")

    with create_progress() as progress:
        task = progress.add_task("GPU Stress Test", total=duration)

        def gpu_progress(elapsed, stats):
            progress.update(task, completed=elapsed)
            temp_str = f"{stats['temperature']}C" if stats.get('temperature') else "N/A"
            util_str = f"{stats['utilization']}%" if stats.get('utilization') else "N/A"
            progress.update(task, description=f"GPU: {util_str} | Temp: {temp_str}")

        result = stress.run(duration=duration, progress_callback=gpu_progress)

    console.print()
    if result.passed:
        print_success("GPU Stress Test PASSED")
    else:
        print_error(f"GPU Stress Test FAILED: {result.error}")

    console.print(f"\nResults:")
    console.print(f"  GPU: {result.gpu_name}")
    if result.max_temperature:
        console.print(f"  Max Temperature: {result.max_temperature:.1f}C")


@app.command()
def stress_memory(
    percentage: int = typer.Option(70, "--percent", "-p", help="Percentage of RAM to test")
):
    """Run memory stress test."""
    from ..stress import MemoryStressTest

    print_banner()
    console.print("\n[bold cyan]Memory Stress Test[/bold cyan]\n")

    stress = MemoryStressTest()
    console.print(f"Testing {percentage}% of available RAM...\n")

    with create_progress() as progress:
        task = progress.add_task("Memory Stress Test", total=30)

        def mem_progress(elapsed, stats):
            progress.update(task, completed=elapsed)
            progress.update(task, description=f"RAM: {stats['memory_percent']:.0f}% | Errors: {stats['errors']}")

        result = stress.run(duration=30, percentage=percentage, progress_callback=mem_progress)

    console.print()
    if result.passed:
        print_success("Memory Stress Test PASSED")
    else:
        print_error(f"Memory Stress Test FAILED: {result.error}")

    console.print(f"\nResults:")
    console.print(f"  Tested: {result.tested_ram_gb:.1f} GB")
    console.print(f"  Errors Found: {result.errors_found}")


@app.command()
def monitor():
    """Launch live system monitor."""
    from ..monitor import LiveMonitor

    mon = LiveMonitor()
    mon.run()


@app.command()
def hwinfo():
    """Display detailed hardware information."""
    from ..info import HardwareInfo

    print_banner()
    console.print("\n[bold cyan]Hardware Information[/bold cyan]\n")

    hw = HardwareInfo()
    hw.display_all()


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
