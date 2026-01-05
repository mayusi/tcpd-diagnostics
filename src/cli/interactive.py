"""Interactive TUI mode with arrow-key navigation."""
import sys
from datetime import datetime
from pathlib import Path

try:
    import questionary
    from questionary import Style as QStyle
    QUESTIONARY_AVAILABLE = True
except ImportError:
    questionary = None
    QStyle = None
    QUESTIONARY_AVAILABLE = False

from ..core.engine import ScanEngine
from ..utils.admin import is_admin, request_elevation
from .ui.console import (
    console, print_banner, print_admin_status, print_report,
    print_error, print_success, print_info, print_warning,
    create_progress, clear_screen, wait_for_key, prompt_yes_no,
    prompt_filename, print_menu_header
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


# Custom style for questionary (only create if available)
CUSTOM_STYLE = None
if QUESTIONARY_AVAILABLE and QStyle:
    CUSTOM_STYLE = QStyle([
        ('qmark', 'fg:cyan bold'),
        ('question', 'fg:white bold'),
        ('answer', 'fg:cyan bold'),
        ('pointer', 'fg:cyan bold'),
        ('highlighted', 'fg:cyan bold'),
        ('selected', 'fg:green'),
        ('separator', 'fg:gray'),
        ('instruction', 'fg:gray'),
    ])

def get_menu_choices():
    """Get menu choices (with separator if questionary available)."""
    choices = [
        {"name": "Quick Scan              (~30 seconds)", "value": "quick"},
        {"name": "Full System Scan        (~2-5 minutes)", "value": "full"},
        {"name": "Hardware Only           (CPU, GPU, RAM, Storage)", "value": "hardware"},
        {"name": "Security Audit          (AV, Firewall, Ports, Startup)", "value": "security"},
        {"name": "Network Tests           (Connectivity, WiFi, DNS, Speed)", "value": "network_menu"},
    ]
    if QUESTIONARY_AVAILABLE:
        choices.append(questionary.Separator("-" * 50))
    choices.extend([
        {"name": "Stress Tests & Monitoring (CPU/GPU/RAM stress, live monitor)", "value": "stress_menu"},
        {"name": "Export Report            (JSON, CSV, HTML)", "value": "export_menu"},
        {"name": "Install Dependencies     (pip packages)", "value": "install_deps"},
    ])
    if QUESTIONARY_AVAILABLE:
        choices.append(questionary.Separator("-" * 50))
    choices.extend([
        {"name": "View System Info", "value": "info"},
        {"name": "Exit", "value": "exit"},
    ])
    return choices


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


def show_system_info(admin_status: bool):
    """Display basic system information."""
    clear_screen()
    print_banner()
    print_admin_status(admin_status)

    console.print("\n[bold cyan]System Information[/bold cyan]\n")

    import platform
    import psutil

    info = {
        "Computer Name": platform.node(),
        "OS": f"{platform.system()} {platform.release()}",
        "OS Version": platform.version(),
        "Architecture": platform.machine(),
        "Processor": platform.processor(),
        "CPU Cores": f"{psutil.cpu_count(logical=False)} physical, {psutil.cpu_count()} logical",
        "RAM": f"{psutil.virtual_memory().total / (1024**3):.1f} GB",
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
    }

    from rich.table import Table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    for key, value in info.items():
        table.add_row(key, str(value))

    console.print(table)
    wait_for_key()


def run_scan(mode: str, admin_status: bool):
    """Run a diagnostic scan with the specified mode."""
    clear_screen()
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

    # Ask to save report
    console.print()
    if prompt_yes_no("Save report to file?", default=True):
        default_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filename = prompt_filename(default=default_name)

        if filename:
            try:
                # Ensure .json extension
                if not filename.endswith('.json'):
                    filename += '.json'
                report.save_json(filename)
                print_success(f"Report saved to {filename}")
            except Exception as e:
                print_error(f"Failed to save report: {e}")

    wait_for_key()


def show_stress_menu():
    """Show sub-menu for stress testing and monitoring."""
    from ..stress import CPUStressTest, GPUStressTest, MemoryStressTest
    from ..monitor import LiveMonitor
    from ..info import HardwareInfo

    while True:
        clear_screen()
        print_banner()
        console.print("\n[bold cyan]Stress Tests & Monitoring[/bold cyan]\n")

        choices = [
            {"name": "View Hardware Info       (Detailed CPU/GPU/RAM specs)", "value": "hw_info"},
            {"name": "Live System Monitor      (Real-time stats dashboard)", "value": "live_monitor"},
        ]
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.extend([
            {"name": "CPU Stress Test          (30 seconds)", "value": "cpu_30"},
            {"name": "CPU Stress Test          (60 seconds)", "value": "cpu_60"},
            {"name": "CPU Stress Test          (120 seconds)", "value": "cpu_120"},
        ])
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.extend([
            {"name": "GPU Stress Test          (30 seconds)", "value": "gpu_30"},
            {"name": "GPU Stress Test          (60 seconds)", "value": "gpu_60"},
            {"name": "GPU Stress Test          (120 seconds)", "value": "gpu_120"},
        ])
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.extend([
            {"name": "Memory Stress Test       (Test 70% of RAM)", "value": "mem_test"},
        ])
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.append({"name": "Back to Main Menu", "value": "back"})

        choice = questionary.select(
            "Select an option:",
            choices=choices,
            style=CUSTOM_STYLE,
            use_shortcuts=False,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "back":
            return

        if choice == "hw_info":
            clear_screen()
            print_banner()
            console.print("\n[bold cyan]Hardware Information[/bold cyan]\n")
            try:
                hw = HardwareInfo()
                hw.display_all()
            except Exception as e:
                print_error(f"Error getting hardware info: {e}")
            wait_for_key()

        elif choice == "live_monitor":
            clear_screen()
            try:
                monitor = LiveMonitor()
                monitor.run()
            except Exception as e:
                print_error(f"Error running monitor: {e}")
            wait_for_key()

        elif choice.startswith("cpu_"):
            duration = int(choice.split("_")[1])
            clear_screen()
            print_banner()
            console.print(f"\n[bold cyan]CPU Stress Test ({duration}s)[/bold cyan]\n")
            print_warning("This will stress all CPU cores. Monitor your temperatures!")
            console.print()

            if prompt_yes_no("Start CPU stress test?", default=True):
                try:
                    stress = CPUStressTest()
                    console.print(f"[cyan]Stressing {stress.cpu_count} CPU cores for {duration} seconds...[/cyan]\n")

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

                    console.print(f"\n[cyan]Results:[/cyan]")
                    console.print(f"  Cores Tested: {result.cores_tested}")
                    console.print(f"  Avg Utilization: {result.avg_utilization:.1f}%")
                    console.print(f"  Max Utilization: {result.max_utilization:.1f}%")
                    if result.max_temperature:
                        console.print(f"  Max Temperature: {result.max_temperature:.1f}C")
                        console.print(f"  Avg Temperature: {result.avg_temperature:.1f}C")
                    console.print(f"  Throttling Detected: {'Yes' if result.throttling_detected else 'No'}")

                except Exception as e:
                    print_error(f"Error during stress test: {e}")

            wait_for_key()

        elif choice.startswith("gpu_"):
            duration = int(choice.split("_")[1])
            clear_screen()
            print_banner()
            console.print(f"\n[bold cyan]GPU Stress Test ({duration}s)[/bold cyan]\n")
            print_warning("This will stress your GPU. Monitor your temperatures!")
            console.print()

            if prompt_yes_no("Start GPU stress test?", default=True):
                try:
                    stress = GPUStressTest()

                    # Show compute mode
                    if stress.opencl_available:
                        print_success("OpenCL GPU compute available - REAL GPU stress!")
                    else:
                        print_warning("OpenCL not available - using CPU fallback (install pyopencl for real GPU stress)")

                    console.print(f"[cyan]Running GPU stress test for {duration} seconds...[/cyan]\n")

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

                    console.print(f"\n[cyan]Results:[/cyan]")
                    console.print(f"  GPU: {result.gpu_name}")
                    console.print(f"  Compute Mode: {'[green]OpenCL GPU[/green]' if result.opencl_used else '[yellow]CPU Fallback[/yellow]'}")
                    if result.max_temperature:
                        console.print(f"  Max Temperature: {result.max_temperature:.1f}C")
                        console.print(f"  Avg Temperature: {result.avg_temperature:.1f}C")
                    if result.max_utilization:
                        console.print(f"  Max Utilization: {result.max_utilization:.1f}%")
                    console.print(f"  VRAM Total: {result.total_memory_mb:.0f} MB")

                except Exception as e:
                    print_error(f"Error during stress test: {e}")

            wait_for_key()

        elif choice == "mem_test":
            clear_screen()
            print_banner()
            console.print("\n[bold cyan]Memory Stress Test[/bold cyan]\n")
            print_warning("This will allocate 70% of available RAM for testing!")
            console.print()

            if prompt_yes_no("Start memory stress test?", default=True):
                try:
                    stress = MemoryStressTest()
                    console.print(f"[cyan]Testing {stress.available_ram / (1024**3):.1f} GB available RAM...[/cyan]\n")

                    with create_progress() as progress:
                        task = progress.add_task("Memory Stress Test", total=30)

                        def mem_progress(elapsed, stats):
                            progress.update(task, completed=elapsed)
                            progress.update(task, description=f"RAM: {stats['memory_percent']:.0f}% | Errors: {stats['errors']}")

                        result = stress.run(duration=30, percentage=70, progress_callback=mem_progress)

                    console.print()
                    if result.passed:
                        print_success("Memory Stress Test PASSED")
                    else:
                        print_error(f"Memory Stress Test FAILED: {result.error}")

                    console.print(f"\n[cyan]Results:[/cyan]")
                    console.print(f"  Total RAM: {result.total_ram_gb:.1f} GB")
                    console.print(f"  Tested: {result.tested_ram_gb:.1f} GB ({result.test_percentage}%)")
                    console.print(f"  Errors Found: {result.errors_found}")
                    console.print(f"  Max Usage: {result.max_usage_percent:.1f}%")
                    if result.write_speed_mbps:
                        console.print(f"  Write Speed: {result.write_speed_mbps:.0f} MB/s")
                    if result.read_speed_mbps:
                        console.print(f"  Read Speed: {result.read_speed_mbps:.0f} MB/s")

                except Exception as e:
                    print_error(f"Error during stress test: {e}")

            wait_for_key()


def show_network_menu(admin_status: bool):
    """Show sub-menu for network tests."""
    while True:
        clear_screen()
        print_banner()
        print_admin_status(admin_status)
        console.print("\n[bold cyan]Network Tests[/bold cyan]\n")

        choices = [
            {"name": "Full Network Scan       (All network tests)", "value": "full_network"},
        ]
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.extend([
            {"name": "Internet Connectivity   (Ping, DNS, HTTP checks)", "value": "connectivity"},
            {"name": "WiFi Analysis           (Signal strength, security)", "value": "wifi"},
            {"name": "DNS Performance         (DNS server benchmarks)", "value": "dns"},
            {"name": "Speed Test              (Download speed estimate)", "value": "speed"},
        ])
        if QUESTIONARY_AVAILABLE:
            choices.append(questionary.Separator("-" * 50))
        choices.append({"name": "Back to Main Menu", "value": "back"})

        choice = questionary.select(
            "Select a network test:",
            choices=choices,
            style=CUSTOM_STYLE,
            use_shortcuts=False,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "back":
            return

        # Run selected network test(s)
        clear_screen()
        print_banner()
        print_admin_status(admin_status)

        from ..core.engine import ScanEngine

        engine = ScanEngine(is_admin=admin_status)

        if choice == "full_network":
            console.print("\n[bold cyan]Running Full Network Scan...[/bold cyan]\n")
            scanners = [
                ConnectivityScanner(),
                WiFiScanner(),
                DNSScanner(),
                SpeedTestScanner(),
            ]
        elif choice == "connectivity":
            console.print("\n[bold cyan]Running Connectivity Test...[/bold cyan]\n")
            scanners = [ConnectivityScanner()]
        elif choice == "wifi":
            console.print("\n[bold cyan]Running WiFi Analysis...[/bold cyan]\n")
            scanners = [WiFiScanner()]
        elif choice == "dns":
            console.print("\n[bold cyan]Running DNS Performance Test...[/bold cyan]\n")
            scanners = [DNSScanner()]
        elif choice == "speed":
            console.print("\n[bold cyan]Running Speed Test...[/bold cyan]\n")
            print_info("Note: Speed test uses small files for quick estimation")
            console.print()
            scanners = [SpeedTestScanner()]
        else:
            continue

        engine.register_scanners(scanners)

        with create_progress() as progress:
            task = progress.add_task("Running network tests...", total=100)

            def update_progress(current: int, total: int, name: str):
                if total > 0:
                    pct = (current / total) * 100
                    progress.update(task, completed=pct, description=f"Testing: {name}")

            report = engine.run_scan(mode="full", progress_callback=update_progress)

        print_report(report)
        wait_for_key()


def show_export_menu():
    """Show export options menu."""
    from .ui.export import export_to_csv, export_to_html, get_default_export_path

    clear_screen()
    print_banner()
    console.print("\n[bold cyan]Export Report[/bold cyan]\n")
    console.print("[yellow]Note: Run a scan first to generate a report to export.[/yellow]")
    console.print()

    print_info("To export a report:")
    console.print("  1. Run any scan (Quick, Full, Hardware, Security, Network)")
    console.print("  2. When prompted after scan, choose to save the report")
    console.print("  3. The report is saved as JSON by default")
    console.print()
    console.print("[cyan]Export formats available:[/cyan]")
    console.print("  - JSON: Default format, full data")
    console.print("  - CSV:  Spreadsheet compatible, findings only")
    console.print("  - HTML: Visual report for browsers")
    console.print()

    # Offer to run a scan now
    choices = [
        {"name": "Run Quick Scan & Export", "value": "quick"},
        {"name": "Run Full Scan & Export", "value": "full"},
    ]
    if QUESTIONARY_AVAILABLE:
        choices.append(questionary.Separator("-" * 50))
    choices.append({"name": "Back to Main Menu", "value": "back"})

    choice = questionary.select(
        "What would you like to do?",
        choices=choices,
        style=CUSTOM_STYLE,
    ).ask()

    if choice is None or choice == "back":
        return

    # Run scan and offer export
    from ..core.engine import ScanEngine

    admin_status = is_admin()
    engine = ScanEngine(is_admin=admin_status)
    engine.register_scanners(get_all_scanners())

    clear_screen()
    print_banner()
    console.print(f"\n[bold cyan]Running {choice} scan for export...[/bold cyan]\n")

    with create_progress() as progress:
        task = progress.add_task(f"Running {choice} scan...", total=100)

        def update_progress(current: int, total: int, name: str):
            if total > 0:
                pct = (current / total) * 100
                progress.update(task, completed=pct, description=f"Scanning: {name}")

        report = engine.run_scan(mode=choice, progress_callback=update_progress)

    print_report(report)
    console.print()

    # Export options
    export_choices = [
        {"name": "Export to JSON", "value": "json"},
        {"name": "Export to CSV", "value": "csv"},
        {"name": "Export to HTML", "value": "html"},
        {"name": "Export All Formats", "value": "all"},
    ]
    if QUESTIONARY_AVAILABLE:
        export_choices.append(questionary.Separator("-" * 50))
    export_choices.append({"name": "Skip Export", "value": "skip"})

    export_choice = questionary.select(
        "Choose export format:",
        choices=export_choices,
        style=CUSTOM_STYLE,
    ).ask()

    if export_choice is None or export_choice == "skip":
        wait_for_key()
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"tcpd_{timestamp}"

    try:
        if export_choice in ("json", "all"):
            json_path = f"{base_name}.json"
            report.save_json(json_path)
            print_success(f"Saved: {json_path}")

        if export_choice in ("csv", "all"):
            csv_path = f"{base_name}.csv"
            if export_to_csv(report, csv_path):
                print_success(f"Saved: {csv_path}")
            else:
                print_error(f"Failed to save CSV")

        if export_choice in ("html", "all"):
            html_path = f"{base_name}.html"
            if export_to_html(report, html_path):
                print_success(f"Saved: {html_path}")
            else:
                print_error(f"Failed to save HTML")

    except Exception as e:
        print_error(f"Export error: {e}")

    wait_for_key()


def show_dependency_menu():
    """Show dependency installation menu."""
    from ..utils.dependency_installer import (
        check_missing_dependencies, install_package, install_all_requirements,
        get_dependency_status, upgrade_pip
    )

    clear_screen()
    print_banner()
    console.print("\n[bold cyan]Dependency Manager[/bold cyan]\n")

    # Get current status
    status = get_dependency_status()

    from rich.table import Table
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
        wait_for_key()
        return

    # Offer to install missing
    choices = [
        {"name": "Install All Missing Dependencies", "value": "install_all"},
        {"name": "Upgrade pip first, then install", "value": "upgrade_pip"},
    ]

    # Add individual packages
    for import_name, pip_name in status['missing_list']:
        choices.append({"name": f"Install {pip_name} only", "value": pip_name})

    if QUESTIONARY_AVAILABLE:
        choices.append(questionary.Separator("-" * 50))
    choices.append({"name": "Back to Main Menu", "value": "back"})

    choice = questionary.select(
        "What would you like to do?",
        choices=choices,
        style=CUSTOM_STYLE,
    ).ask()

    if choice is None or choice == "back":
        return

    if choice == "upgrade_pip":
        print_info("Upgrading pip...")
        success, msg = upgrade_pip()
        if success:
            print_success(msg)
        else:
            print_error(msg)
        choice = "install_all"  # Continue to install

    if choice == "install_all":
        print_info("Installing all dependencies...")
        console.print()
        success, msg = install_all_requirements()
        if success:
            print_success(msg)
        else:
            print_error(msg)
    else:
        # Install single package
        print_info(f"Installing {choice}...")
        success, msg = install_package(choice)
        if success:
            print_success(msg)
        else:
            print_error(msg)

    wait_for_key()


def check_questionary():
    """Check if questionary is available, show fallback message if not."""
    if not QUESTIONARY_AVAILABLE:
        print_error("The 'questionary' package is required for interactive mode.")
        print_info("Install it with: pip install questionary")
        console.print()
        console.print("Alternatively, use command-line mode:")
        console.print("  tcpd scan --mode quick")
        console.print("  tcpd scan --mode full")
        console.print("  tcpd hardware")
        console.print("  tcpd security")
        return False
    return True


def run_interactive_mode():
    """Run the interactive TUI mode."""
    # Check for questionary
    if not check_questionary():
        return

    # Check/request admin at startup
    admin_status = is_admin()
    if not admin_status:
        clear_screen()
        print_banner()
        print_info("This tool works best with Administrator privileges.")
        console.print()

        if prompt_yes_no("Request Administrator privileges?", default=True):
            if request_elevation():
                return  # Will restart with admin
            print_warning("Continuing without admin - some checks will be limited")
            wait_for_key()

    admin_status = is_admin()

    # Main loop
    while True:
        try:
            clear_screen()
            print_menu_header()
            print_admin_status(admin_status)

            # Show menu
            choice = questionary.select(
                "Select an option:",
                choices=get_menu_choices(),
                style=CUSTOM_STYLE,
                use_shortcuts=False,
                use_arrow_keys=True,
                use_jk_keys=False,
            ).ask()

            if choice is None or choice == "exit":
                clear_screen()
                console.print("[cyan]Thank you for using TCPD![/cyan]")
                console.print()
                break

            elif choice == "info":
                show_system_info(admin_status)

            elif choice == "stress_menu":
                show_stress_menu()

            elif choice == "network_menu":
                show_network_menu(admin_status)

            elif choice == "export_menu":
                show_export_menu()

            elif choice == "install_deps":
                show_dependency_menu()

            elif choice in ("quick", "full", "hardware", "security"):
                run_scan(choice, admin_status)

        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            clear_screen()
            console.print("\n[yellow]Interrupted by user.[/yellow]")
            console.print("[cyan]Thank you for using TCPD![/cyan]")
            console.print()
            break

        except Exception as e:
            print_error(f"An error occurred: {e}")
            wait_for_key()


if __name__ == "__main__":
    run_interactive_mode()
