"""
Live System Monitor Module

Real-time dashboard showing CPU, GPU, RAM, and other system stats.
Uses Rich Live display for terminal UI.
"""

import time
import psutil
import threading
from typing import Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text


def _get_nvidia_stats() -> Optional[Dict]:
    """Get NVIDIA GPU stats."""
    try:
        import pynvml
        pynvml.nvmlInit()

        if pynvml.nvmlDeviceGetCount() == 0:
            pynvml.nvmlShutdown()
            return None

        handle = pynvml.nvmlDeviceGetHandleByIndex(0)

        name = pynvml.nvmlDeviceGetName(handle)
        if isinstance(name, bytes):
            name = name.decode('utf-8')

        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)

        pynvml.nvmlShutdown()

        return {
            'name': name,
            'temp': temp,
            'util': util.gpu,
            'mem_util': util.memory,
            'mem_used': mem.used / (1024**3),
            'mem_total': mem.total / (1024**3)
        }
    except Exception:
        return None


def _get_cpu_temp() -> Optional[float]:
    """Get CPU temperature."""
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                if 'cpu' in name.lower() or 'core' in name.lower():
                    if entries:
                        return entries[0].current
            for name, entries in temps.items():
                if entries:
                    return entries[0].current
    except Exception:
        pass

    try:
        import wmi
        w = wmi.WMI(namespace="root\\WMI")
        temp_info = w.MSAcpi_ThermalZoneTemperature()
        if temp_info:
            kelvin = temp_info[0].CurrentTemperature / 10.0
            return kelvin - 273.15
    except Exception:
        pass

    return None


def _create_progress_bar(percent: float, width: int = 20, filled: str = "#", empty: str = "-") -> str:
    """Create ASCII progress bar."""
    filled_count = int(percent / 100 * width)
    empty_count = width - filled_count
    return f"[{filled * filled_count}{empty * empty_count}]"


def _get_status_color(value: float, warn: float = 70, crit: float = 90) -> str:
    """Get color based on value thresholds."""
    if value >= crit:
        return "red"
    elif value >= warn:
        return "yellow"
    return "green"


class LiveMonitor:
    """Live system monitor with real-time stats display."""

    def __init__(self):
        self.console = Console()
        self.running = False
        self._stop_flag = False

    def _build_display(self) -> Table:
        """Build the monitor display table."""
        # Main table
        main_table = Table(show_header=False, box=None, padding=(0, 1))
        main_table.add_column("Content", justify="left")

        # CPU Section
        cpu_percent = psutil.cpu_percent(interval=0)
        cpu_freq = psutil.cpu_freq()
        cpu_temp = _get_cpu_temp()
        per_cpu = psutil.cpu_percent(percpu=True)

        cpu_table = Table(title="CPU", title_style="bold cyan", box=None)
        cpu_table.add_column("Metric", style="dim")
        cpu_table.add_column("Value", justify="right")
        cpu_table.add_column("Bar", justify="left")

        color = _get_status_color(cpu_percent)
        cpu_table.add_row(
            "Usage",
            f"[{color}]{cpu_percent:5.1f}%[/{color}]",
            _create_progress_bar(cpu_percent)
        )

        if cpu_freq:
            cpu_table.add_row(
                "Frequency",
                f"{cpu_freq.current:,.0f} MHz",
                f"(max: {cpu_freq.max:,.0f})"
            )

        if cpu_temp is not None:
            temp_color = _get_status_color(cpu_temp, 70, 85)
            cpu_table.add_row(
                "Temperature",
                f"[{temp_color}]{cpu_temp:.1f}C[/{temp_color}]",
                ""
            )

        # Per-core utilization
        core_str = " ".join([f"{p:3.0f}%" for p in per_cpu[:8]])  # Show first 8 cores
        if len(per_cpu) > 8:
            core_str += " ..."
        cpu_table.add_row("Cores", core_str, "")

        main_table.add_row(cpu_table)
        main_table.add_row("")

        # Memory Section
        mem = psutil.virtual_memory()
        mem_table = Table(title="Memory", title_style="bold magenta", box=None)
        mem_table.add_column("Metric", style="dim")
        mem_table.add_column("Value", justify="right")
        mem_table.add_column("Bar", justify="left")

        mem_color = _get_status_color(mem.percent, 80, 95)
        mem_table.add_row(
            "RAM Usage",
            f"[{mem_color}]{mem.percent:5.1f}%[/{mem_color}]",
            _create_progress_bar(mem.percent)
        )
        mem_table.add_row(
            "Used / Total",
            f"{mem.used / (1024**3):.1f} / {mem.total / (1024**3):.1f} GB",
            ""
        )
        mem_table.add_row(
            "Available",
            f"{mem.available / (1024**3):.1f} GB",
            ""
        )

        main_table.add_row(mem_table)
        main_table.add_row("")

        # GPU Section
        gpu_stats = _get_nvidia_stats()
        if gpu_stats:
            gpu_table = Table(title=f"GPU - {gpu_stats['name']}", title_style="bold green", box=None)
            gpu_table.add_column("Metric", style="dim")
            gpu_table.add_column("Value", justify="right")
            gpu_table.add_column("Bar", justify="left")

            gpu_color = _get_status_color(gpu_stats['util'])
            gpu_table.add_row(
                "GPU Usage",
                f"[{gpu_color}]{gpu_stats['util']:5.1f}%[/{gpu_color}]",
                _create_progress_bar(gpu_stats['util'])
            )

            vram_percent = (gpu_stats['mem_used'] / gpu_stats['mem_total']) * 100 if gpu_stats['mem_total'] > 0 else 0
            vram_color = _get_status_color(vram_percent, 80, 95)
            gpu_table.add_row(
                "VRAM Usage",
                f"[{vram_color}]{vram_percent:5.1f}%[/{vram_color}]",
                _create_progress_bar(vram_percent)
            )
            gpu_table.add_row(
                "VRAM Used",
                f"{gpu_stats['mem_used']:.1f} / {gpu_stats['mem_total']:.1f} GB",
                ""
            )

            temp_color = _get_status_color(gpu_stats['temp'], 75, 90)
            gpu_table.add_row(
                "Temperature",
                f"[{temp_color}]{gpu_stats['temp']}C[/{temp_color}]",
                ""
            )

            main_table.add_row(gpu_table)
            main_table.add_row("")

        # Disk Section
        disk_table = Table(title="Storage", title_style="bold yellow", box=None)
        disk_table.add_column("Drive", style="dim")
        disk_table.add_column("Used", justify="right")
        disk_table.add_column("Bar", justify="left")

        for part in psutil.disk_partitions():
            try:
                if 'cdrom' in part.opts.lower() or part.fstype == '':
                    continue
                usage = psutil.disk_usage(part.mountpoint)
                disk_color = _get_status_color(usage.percent, 80, 95)
                disk_table.add_row(
                    part.device[:10],
                    f"[{disk_color}]{usage.percent:5.1f}%[/{disk_color}] ({usage.used / (1024**3):.0f}/{usage.total / (1024**3):.0f}GB)",
                    _create_progress_bar(usage.percent, width=15)
                )
            except (PermissionError, OSError):
                continue

        main_table.add_row(disk_table)

        return main_table

    def run(self, duration: Optional[int] = None):
        """
        Run the live monitor.

        Args:
            duration: Run for this many seconds, or None for indefinite (press Ctrl+C to stop)
        """
        self.running = True
        self._stop_flag = False

        self.console.print("[bold cyan]Live System Monitor[/bold cyan]")
        self.console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        start_time = time.time()

        try:
            with Live(self._build_display(), console=self.console, refresh_per_second=1) as live:
                while not self._stop_flag:
                    if duration and (time.time() - start_time) >= duration:
                        break

                    live.update(self._build_display())
                    time.sleep(1)

        except KeyboardInterrupt:
            pass

        self.running = False
        self.console.print("\n[dim]Monitor stopped.[/dim]")

    def stop(self):
        """Stop the live monitor."""
        self._stop_flag = True
        self.running = False
