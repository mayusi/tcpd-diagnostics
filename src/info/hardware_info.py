"""
Hardware Info Display Module

Displays detailed hardware specifications like GPU-Z/CPU-Z.
Shows CPU, GPU, RAM, Storage, and Motherboard info.
"""

import psutil
from typing import Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def _get_wmi_data() -> Dict[str, Any]:
    """Get hardware data via WMI."""
    data = {
        'cpu': {},
        'gpu': [],
        'memory': [],
        'motherboard': {},
        'bios': {}
    }

    try:
        import wmi
        w = wmi.WMI()

        # CPU Info
        for cpu in w.Win32_Processor():
            data['cpu'] = {
                'name': cpu.Name.strip() if cpu.Name else 'Unknown',
                'manufacturer': cpu.Manufacturer or 'Unknown',
                'cores': cpu.NumberOfCores or 0,
                'threads': cpu.NumberOfLogicalProcessors or 0,
                'max_clock': cpu.MaxClockSpeed or 0,
                'current_clock': cpu.CurrentClockSpeed or 0,
                'l2_cache': (cpu.L2CacheSize or 0),
                'l3_cache': (cpu.L3CacheSize or 0),
                'architecture': cpu.Architecture or 0,
                'socket': cpu.SocketDesignation or 'Unknown'
            }
            break

        # GPU Info
        for gpu in w.Win32_VideoController():
            adapter_ram = gpu.AdapterRAM or 0
            if adapter_ram < 0:  # Handle int32 overflow
                adapter_ram = 4 * 1024 * 1024 * 1024

            data['gpu'].append({
                'name': gpu.Name or 'Unknown',
                'manufacturer': gpu.AdapterCompatibility or 'Unknown',
                'vram_bytes': adapter_ram,
                'driver_version': gpu.DriverVersion or 'Unknown',
                'driver_date': gpu.DriverDate[:8] if gpu.DriverDate else 'Unknown',
                'status': gpu.Status or 'Unknown'
            })

        # Memory Info
        for mem in w.Win32_PhysicalMemory():
            capacity = int(mem.Capacity or 0)
            data['memory'].append({
                'slot': mem.DeviceLocator or 'Unknown',
                'manufacturer': mem.Manufacturer or 'Unknown',
                'capacity_gb': capacity / (1024**3),
                'speed': mem.Speed or 0,
                'type': mem.MemoryType or 0,
                'serial': mem.SerialNumber or 'Unknown',
                'part_number': (mem.PartNumber or '').strip()
            })

        # Motherboard Info
        for board in w.Win32_BaseBoard():
            data['motherboard'] = {
                'manufacturer': board.Manufacturer or 'Unknown',
                'model': board.Product or 'Unknown',
                'serial': board.SerialNumber or 'Unknown'
            }
            break

        # BIOS Info
        for bios in w.Win32_BIOS():
            data['bios'] = {
                'vendor': bios.Manufacturer or 'Unknown',
                'version': bios.SMBIOSBIOSVersion or 'Unknown',
                'date': bios.ReleaseDate[:8] if bios.ReleaseDate else 'Unknown'
            }
            break

    except Exception:
        pass

    return data


def _get_nvidia_info() -> Optional[Dict]:
    """Get detailed NVIDIA GPU info."""
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

        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        driver = pynvml.nvmlSystemGetDriverVersion()
        if isinstance(driver, bytes):
            driver = driver.decode('utf-8')

        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)

        # Try to get clocks
        try:
            graphics_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)
            mem_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_MEM)
        except Exception:
            graphics_clock = 0
            mem_clock = 0

        # Try to get power
        try:
            power = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000  # Convert to watts
        except Exception:
            power = 0

        pynvml.nvmlShutdown()

        return {
            'name': name,
            'driver': driver,
            'vram_total_gb': mem.total / (1024**3),
            'vram_used_gb': mem.used / (1024**3),
            'temperature': temp,
            'utilization': util.gpu,
            'mem_utilization': util.memory,
            'graphics_clock': graphics_clock,
            'memory_clock': mem_clock,
            'power_watts': power
        }
    except Exception:
        return None


def _get_ddr_type(type_code: int) -> str:
    """Convert WMI MemoryType to string."""
    types = {
        0: 'Unknown',
        20: 'DDR',
        21: 'DDR2',
        22: 'DDR2 FB-DIMM',
        24: 'DDR3',
        26: 'DDR4',
        34: 'DDR5'
    }
    return types.get(type_code, f'Type {type_code}')


class HardwareInfo:
    """Hardware information display."""

    def __init__(self):
        self.console = Console()
        self.wmi_data = _get_wmi_data()
        self.nvidia_info = _get_nvidia_info()

    def display_all(self):
        """Display all hardware information."""
        self.display_cpu()
        self.console.print()
        self.display_gpu()
        self.console.print()
        self.display_memory()
        self.console.print()
        self.display_storage()
        self.console.print()
        self.display_motherboard()

    def display_cpu(self):
        """Display CPU information."""
        cpu = self.wmi_data.get('cpu', {})
        freq = psutil.cpu_freq()

        table = Table(title="CPU Information", title_style="bold cyan", show_header=False)
        table.add_column("Property", style="dim", width=20)
        table.add_column("Value", style="white")

        table.add_row("Processor", cpu.get('name', 'Unknown'))
        table.add_row("Manufacturer", cpu.get('manufacturer', 'Unknown'))
        table.add_row("Socket", cpu.get('socket', 'Unknown'))
        table.add_row("Cores", str(cpu.get('cores', 0)))
        table.add_row("Threads", str(cpu.get('threads', 0)))
        table.add_row("Base Clock", f"{cpu.get('max_clock', 0)} MHz")

        if freq:
            table.add_row("Current Clock", f"{freq.current:.0f} MHz")
            table.add_row("Min Clock", f"{freq.min:.0f} MHz")
            table.add_row("Max Clock", f"{freq.max:.0f} MHz")

        l2 = cpu.get('l2_cache', 0)
        l3 = cpu.get('l3_cache', 0)
        if l2:
            table.add_row("L2 Cache", f"{l2} KB")
        if l3:
            table.add_row("L3 Cache", f"{l3 / 1024:.0f} MB")

        # Architecture
        arch_map = {0: 'x86', 9: 'x64', 12: 'ARM64'}
        arch = arch_map.get(cpu.get('architecture', 0), 'Unknown')
        table.add_row("Architecture", arch)

        # Current utilization
        cpu_percent = psutil.cpu_percent()
        table.add_row("Utilization", f"{cpu_percent:.1f}%")

        self.console.print(table)

    def display_gpu(self):
        """Display GPU information."""
        # First show NVIDIA info if available (more detailed)
        if self.nvidia_info:
            table = Table(title="GPU Information (NVIDIA)", title_style="bold green", show_header=False)
            table.add_column("Property", style="dim", width=20)
            table.add_column("Value", style="white")

            info = self.nvidia_info
            table.add_row("GPU", info['name'])
            table.add_row("Driver Version", info['driver'])
            table.add_row("VRAM Total", f"{info['vram_total_gb']:.1f} GB")
            table.add_row("VRAM Used", f"{info['vram_used_gb']:.1f} GB")
            table.add_row("VRAM Free", f"{info['vram_total_gb'] - info['vram_used_gb']:.1f} GB")
            table.add_row("Temperature", f"{info['temperature']}C")
            table.add_row("GPU Utilization", f"{info['utilization']}%")
            table.add_row("Memory Utilization", f"{info['mem_utilization']}%")

            if info['graphics_clock']:
                table.add_row("Graphics Clock", f"{info['graphics_clock']} MHz")
            if info['memory_clock']:
                table.add_row("Memory Clock", f"{info['memory_clock']} MHz")
            if info['power_watts']:
                table.add_row("Power Usage", f"{info['power_watts']:.0f} W")

            self.console.print(table)
            return

        # Fall back to WMI data
        gpus = self.wmi_data.get('gpu', [])
        if not gpus:
            self.console.print("[yellow]No GPU information available[/yellow]")
            return

        for i, gpu in enumerate(gpus):
            table = Table(title=f"GPU {i} Information", title_style="bold green", show_header=False)
            table.add_column("Property", style="dim", width=20)
            table.add_column("Value", style="white")

            table.add_row("GPU", gpu.get('name', 'Unknown'))
            table.add_row("Manufacturer", gpu.get('manufacturer', 'Unknown'))

            vram_gb = gpu.get('vram_bytes', 0) / (1024**3)
            table.add_row("VRAM", f"{vram_gb:.1f} GB")
            table.add_row("Driver Version", gpu.get('driver_version', 'Unknown'))
            table.add_row("Driver Date", gpu.get('driver_date', 'Unknown'))
            table.add_row("Status", gpu.get('status', 'Unknown'))

            self.console.print(table)

    def display_memory(self):
        """Display memory information."""
        mem = psutil.virtual_memory()
        sticks = self.wmi_data.get('memory', [])

        # Summary table
        summary = Table(title="Memory Summary", title_style="bold magenta", show_header=False)
        summary.add_column("Property", style="dim", width=20)
        summary.add_column("Value", style="white")

        summary.add_row("Total RAM", f"{mem.total / (1024**3):.1f} GB")
        summary.add_row("Used", f"{mem.used / (1024**3):.1f} GB")
        summary.add_row("Available", f"{mem.available / (1024**3):.1f} GB")
        summary.add_row("Usage", f"{mem.percent:.1f}%")
        summary.add_row("Slots Used", f"{len(sticks)}")

        self.console.print(summary)

        # Individual sticks
        if sticks:
            sticks_table = Table(title="Memory Modules", title_style="bold magenta")
            sticks_table.add_column("Slot", style="dim")
            sticks_table.add_column("Size")
            sticks_table.add_column("Speed")
            sticks_table.add_column("Type")
            sticks_table.add_column("Manufacturer")
            sticks_table.add_column("Part Number")

            for stick in sticks:
                sticks_table.add_row(
                    stick.get('slot', 'Unknown'),
                    f"{stick.get('capacity_gb', 0):.0f} GB",
                    f"{stick.get('speed', 0)} MHz",
                    _get_ddr_type(stick.get('type', 0)),
                    stick.get('manufacturer', 'Unknown'),
                    stick.get('part_number', 'Unknown')
                )

            self.console.print(sticks_table)

    def display_storage(self):
        """Display storage information."""
        table = Table(title="Storage Devices", title_style="bold yellow")
        table.add_column("Drive", style="dim")
        table.add_column("Type")
        table.add_column("Total")
        table.add_column("Used")
        table.add_column("Free")
        table.add_column("Usage")

        for part in psutil.disk_partitions():
            try:
                if 'cdrom' in part.opts.lower() or part.fstype == '':
                    continue

                usage = psutil.disk_usage(part.mountpoint)

                # Determine drive type
                drive_type = "HDD"
                if 'ssd' in part.device.lower():
                    drive_type = "SSD"

                table.add_row(
                    part.device,
                    drive_type,
                    f"{usage.total / (1024**3):.0f} GB",
                    f"{usage.used / (1024**3):.0f} GB",
                    f"{usage.free / (1024**3):.0f} GB",
                    f"{usage.percent:.1f}%"
                )
            except (PermissionError, OSError):
                continue

        self.console.print(table)

    def display_motherboard(self):
        """Display motherboard and BIOS information."""
        board = self.wmi_data.get('motherboard', {})
        bios = self.wmi_data.get('bios', {})

        table = Table(title="Motherboard & BIOS", title_style="bold blue", show_header=False)
        table.add_column("Property", style="dim", width=20)
        table.add_column("Value", style="white")

        table.add_row("Board Manufacturer", board.get('manufacturer', 'Unknown'))
        table.add_row("Board Model", board.get('model', 'Unknown'))
        table.add_row("BIOS Vendor", bios.get('vendor', 'Unknown'))
        table.add_row("BIOS Version", bios.get('version', 'Unknown'))
        table.add_row("BIOS Date", bios.get('date', 'Unknown'))

        self.console.print(table)
