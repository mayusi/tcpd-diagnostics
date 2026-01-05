"""Memory Scanner - RAM information and health."""
import psutil
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


# Memory type mapping (SMBIOS)
MEMORY_TYPE_MAP = {
    0: "Unknown",
    1: "Other",
    2: "DRAM",
    3: "Synchronous DRAM",
    4: "Cache DRAM",
    5: "EDO",
    6: "EDRAM",
    7: "VRAM",
    8: "SRAM",
    9: "RAM",
    10: "ROM",
    11: "Flash",
    12: "EEPROM",
    13: "FEPROM",
    14: "EPROM",
    15: "CDRAM",
    16: "3DRAM",
    17: "SDRAM",
    18: "SGRAM",
    19: "RDRAM",
    20: "DDR",
    21: "DDR2",
    22: "DDR2 FB-DIMM",
    24: "DDR3",
    25: "FBD2",
    26: "DDR4",
    34: "DDR5"
}


class MemoryScanner(BaseScanner):
    """Scan RAM information and usage."""

    name = "Memory"
    category = "hardware"
    description = "RAM usage and stick details"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Get memory usage from psutil
            mem = psutil.virtual_memory()
            raw_data["total_bytes"] = mem.total
            raw_data["available_bytes"] = mem.available
            raw_data["used_bytes"] = mem.used
            raw_data["percent_used"] = mem.percent
            raw_data["total_gb"] = mem.total / (1024 ** 3)
            raw_data["available_gb"] = mem.available / (1024 ** 3)
            raw_data["used_gb"] = mem.used / (1024 ** 3)

            # Get memory stick details from WMI
            sticks = []
            memory_info = wmi_query("Win32_PhysicalMemory")
            for stick in memory_info:
                capacity = stick.get("Capacity", 0)
                if capacity:
                    capacity_gb = int(capacity) / (1024 ** 3)
                else:
                    capacity_gb = 0

                mem_type = stick.get("SMBIOSMemoryType", 0)
                type_name = MEMORY_TYPE_MAP.get(mem_type, "Unknown")

                sticks.append({
                    "slot": stick.get("DeviceLocator", "Unknown"),
                    "manufacturer": (stick.get("Manufacturer") or "Unknown").strip(),
                    "capacity_gb": capacity_gb,
                    "speed_mhz": stick.get("ConfiguredClockSpeed") or stick.get("Speed", 0),
                    "type": type_name,
                    "part_number": (stick.get("PartNumber") or "").strip(),
                    "serial": stick.get("SerialNumber", "")
                })

            raw_data["sticks"] = sticks

            # Get total slots
            array_info = wmi_query("Win32_PhysicalMemoryArray")
            if array_info:
                raw_data["total_slots"] = array_info[0].get("MemoryDevices", 0)
            else:
                raw_data["total_slots"] = len(sticks)

            raw_data["used_slots"] = len(sticks)

            # Build findings
            total_gb = raw_data["total_gb"]
            used_percent = raw_data["percent_used"]
            slots_used = raw_data["used_slots"]
            total_slots = raw_data["total_slots"]

            # Determine memory type from sticks
            mem_types = set(s["type"] for s in sticks if s["type"] != "Unknown")
            type_str = ", ".join(mem_types) if mem_types else "Unknown"

            # Get max speed
            speeds = [s["speed_mhz"] for s in sticks if s["speed_mhz"]]
            speed_str = f"{max(speeds)} MHz" if speeds else "Unknown speed"

            findings.append(self._finding(
                title=f"{total_gb:.1f} GB {type_str} @ {speed_str}",
                description=f"{slots_used}/{total_slots} slots used, {used_percent:.0f}% in use",
                severity=Severity.PASS
            ))

            # Check utilization
            if used_percent > 90:
                findings.append(self._finding(
                    title="Critical memory usage",
                    description=f"RAM is at {used_percent:.0f}% utilization",
                    severity=Severity.CRITICAL,
                    recommendation="Close unused applications or add more RAM"
                ))
            elif used_percent > 80:
                findings.append(self._finding(
                    title="High memory usage",
                    description=f"RAM is at {used_percent:.0f}% utilization",
                    severity=Severity.WARNING,
                    recommendation="Monitor memory usage"
                ))

            # Report individual sticks
            for stick in sticks:
                findings.append(self._finding(
                    title=f"Slot {stick['slot']}: {stick['capacity_gb']:.0f} GB",
                    description=f"{stick['manufacturer']} {stick['type']} @ {stick['speed_mhz']} MHz",
                    severity=Severity.INFO
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
