"""CPU Scanner - Processor information and health."""
import psutil
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class CPUScanner(BaseScanner):
    """Scan CPU information and health status."""

    name = "CPU"
    category = "hardware"
    description = "CPU information and temperature"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Get CPU info from WMI
            cpu_info = wmi_query("Win32_Processor")
            if cpu_info:
                cpu = cpu_info[0]
                raw_data["name"] = cpu.get("Name", "Unknown")
                raw_data["manufacturer"] = cpu.get("Manufacturer", "Unknown")
                raw_data["cores"] = cpu.get("NumberOfCores", 0)
                raw_data["threads"] = cpu.get("NumberOfLogicalProcessors", 0)
                raw_data["max_clock_mhz"] = cpu.get("MaxClockSpeed", 0)
                raw_data["current_clock_mhz"] = cpu.get("CurrentClockSpeed", 0)
                raw_data["l2_cache_kb"] = cpu.get("L2CacheSize", 0)
                raw_data["l3_cache_kb"] = cpu.get("L3CacheSize", 0)
                raw_data["architecture"] = self._get_arch(cpu.get("AddressWidth", 64))

            # Get CPU utilization
            raw_data["utilization_percent"] = psutil.cpu_percent(interval=0.5)

            # Get per-core utilization
            raw_data["per_core_utilization"] = psutil.cpu_percent(interval=0.1, percpu=True)

            # Get CPU frequency
            freq = psutil.cpu_freq()
            if freq:
                raw_data["current_freq_mhz"] = freq.current
                raw_data["min_freq_mhz"] = freq.min
                raw_data["max_freq_mhz"] = freq.max

            # Try to get temperature (requires admin usually)
            temps = self._get_temperature()
            if temps:
                raw_data["temperature_celsius"] = temps

            # Build findings
            cpu_name = raw_data.get("name", "Unknown CPU")
            cores = raw_data.get("cores", 0)
            threads = raw_data.get("threads", 0)
            utilization = raw_data.get("utilization_percent", 0)

            # Main CPU info finding
            temp_str = ""
            if temps:
                temp_str = f" - {temps:.0f}°C"

            findings.append(self._finding(
                title=f"{cpu_name}",
                description=f"{cores} cores, {threads} threads, {utilization:.0f}% load{temp_str}",
                severity=Severity.PASS
            ))

            # Check utilization
            if utilization > 90:
                findings.append(self._finding(
                    title="High CPU utilization",
                    description=f"CPU is at {utilization:.0f}% utilization",
                    severity=Severity.WARNING,
                    recommendation="Check running processes for resource hogs"
                ))

            # Check temperature if available
            if temps:
                if temps > 85:
                    findings.append(self._finding(
                        title="Critical CPU temperature",
                        description=f"CPU temperature is {temps:.0f}°C",
                        severity=Severity.CRITICAL,
                        recommendation="Check cooling system immediately"
                    ))
                elif temps > 75:
                    findings.append(self._finding(
                        title="High CPU temperature",
                        description=f"CPU temperature is {temps:.0f}°C",
                        severity=Severity.WARNING,
                        recommendation="Monitor cooling and airflow"
                    ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_arch(self, address_width: int) -> str:
        """Get architecture string from address width."""
        return "x64" if address_width == 64 else "x86"

    def _get_temperature(self) -> float:
        """Try to get CPU temperature."""
        # Try psutil first (works on some systems)
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if 'cpu' in name.lower() or 'core' in entry.label.lower():
                            return entry.current
        except Exception:
            pass

        # Try WMI thermal zone
        try:
            thermal = wmi_query("MSAcpi_ThermalZoneTemperature", "root\\WMI")
            if thermal:
                # Convert from deciKelvin to Celsius
                kelvin = thermal[0].get("CurrentTemperature", 0) / 10
                return kelvin - 273.15
        except Exception:
            pass

        return None
