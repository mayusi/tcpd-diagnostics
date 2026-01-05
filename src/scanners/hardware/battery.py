"""Battery Scanner - Battery health and status (laptops)."""
import psutil
from typing import List, Optional

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class BatteryScanner(BaseScanner):
    """Scan battery health and status."""

    name = "Battery"
    category = "hardware"
    description = "Battery health and wear level"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Check if battery exists
            battery = psutil.sensors_battery()

            if battery is None:
                findings.append(self._finding(
                    title="No battery detected",
                    description="This appears to be a desktop system",
                    severity=Severity.INFO
                ))
                return self._create_result(findings=findings, raw_data={"present": False})

            raw_data["present"] = True
            raw_data["percent"] = battery.percent
            raw_data["power_plugged"] = battery.power_plugged
            raw_data["seconds_left"] = battery.secsleft if battery.secsleft > 0 else None

            # Get detailed battery info from WMI
            design_capacity = None
            full_charge_capacity = None
            cycle_count = None

            try:
                # Static battery data
                static = wmi_query("BatteryStaticData", "root\\WMI")
                if static:
                    design_capacity = static[0].get("DesignedCapacity")
                    raw_data["design_capacity_mwh"] = design_capacity

                # Full charge capacity
                full_charge = wmi_query("BatteryFullChargedCapacity", "root\\WMI")
                if full_charge:
                    full_charge_capacity = full_charge[0].get("FullChargedCapacity")
                    raw_data["full_charge_capacity_mwh"] = full_charge_capacity

                # Cycle count
                cycles = wmi_query("BatteryCycleCount", "root\\WMI")
                if cycles:
                    cycle_count = cycles[0].get("CycleCount")
                    raw_data["cycle_count"] = cycle_count

            except Exception:
                pass

            # Calculate wear level
            wear_level = None
            if design_capacity and full_charge_capacity and design_capacity > 0:
                wear_level = 100 - ((full_charge_capacity / design_capacity) * 100)
                raw_data["wear_level_percent"] = wear_level

            # Build findings
            status = "Charging" if battery.power_plugged else "Discharging"
            time_str = ""
            if battery.secsleft and battery.secsleft > 0:
                hours = battery.secsleft // 3600
                minutes = (battery.secsleft % 3600) // 60
                time_str = f", {hours}h {minutes}m remaining"

            findings.append(self._finding(
                title=f"Battery: {battery.percent:.0f}%",
                description=f"{status}{time_str}",
                severity=Severity.PASS
            ))

            # Wear level finding
            if wear_level is not None:
                if wear_level > 40:
                    findings.append(self._finding(
                        title=f"Critical battery wear: {wear_level:.0f}%",
                        description="Battery capacity significantly degraded",
                        severity=Severity.CRITICAL,
                        recommendation="Consider replacing the battery"
                    ))
                elif wear_level > 20:
                    findings.append(self._finding(
                        title=f"Battery wear: {wear_level:.0f}%",
                        description="Battery showing normal wear",
                        severity=Severity.WARNING,
                        recommendation="Monitor battery health"
                    ))
                else:
                    findings.append(self._finding(
                        title=f"Battery health: {100 - wear_level:.0f}%",
                        description="Battery is in good condition",
                        severity=Severity.PASS
                    ))

            # Cycle count finding
            if cycle_count is not None:
                findings.append(self._finding(
                    title=f"Battery cycles: {cycle_count}",
                    description="Number of charge cycles",
                    severity=Severity.INFO
                ))

            # Low battery warning
            if battery.percent < 20 and not battery.power_plugged:
                findings.append(self._finding(
                    title="Low battery warning",
                    description=f"Battery is at {battery.percent:.0f}%",
                    severity=Severity.WARNING,
                    recommendation="Connect to power source"
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
