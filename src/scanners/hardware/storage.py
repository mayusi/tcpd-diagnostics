"""Storage Scanner - Disk information and SMART health."""
import psutil
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class StorageScanner(BaseScanner):
    """Scan storage devices and health."""

    name = "Storage"
    category = "hardware"
    description = "Disk health and usage"
    requires_admin = False  # Basic info without admin, SMART needs admin
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {"drives": [], "partitions": []}

        try:
            # Get physical drives from WMI
            drives = wmi_query("Win32_DiskDrive")
            for drive in drives:
                size_bytes = drive.get("Size", 0)
                if size_bytes:
                    size_gb = int(size_bytes) / (1024 ** 3)
                else:
                    size_gb = 0

                drive_info = {
                    "model": drive.get("Model", "Unknown"),
                    "serial": (drive.get("SerialNumber") or "").strip(),
                    "size_gb": size_gb,
                    "interface": drive.get("InterfaceType", "Unknown"),
                    "media_type": drive.get("MediaType", "Unknown"),
                    "firmware": drive.get("FirmwareRevision", ""),
                    "status": drive.get("Status", "Unknown"),
                    "device_id": drive.get("DeviceID", "")
                }

                # Detect if SSD or HDD
                model_lower = drive_info["model"].lower()
                if "ssd" in model_lower or "nvme" in model_lower or "solid state" in model_lower:
                    drive_info["type"] = "SSD"
                elif drive_info["interface"] == "NVMe":
                    drive_info["type"] = "NVMe SSD"
                else:
                    drive_info["type"] = "HDD"

                raw_data["drives"].append(drive_info)

                # Finding for each physical drive
                findings.append(self._finding(
                    title=f"{drive_info['model']}",
                    description=f"{drive_info['type']}, {size_gb:.0f} GB, {drive_info['interface']}",
                    severity=Severity.PASS
                ))

            # Get partition usage
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)

                    part_info = {
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total_gb": usage.total / (1024 ** 3),
                        "used_gb": usage.used / (1024 ** 3),
                        "free_gb": usage.free / (1024 ** 3),
                        "percent_used": usage.percent
                    }
                    raw_data["partitions"].append(part_info)

                    # Check disk space
                    severity = Severity.PASS
                    recommendation = None

                    if usage.percent >= 95:
                        severity = Severity.CRITICAL
                        recommendation = "Free up disk space immediately"
                    elif usage.percent >= 85:
                        severity = Severity.WARNING
                        recommendation = "Consider freeing up disk space"

                    findings.append(self._finding(
                        title=f"Drive {partition.mountpoint}",
                        description=f"{usage.percent:.0f}% used ({usage.free / (1024**3):.1f} GB free of {usage.total / (1024**3):.0f} GB)",
                        severity=severity,
                        recommendation=recommendation
                    ))

                except PermissionError:
                    pass
                except Exception:
                    pass

            # Try to get SMART data (requires admin)
            if self._is_admin:
                smart_data = self._get_smart_data()
                if smart_data:
                    raw_data["smart"] = smart_data
                    findings.extend(self._analyze_smart(smart_data))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_smart_data(self) -> List[dict]:
        """Get SMART data from drives (requires admin)."""
        smart_data = []
        try:
            # Try WMI SMART data
            smart_info = wmi_query("MSStorageDriver_FailurePredictStatus", "root\\WMI")
            for item in smart_info:
                smart_data.append({
                    "instance": item.get("InstanceName", ""),
                    "predict_failure": item.get("PredictFailure", False),
                    "reason": item.get("Reason", 0)
                })
        except Exception:
            pass

        return smart_data

    def _analyze_smart(self, smart_data: List[dict]) -> List[Finding]:
        """Analyze SMART data for issues."""
        findings = []

        for item in smart_data:
            if item.get("predict_failure"):
                findings.append(self._finding(
                    title="SMART Failure Predicted",
                    description=f"Drive {item['instance']} is predicting failure",
                    severity=Severity.CRITICAL,
                    recommendation="BACKUP DATA IMMEDIATELY and replace drive"
                ))
            else:
                findings.append(self._finding(
                    title="SMART Status OK",
                    description=f"Drive health check passed",
                    severity=Severity.PASS
                ))

        return findings
