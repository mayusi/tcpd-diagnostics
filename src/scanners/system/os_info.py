"""OS Info Scanner - Windows version and system information."""
import platform
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query
from ...utils.registry import read_value, RegistryPaths


class OSInfoScanner(BaseScanner):
    """Scan operating system information."""

    name = "OS Info"
    category = "system"
    description = "Windows version and system details"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Get Windows version from registry
            raw_data["product_name"] = read_value(
                RegistryPaths.WINDOWS_VERSION,
                "ProductName",
                "Unknown"
            )
            raw_data["display_version"] = read_value(
                RegistryPaths.WINDOWS_VERSION,
                "DisplayVersion",
                read_value(RegistryPaths.WINDOWS_VERSION, "ReleaseId", "Unknown")
            )
            raw_data["build_number"] = read_value(
                RegistryPaths.WINDOWS_VERSION,
                "CurrentBuildNumber",
                "Unknown"
            )
            raw_data["edition_id"] = read_value(
                RegistryPaths.WINDOWS_VERSION,
                "EditionID",
                "Unknown"
            )
            raw_data["install_date"] = read_value(
                RegistryPaths.WINDOWS_VERSION,
                "InstallDate",
                None
            )

            # Get computer name
            raw_data["computer_name"] = platform.node()

            # Get from WMI for more details
            os_info = wmi_query("Win32_OperatingSystem")
            if os_info:
                os_data = os_info[0]
                raw_data["architecture"] = os_data.get("OSArchitecture", "Unknown")
                raw_data["registered_user"] = os_data.get("RegisteredUser", "Unknown")
                raw_data["system_directory"] = os_data.get("SystemDirectory", "")
                raw_data["boot_device"] = os_data.get("BootDevice", "")
                raw_data["serial_number"] = os_data.get("SerialNumber", "")

                # Parse install date
                install_date = os_data.get("InstallDate", "")
                if install_date:
                    try:
                        raw_data["install_date_formatted"] = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
                    except Exception:
                        pass

                # Parse last boot
                last_boot = os_data.get("LastBootUpTime", "")
                if last_boot:
                    try:
                        raw_data["last_boot"] = f"{last_boot[:4]}-{last_boot[4:6]}-{last_boot[6:8]} {last_boot[8:10]}:{last_boot[10:12]}"
                    except Exception:
                        pass

            # Main OS finding
            os_name = raw_data.get("product_name", "Windows")
            version = raw_data.get("display_version", "Unknown")
            build = raw_data.get("build_number", "")
            arch = raw_data.get("architecture", "64-bit")

            findings.append(self._finding(
                title=f"{os_name}",
                description=f"Version {version} (Build {build}) - {arch}",
                severity=Severity.PASS
            ))

            # Computer name
            findings.append(self._finding(
                title=f"Computer: {raw_data.get('computer_name', 'Unknown')}",
                description=f"Edition: {raw_data.get('edition_id', 'Unknown')}",
                severity=Severity.INFO
            ))

            # Last boot time
            if raw_data.get("last_boot"):
                findings.append(self._finding(
                    title=f"Last boot: {raw_data['last_boot']}",
                    description="System uptime since last restart",
                    severity=Severity.INFO
                ))

            # Check if Windows is activated
            activation = self._check_activation()
            raw_data["activated"] = activation.get("activated", False)

            if activation.get("activated"):
                findings.append(self._finding(
                    title="Windows is activated",
                    description=activation.get("status", "Activated"),
                    severity=Severity.PASS
                ))
            else:
                findings.append(self._finding(
                    title="Windows activation issue",
                    description=activation.get("status", "Not activated"),
                    severity=Severity.WARNING,
                    recommendation="Activate Windows for full functionality"
                ))

            # Check for EOL versions
            build_num = int(raw_data.get("build_number", "0") or "0")
            if build_num < 19041:  # Older than Windows 10 2004
                findings.append(self._finding(
                    title="Outdated Windows version",
                    description="This Windows version may be out of support",
                    severity=Severity.WARNING,
                    recommendation="Update to a supported Windows version"
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _check_activation(self) -> dict:
        """Check Windows activation status."""
        try:
            import subprocess
            result = subprocess.run(
                ["cscript", "//nologo", r"C:\Windows\System32\slmgr.vbs", "/xpr"],
                capture_output=True, text=True, timeout=30
            )

            output = result.stdout.lower()
            if "permanently activated" in output:
                return {"activated": True, "status": "Permanently activated"}
            elif "will expire" in output:
                return {"activated": True, "status": "Activated (volume license)"}
            elif "notification mode" in output or "not activated" in output:
                return {"activated": False, "status": "Not activated"}
            else:
                return {"activated": True, "status": "Unknown activation status"}

        except Exception:
            return {"activated": True, "status": "Could not check activation"}
