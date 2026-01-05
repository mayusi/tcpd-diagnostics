"""Antivirus Scanner - Windows Defender and third-party AV status."""
from typing import List
import subprocess

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query
from ...utils.registry import read_value, RegistryPaths


class AntivirusScanner(BaseScanner):
    """Scan antivirus and security status."""

    name = "Antivirus"
    category = "security"
    description = "Windows Defender and AV status"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Check Windows Defender status
            defender_status = self._get_defender_status()
            raw_data["windows_defender"] = defender_status

            if defender_status.get("enabled"):
                findings.append(self._finding(
                    title="Windows Defender: Active",
                    description=f"Real-time protection enabled",
                    severity=Severity.PASS
                ))

                # Check definitions
                if defender_status.get("definitions_outdated"):
                    findings.append(self._finding(
                        title="Defender definitions may be outdated",
                        description="Last update was more than 7 days ago",
                        severity=Severity.WARNING,
                        recommendation="Update Windows Defender definitions"
                    ))
            else:
                findings.append(self._finding(
                    title="Windows Defender: Disabled or Inactive",
                    description="Real-time protection is not enabled",
                    severity=Severity.WARNING,
                    recommendation="Enable Windows Defender or ensure third-party AV is active"
                ))

            # Check for third-party antivirus
            third_party_av = self._get_third_party_av()
            raw_data["third_party_av"] = third_party_av

            if third_party_av:
                for av in third_party_av:
                    state = self._parse_av_state(av.get("productState", 0))
                    severity = Severity.PASS if state["enabled"] else Severity.WARNING

                    findings.append(self._finding(
                        title=f"Third-party AV: {av.get('displayName', 'Unknown')}",
                        description=f"Status: {'Active' if state['enabled'] else 'Inactive'}",
                        severity=severity
                    ))

            # Check Windows Security Center
            security_health = self._get_security_health()
            raw_data["security_health"] = security_health

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_defender_status(self) -> dict:
        """Get Windows Defender status."""
        status = {
            "enabled": False,
            "real_time_protection": False,
            "definitions_outdated": False
        }

        try:
            # Try PowerShell to get Defender status
            cmd = "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                status["enabled"] = data.get("AntivirusEnabled", False)
                status["real_time_protection"] = data.get("RealTimeProtectionEnabled", False)

                # Check if definitions are outdated (more than 7 days)
                last_update = data.get("AntivirusSignatureLastUpdated")
                if last_update:
                    from datetime import datetime, timedelta
                    try:
                        # Parse the date
                        update_date = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
                        if datetime.now(update_date.tzinfo) - update_date > timedelta(days=7):
                            status["definitions_outdated"] = True
                    except Exception:
                        pass

        except Exception:
            # Fallback: Check registry
            try:
                disabled = read_value(RegistryPaths.WINDOWS_DEFENDER, "DisableAntiSpyware", 0)
                status["enabled"] = disabled != 1
            except Exception:
                pass

        return status

    def _get_third_party_av(self) -> List[dict]:
        """Get third-party antivirus products."""
        products = []
        try:
            # Query Security Center for AV products
            av_products = wmi_query("AntiVirusProduct", "root\\SecurityCenter2")
            for av in av_products:
                products.append({
                    "displayName": av.get("displayName", "Unknown"),
                    "productState": av.get("productState", 0),
                    "pathToSignedProductExe": av.get("pathToSignedProductExe", ""),
                    "pathToSignedReportingExe": av.get("pathToSignedReportingExe", "")
                })
        except Exception:
            pass

        return products

    def _parse_av_state(self, product_state: int) -> dict:
        """Parse antivirus product state."""
        # Product state is a bitfield
        # Bits 4-7: Product state (0x00=off, 0x10=on)
        # Bits 8-15: Signature status
        hex_state = hex(product_state)
        state_byte = (product_state >> 12) & 0xF

        return {
            "enabled": state_byte in [1, 3],  # Enabled states
            "up_to_date": (product_state >> 4) & 0xF == 0
        }

    def _get_security_health(self) -> dict:
        """Get overall security health."""
        health = {}
        try:
            cmd = "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                health = json.loads(result.stdout)
        except Exception:
            pass
        return health
