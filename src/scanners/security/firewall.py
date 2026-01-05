"""Firewall Scanner - Windows Firewall status."""
from typing import List
import subprocess

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class FirewallScanner(BaseScanner):
    """Scan Windows Firewall status."""

    name = "Firewall"
    category = "security"
    description = "Windows Firewall configuration"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {"profiles": {}}

        try:
            # Get firewall status using netsh
            profiles = ["Domain", "Private", "Public"]

            all_enabled = True
            for profile in profiles:
                status = self._get_profile_status(profile)
                raw_data["profiles"][profile] = status

                if status.get("enabled"):
                    findings.append(self._finding(
                        title=f"Firewall ({profile}): Enabled",
                        description=f"Inbound: {status.get('inbound_action', 'Block')}, Outbound: {status.get('outbound_action', 'Allow')}",
                        severity=Severity.PASS
                    ))
                else:
                    all_enabled = False
                    findings.append(self._finding(
                        title=f"Firewall ({profile}): DISABLED",
                        description=f"Firewall is disabled for {profile} profile",
                        severity=Severity.CRITICAL,
                        recommendation=f"Enable Windows Firewall for {profile} profile"
                    ))

            # Summary finding
            if all_enabled:
                findings.insert(0, self._finding(
                    title="Windows Firewall: All profiles enabled",
                    description="Firewall is active on all network profiles",
                    severity=Severity.PASS
                ))
            else:
                findings.insert(0, self._finding(
                    title="Windows Firewall: Some profiles disabled",
                    description="One or more firewall profiles are disabled",
                    severity=Severity.WARNING,
                    recommendation="Enable Windows Firewall for all profiles"
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_profile_status(self, profile: str) -> dict:
        """Get firewall status for a specific profile."""
        status = {
            "enabled": False,
            "inbound_action": "Unknown",
            "outbound_action": "Unknown"
        }

        try:
            # Use PowerShell to get firewall profile
            cmd = f"Get-NetFirewallProfile -Name {profile} | Select-Object -Property Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                status["enabled"] = data.get("Enabled", False)

                # Action values: 0=NotConfigured, 1=Allow, 2=Block
                inbound = data.get("DefaultInboundAction", 0)
                outbound = data.get("DefaultOutboundAction", 0)

                action_map = {0: "NotConfigured", 1: "Allow", 2: "Block"}
                status["inbound_action"] = action_map.get(inbound, "Unknown")
                status["outbound_action"] = action_map.get(outbound, "Unknown")

        except Exception:
            # Fallback to netsh
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", profile.lower() + "profile", "state"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    output = result.stdout.lower()
                    status["enabled"] = "on" in output
            except Exception:
                pass

        return status
