"""Windows Update Scanner - Update status and pending updates."""
from typing import List
import subprocess

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class WindowsUpdateScanner(BaseScanner):
    """Scan Windows Update status."""

    name = "Windows Update"
    category = "security"
    description = "Pending updates and update history"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Get pending updates
            pending = self._get_pending_updates()
            raw_data["pending_updates"] = pending

            if pending:
                count = len(pending)
                # Check for critical updates
                critical_count = sum(1 for u in pending if u.get("is_critical", False))

                if critical_count > 0:
                    findings.append(self._finding(
                        title=f"Critical updates pending: {critical_count}",
                        description="Important security updates are waiting to be installed",
                        severity=Severity.CRITICAL,
                        recommendation="Install critical updates immediately"
                    ))

                if count > critical_count:
                    findings.append(self._finding(
                        title=f"Updates pending: {count - critical_count}",
                        description="Non-critical updates available",
                        severity=Severity.WARNING,
                        recommendation="Install pending Windows updates"
                    ))

                # List first few updates
                for update in pending[:5]:
                    findings.append(self._finding(
                        title=f"Update: {update.get('title', 'Unknown')[:50]}",
                        description=update.get("description", "")[:100],
                        severity=Severity.INFO
                    ))
            else:
                findings.append(self._finding(
                    title="Windows Update: Up to date",
                    description="No pending updates detected",
                    severity=Severity.PASS
                ))

            # Get last update date
            last_update = self._get_last_update_date()
            raw_data["last_update"] = last_update

            if last_update:
                findings.append(self._finding(
                    title=f"Last update: {last_update}",
                    description="Most recent Windows update installation",
                    severity=Severity.INFO
                ))

            # Check auto-update setting
            auto_update = self._check_auto_update()
            raw_data["auto_update_enabled"] = auto_update

            if not auto_update:
                findings.append(self._finding(
                    title="Automatic updates may be disabled",
                    description="Windows Update automatic installation might be turned off",
                    severity=Severity.WARNING,
                    recommendation="Enable automatic Windows updates"
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_pending_updates(self) -> List[dict]:
        """Get list of pending Windows updates."""
        updates = []
        try:
            # Use COM object through PowerShell
            cmd = '''
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
            $SearchResult.Updates | Select-Object Title, @{N='is_critical';E={$_.MsrcSeverity -eq 'Critical'}}, Description | ConvertTo-Json
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=60
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    updates = [data]
                elif isinstance(data, list):
                    updates = data

        except Exception:
            pass

        return updates

    def _get_last_update_date(self) -> str:
        """Get date of last Windows update."""
        try:
            cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()[:10]  # Return date portion

        except Exception:
            pass

        return None

    def _check_auto_update(self) -> bool:
        """Check if automatic updates are enabled."""
        try:
            from ...utils.registry import read_value
            # Check Group Policy setting
            au_options = read_value(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                "NoAutoUpdate",
                0
            )
            return au_options != 1
        except Exception:
            return True  # Assume enabled if we can't check
