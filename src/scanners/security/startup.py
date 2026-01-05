"""Startup Scanner - Startup programs and autorun entries."""
from typing import List
import os

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.registry import get_startup_entries, list_subkeys, read_all_values
from ...utils.wmi_helper import wmi_query


class StartupScanner(BaseScanner):
    """Scan startup programs and registry autorun entries."""

    name = "Startup Programs"
    category = "security"
    description = "Autorun entries and startup programs"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "registry_entries": [],
            "startup_folder": [],
            "scheduled_tasks": []
        }

        try:
            # Get registry startup entries
            registry_entries = get_startup_entries()
            raw_data["registry_entries"] = registry_entries

            # Get startup folder items
            startup_folder = self._get_startup_folder_items()
            raw_data["startup_folder"] = startup_folder

            # Get scheduled tasks that run at startup/login
            scheduled_tasks = self._get_startup_tasks()
            raw_data["scheduled_tasks"] = scheduled_tasks

            total_entries = len(registry_entries) + len(startup_folder) + len(scheduled_tasks)

            findings.append(self._finding(
                title=f"Startup entries: {total_entries}",
                description=f"Registry: {len(registry_entries)}, Folder: {len(startup_folder)}, Tasks: {len(scheduled_tasks)}",
                severity=Severity.INFO
            ))

            # Analyze registry entries
            suspicious_count = 0
            for entry in registry_entries:
                is_suspicious, reason = self._check_suspicious(entry)
                if is_suspicious:
                    suspicious_count += 1
                    findings.append(self._finding(
                        title=f"Suspicious startup: {entry['name']}",
                        description=f"{reason}: {entry['command'][:60]}...",
                        severity=Severity.WARNING,
                        recommendation="Verify this startup entry is legitimate"
                    ))

            # List normal startup entries
            for entry in registry_entries[:10]:  # First 10
                is_suspicious, _ = self._check_suspicious(entry)
                if not is_suspicious:
                    findings.append(self._finding(
                        title=f"Startup: {entry['name']}",
                        description=f"Location: {entry['location']}",
                        severity=Severity.INFO
                    ))

            # Startup folder items
            for item in startup_folder:
                findings.append(self._finding(
                    title=f"Startup Folder: {item['name']}",
                    description=item.get('target', 'Unknown target'),
                    severity=Severity.INFO
                ))

            # Scheduled tasks at startup
            for task in scheduled_tasks[:5]:
                findings.append(self._finding(
                    title=f"Scheduled Task: {task['name']}",
                    description=f"Trigger: {task.get('trigger', 'Unknown')}",
                    severity=Severity.INFO
                ))

            if suspicious_count == 0:
                findings.insert(1, self._finding(
                    title="No suspicious startup entries detected",
                    description="All startup entries appear normal",
                    severity=Severity.PASS
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_startup_folder_items(self) -> List[dict]:
        """Get items from startup folders."""
        items = []

        startup_paths = [
            os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.join(os.environ.get('PROGRAMDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
        ]

        for path in startup_paths:
            if os.path.exists(path):
                try:
                    for item in os.listdir(path):
                        full_path = os.path.join(path, item)
                        items.append({
                            "name": item,
                            "path": full_path,
                            "target": self._get_shortcut_target(full_path) if item.endswith('.lnk') else full_path
                        })
                except Exception:
                    pass

        return items

    def _get_shortcut_target(self, lnk_path: str) -> str:
        """Get target of a .lnk shortcut file."""
        try:
            import subprocess
            cmd = f'''
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{lnk_path}")
            $Shortcut.TargetPath
            '''
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return lnk_path

    def _get_startup_tasks(self) -> List[dict]:
        """Get scheduled tasks that run at startup or login."""
        tasks = []
        try:
            import subprocess
            cmd = 'Get-ScheduledTask | Where-Object {$_.Triggers -match "Boot|Logon"} | Select-Object TaskName,TaskPath,State | ConvertTo-Json'
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for task in data:
                    tasks.append({
                        "name": task.get("TaskName", "Unknown"),
                        "path": task.get("TaskPath", ""),
                        "state": task.get("State", "Unknown"),
                        "trigger": "Boot/Logon"
                    })
        except Exception:
            pass
        return tasks

    def _check_suspicious(self, entry: dict) -> tuple:
        """Check if a startup entry is suspicious."""
        command = entry.get('command', '').lower()
        name = entry.get('name', '').lower()

        # Check for suspicious patterns
        suspicious_patterns = [
            (r'\appdata\local\temp', "Runs from temp folder"),
            (r'\users\public', "Runs from public folder"),
            ('cmd /c', "Uses command shell"),
            ('powershell -e', "Uses encoded PowerShell"),
            ('powershell -enc', "Uses encoded PowerShell"),
            ('regsvr32', "Uses regsvr32"),
            ('mshta', "Uses mshta"),
            ('wscript', "Uses Windows Script Host"),
            ('cscript', "Uses Windows Script Host"),
        ]

        for pattern, reason in suspicious_patterns:
            if pattern in command:
                return True, reason

        return False, ""
