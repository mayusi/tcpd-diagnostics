"""BitLocker Scanner - Disk encryption status."""
import subprocess
from typing import List, Dict

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class BitLockerScanner(BaseScanner):
    """Check BitLocker encryption status on all drives."""

    name = "BitLocker"
    category = "security"
    description = "Disk encryption status"
    requires_admin = True  # BitLocker status requires admin
    dependencies = []

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "drives": [],
            "any_encrypted": False,
            "system_drive_encrypted": False,
        }

        # Get BitLocker status for all drives
        drives = self._get_bitlocker_status()
        raw_data["drives"] = drives

        if not drives:
            findings.append(self._finding(
                title="BitLocker Status Unknown",
                description="Could not retrieve BitLocker status (requires admin)",
                severity=Severity.INFO,
                recommendation="Run as Administrator for full details"
            ))
            return self._create_result(findings=findings, raw_data=raw_data)

        encrypted_count = 0
        unencrypted_count = 0

        for drive in drives:
            drive_letter = drive.get("drive", "?")
            status = drive.get("status", "Unknown")
            protection = drive.get("protection", "Unknown")

            is_encrypted = "fully encrypted" in status.lower() or "encryption" in status.lower()
            is_protected = protection.lower() == "on"

            if is_encrypted and is_protected:
                encrypted_count += 1
                raw_data["any_encrypted"] = True

                if drive_letter.upper() == "C:":
                    raw_data["system_drive_encrypted"] = True

                findings.append(self._finding(
                    title=f"Drive {drive_letter} Encrypted",
                    description=f"BitLocker: {status}",
                    severity=Severity.PASS,
                    details=drive
                ))
            elif is_encrypted and not is_protected:
                findings.append(self._finding(
                    title=f"Drive {drive_letter} - Protection Suspended",
                    description=f"BitLocker encrypted but protection is suspended",
                    severity=Severity.WARNING,
                    recommendation="Resume BitLocker protection",
                    details=drive
                ))
            else:
                unencrypted_count += 1
                severity = Severity.CRITICAL if drive_letter.upper() == "C:" else Severity.WARNING

                findings.append(self._finding(
                    title=f"Drive {drive_letter} NOT Encrypted",
                    description="No BitLocker encryption on this drive",
                    severity=severity,
                    recommendation="Enable BitLocker to protect data",
                    details=drive
                ))

        # Summary finding
        if encrypted_count > 0 and unencrypted_count == 0:
            findings.insert(0, self._finding(
                title="All Drives Encrypted",
                description=f"{encrypted_count} drive(s) protected with BitLocker",
                severity=Severity.PASS
            ))
        elif encrypted_count > 0:
            findings.insert(0, self._finding(
                title="Partial Encryption",
                description=f"{encrypted_count} encrypted, {unencrypted_count} unencrypted",
                severity=Severity.WARNING,
                recommendation="Consider encrypting all drives"
            ))
        else:
            findings.insert(0, self._finding(
                title="No BitLocker Encryption",
                description="None of your drives are encrypted",
                severity=Severity.CRITICAL,
                recommendation="Enable BitLocker to protect sensitive data"
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _get_bitlocker_status(self) -> List[Dict]:
        """Get BitLocker status using manage-bde command."""
        drives = []

        try:
            # First get list of drives
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "deviceid"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            drive_letters = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and ':' in line and 'DeviceID' not in line:
                    drive_letters.append(line)

            # Check BitLocker status for each drive
            for drive in drive_letters:
                status_info = self._get_drive_bitlocker_status(drive)
                if status_info:
                    drives.append(status_info)

        except Exception:
            pass

        return drives

    def _get_drive_bitlocker_status(self, drive: str) -> Dict:
        """Get BitLocker status for a specific drive."""
        try:
            result = subprocess.run(
                ["manage-bde", "-status", drive],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return {"drive": drive, "status": "Unknown", "error": "Access denied"}

            output = result.stdout
            info = {"drive": drive}

            for line in output.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if 'conversion status' in key:
                        info['status'] = value
                    elif 'percentage encrypted' in key:
                        info['percent_encrypted'] = value
                    elif 'encryption method' in key:
                        info['method'] = value
                    elif 'protection status' in key:
                        info['protection'] = value
                    elif 'lock status' in key:
                        info['lock_status'] = value

            return info

        except Exception as e:
            return {"drive": drive, "status": "Error", "error": str(e)}
