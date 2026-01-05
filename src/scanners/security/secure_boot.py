"""Secure Boot Scanner - UEFI Secure Boot and TPM status."""
import subprocess
import winreg
from typing import List, Dict, Optional

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class SecureBootScanner(BaseScanner):
    """Check Secure Boot, UEFI mode, and TPM status."""

    name = "Secure Boot"
    category = "security"
    description = "Secure Boot, UEFI, and TPM status"
    requires_admin = False
    dependencies = []

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "secure_boot_enabled": None,
            "uefi_mode": None,
            "tpm_present": None,
            "tpm_version": None,
            "tpm_ready": None,
        }

        # Check Secure Boot status
        secure_boot = self._check_secure_boot()
        raw_data["secure_boot_enabled"] = secure_boot

        if secure_boot is True:
            findings.append(self._finding(
                title="Secure Boot: Enabled",
                description="System is protected against boot-level malware",
                severity=Severity.PASS
            ))
        elif secure_boot is False:
            findings.append(self._finding(
                title="Secure Boot: Disabled",
                description="System vulnerable to bootkit/rootkit attacks",
                severity=Severity.WARNING,
                recommendation="Enable Secure Boot in BIOS/UEFI settings"
            ))
        else:
            findings.append(self._finding(
                title="Secure Boot: Unknown",
                description="Could not determine Secure Boot status",
                severity=Severity.INFO
            ))

        # Check UEFI vs Legacy BIOS
        uefi_mode = self._check_uefi_mode()
        raw_data["uefi_mode"] = uefi_mode

        if uefi_mode == "UEFI":
            findings.append(self._finding(
                title="Boot Mode: UEFI",
                description="Using modern UEFI boot (recommended)",
                severity=Severity.PASS
            ))
        elif uefi_mode == "Legacy":
            findings.append(self._finding(
                title="Boot Mode: Legacy BIOS",
                description="Using older Legacy/CSM boot mode",
                severity=Severity.WARNING,
                recommendation="Consider migrating to UEFI for better security"
            ))
        else:
            findings.append(self._finding(
                title="Boot Mode: Unknown",
                description="Could not determine boot mode",
                severity=Severity.INFO
            ))

        # Check TPM status
        tpm_info = self._check_tpm()
        raw_data["tpm_present"] = tpm_info.get("present")
        raw_data["tpm_version"] = tpm_info.get("version")
        raw_data["tpm_ready"] = tpm_info.get("ready")

        if tpm_info.get("present"):
            version = tpm_info.get("version", "Unknown")
            ready = tpm_info.get("ready", False)

            if "2.0" in str(version):
                severity = Severity.PASS
                desc = f"TPM 2.0 detected"
                if ready:
                    desc += " (Ready)"
            elif "1.2" in str(version):
                severity = Severity.WARNING
                desc = "TPM 1.2 detected (older version)"
            else:
                severity = Severity.PASS
                desc = f"TPM {version} detected"

            findings.append(self._finding(
                title=f"TPM: {version}",
                description=desc,
                severity=severity,
                details=tpm_info
            ))

            if not ready:
                findings.append(self._finding(
                    title="TPM Not Ready",
                    description="TPM is present but not fully initialized",
                    severity=Severity.WARNING,
                    recommendation="Enable and initialize TPM in BIOS settings"
                ))
        else:
            findings.append(self._finding(
                title="TPM: Not Detected",
                description="No TPM module found or TPM is disabled",
                severity=Severity.WARNING,
                recommendation="Enable TPM in BIOS for BitLocker and Windows 11"
            ))

        # Windows 11 compatibility note
        if raw_data.get("tpm_present") and "2.0" in str(raw_data.get("tpm_version", "")) and raw_data.get("secure_boot_enabled"):
            findings.append(self._finding(
                title="Windows 11 Ready",
                description="TPM 2.0 and Secure Boot meet Windows 11 requirements",
                severity=Severity.PASS
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _check_secure_boot(self) -> Optional[bool]:
        """Check if Secure Boot is enabled."""
        try:
            # Method 1: Check via PowerShell
            result = subprocess.run(
                ["powershell", "-Command", "Confirm-SecureBootUEFI"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            output = result.stdout.strip().lower()
            if "true" in output:
                return True
            elif "false" in output:
                return False

        except Exception:
            pass

        try:
            # Method 2: Check registry
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            )
            value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            winreg.CloseKey(key)
            return value == 1

        except Exception:
            pass

        return None

    def _check_uefi_mode(self) -> Optional[str]:
        """Check if system is using UEFI or Legacy BIOS."""
        try:
            # Check for EFI system partition or firmware type
            result = subprocess.run(
                ["powershell", "-Command", "$env:firmware_type"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            output = result.stdout.strip().upper()
            if "UEFI" in output:
                return "UEFI"
            elif "BIOS" in output or "LEGACY" in output:
                return "Legacy"

        except Exception:
            pass

        try:
            # Alternative: check bcdedit
            result = subprocess.run(
                ["bcdedit", "/enum", "firmware"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                return "UEFI"
            else:
                return "Legacy"

        except Exception:
            pass

        return None

    def _check_tpm(self) -> Dict:
        """Check TPM status and version."""
        info = {"present": False}

        try:
            # Use PowerShell Get-Tpm
            result = subprocess.run(
                ["powershell", "-Command", "Get-Tpm | ConvertTo-Json"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    tpm_data = json.loads(result.stdout)
                    info["present"] = tpm_data.get("TpmPresent", False)
                    info["ready"] = tpm_data.get("TpmReady", False)
                    info["enabled"] = tpm_data.get("TpmEnabled", False)

                    # Get version via WMI
                    version_result = subprocess.run(
                        ["powershell", "-Command",
                         "(Get-WmiObject -Namespace 'root\\cimv2\\security\\microsofttpm' -Class Win32_Tpm).SpecVersion"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if version_result.returncode == 0:
                        version = version_result.stdout.strip()
                        if version:
                            # Parse version string like "2.0, 0, 1.59"
                            if version.startswith("2"):
                                info["version"] = "2.0"
                            elif version.startswith("1"):
                                info["version"] = "1.2"
                            else:
                                info["version"] = version.split(',')[0].strip()

                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

        # Fallback: check WMI directly
        if not info.get("present"):
            try:
                result = subprocess.run(
                    ["wmic", "/namespace:\\\\root\\cimv2\\security\\microsofttpm", "path", "Win32_Tpm", "get", "IsEnabled_InitialValue"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if "TRUE" in result.stdout.upper():
                    info["present"] = True
                    info["enabled"] = True

            except Exception:
                pass

        return info
