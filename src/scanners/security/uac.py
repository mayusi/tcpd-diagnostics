"""UAC Scanner - User Account Control settings."""
import winreg
from typing import List, Dict

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class UACScanner(BaseScanner):
    """Check User Account Control (UAC) settings."""

    name = "UAC"
    category = "security"
    description = "User Account Control settings"
    requires_admin = False
    dependencies = []

    # UAC registry keys
    UAC_REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "uac_enabled": None,
            "consent_prompt_behavior_admin": None,
            "consent_prompt_behavior_user": None,
            "enable_lua": None,
            "prompt_on_secure_desktop": None,
            "filter_administrator_token": None,
        }

        # Read UAC settings from registry
        settings = self._get_uac_settings()
        raw_data.update(settings)

        # Check if UAC is enabled (EnableLUA)
        enable_lua = settings.get("enable_lua")
        if enable_lua == 1:
            raw_data["uac_enabled"] = True
            findings.append(self._finding(
                title="UAC: Enabled",
                description="User Account Control is active",
                severity=Severity.PASS
            ))
        elif enable_lua == 0:
            raw_data["uac_enabled"] = False
            findings.append(self._finding(
                title="UAC: DISABLED",
                description="User Account Control is completely disabled!",
                severity=Severity.CRITICAL,
                recommendation="Enable UAC immediately for system security"
            ))
        else:
            findings.append(self._finding(
                title="UAC Status: Unknown",
                description="Could not determine UAC status",
                severity=Severity.INFO
            ))

        # Check admin consent prompt behavior
        # 0 = Elevate without prompting (most dangerous)
        # 1 = Prompt for credentials on secure desktop
        # 2 = Prompt for consent on secure desktop
        # 3 = Prompt for credentials
        # 4 = Prompt for consent
        # 5 = Prompt for consent for non-Windows binaries (default)
        admin_behavior = settings.get("consent_prompt_behavior_admin")
        behavior_desc = {
            0: ("Never Notify", Severity.CRITICAL, "UAC never prompts - VERY DANGEROUS"),
            1: ("Prompt for credentials (secure desktop)", Severity.PASS, "Strong: Requires password"),
            2: ("Prompt for consent (secure desktop)", Severity.PASS, "Good: Yes/No prompt on secure desktop"),
            3: ("Prompt for credentials", Severity.WARNING, "Prompts but not on secure desktop"),
            4: ("Prompt for consent", Severity.WARNING, "Prompts but not on secure desktop"),
            5: ("Default (non-Windows binaries)", Severity.PASS, "Standard Windows setting"),
        }

        if admin_behavior is not None:
            name, severity, desc = behavior_desc.get(admin_behavior, ("Unknown", Severity.INFO, f"Level {admin_behavior}"))

            findings.append(self._finding(
                title=f"UAC Admin Behavior: {name}",
                description=desc,
                severity=severity,
                recommendation="Set to level 2 or higher for better security" if admin_behavior < 2 else None,
                details={"level": admin_behavior}
            ))

        # Check secure desktop setting
        secure_desktop = settings.get("prompt_on_secure_desktop")
        if secure_desktop == 1:
            findings.append(self._finding(
                title="Secure Desktop: Enabled",
                description="UAC prompts appear on secure desktop (recommended)",
                severity=Severity.PASS
            ))
        elif secure_desktop == 0:
            findings.append(self._finding(
                title="Secure Desktop: Disabled",
                description="UAC prompts NOT on secure desktop - vulnerable to spoofing",
                severity=Severity.WARNING,
                recommendation="Enable secure desktop in UAC settings"
            ))

        # Check admin approval mode for built-in Administrator
        filter_admin = settings.get("filter_administrator_token")
        if filter_admin == 1:
            findings.append(self._finding(
                title="Admin Approval Mode: Enabled",
                description="Built-in Administrator runs with filtered token",
                severity=Severity.PASS
            ))
        elif filter_admin == 0:
            findings.append(self._finding(
                title="Admin Approval Mode: Disabled",
                description="Built-in Administrator has unrestricted access",
                severity=Severity.WARNING,
                recommendation="Enable Admin Approval Mode for extra security"
            ))

        # Overall UAC assessment
        if raw_data.get("uac_enabled") and admin_behavior and admin_behavior >= 2:
            findings.insert(0, self._finding(
                title="UAC Configuration: Good",
                description="UAC is properly configured for security",
                severity=Severity.PASS
            ))
        elif raw_data.get("uac_enabled"):
            findings.insert(0, self._finding(
                title="UAC Configuration: Weak",
                description="UAC is enabled but settings could be stronger",
                severity=Severity.WARNING,
                recommendation="Increase UAC notification level"
            ))
        else:
            findings.insert(0, self._finding(
                title="UAC Configuration: Critical Risk",
                description="UAC is disabled or misconfigured",
                severity=Severity.CRITICAL,
                recommendation="Enable and configure UAC properly"
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _get_uac_settings(self) -> Dict:
        """Read UAC settings from registry."""
        settings = {}

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                self.UAC_REGISTRY_PATH,
                0,
                winreg.KEY_READ
            )

            # EnableLUA - Master UAC switch
            try:
                value, _ = winreg.QueryValueEx(key, "EnableLUA")
                settings["enable_lua"] = value
            except WindowsError:
                pass

            # ConsentPromptBehaviorAdmin - How admins are prompted
            try:
                value, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                settings["consent_prompt_behavior_admin"] = value
            except WindowsError:
                pass

            # ConsentPromptBehaviorUser - How standard users are prompted
            try:
                value, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
                settings["consent_prompt_behavior_user"] = value
            except WindowsError:
                pass

            # PromptOnSecureDesktop - Use secure desktop for prompts
            try:
                value, _ = winreg.QueryValueEx(key, "PromptOnSecureDesktop")
                settings["prompt_on_secure_desktop"] = value
            except WindowsError:
                pass

            # FilterAdministratorToken - Admin approval for built-in admin
            try:
                value, _ = winreg.QueryValueEx(key, "FilterAdministratorToken")
                settings["filter_administrator_token"] = value
            except WindowsError:
                pass

            winreg.CloseKey(key)

        except Exception:
            pass

        return settings
