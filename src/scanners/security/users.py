"""Users Scanner - User accounts and access analysis."""
from typing import List
import subprocess

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class UsersScanner(BaseScanner):
    """Scan user accounts and permissions."""

    name = "User Accounts"
    category = "security"
    description = "Local user accounts analysis"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "users": [],
            "admin_count": 0,
            "disabled_count": 0
        }

        try:
            # Get local users
            users = self._get_local_users()
            raw_data["users"] = users

            # Count admins and disabled
            admin_count = sum(1 for u in users if u.get("is_admin"))
            disabled_count = sum(1 for u in users if u.get("disabled"))
            raw_data["admin_count"] = admin_count
            raw_data["disabled_count"] = disabled_count

            # Summary
            findings.append(self._finding(
                title=f"User accounts: {len(users)}",
                description=f"Administrators: {admin_count}, Disabled: {disabled_count}",
                severity=Severity.INFO
            ))

            # List users
            for user in users:
                name = user.get("name", "Unknown")
                is_admin = user.get("is_admin", False)
                disabled = user.get("disabled", False)
                last_login = user.get("last_login", "Never")

                status_parts = []
                if is_admin:
                    status_parts.append("Administrator")
                if disabled:
                    status_parts.append("Disabled")

                status_str = ", ".join(status_parts) if status_parts else "Standard user"

                severity = Severity.INFO
                if is_admin and not disabled:
                    severity = Severity.INFO  # Just noting admin accounts

                findings.append(self._finding(
                    title=f"User: {name}",
                    description=f"{status_str} | Last login: {last_login}",
                    severity=severity
                ))

            # Check for suspicious patterns
            # Multiple admin accounts
            if admin_count > 3:
                findings.append(self._finding(
                    title=f"Multiple admin accounts: {admin_count}",
                    description="More than 3 administrator accounts exist",
                    severity=Severity.WARNING,
                    recommendation="Review admin accounts and remove unnecessary ones"
                ))

            # Check for default/common usernames
            suspicious_names = ['admin', 'administrator', 'test', 'guest', 'user']
            for user in users:
                name_lower = user.get("name", "").lower()
                if name_lower in suspicious_names and not user.get("disabled"):
                    if name_lower != 'administrator':  # Built-in is expected
                        findings.append(self._finding(
                            title=f"Review user account: {user['name']}",
                            description="Common/default username that may pose security risk",
                            severity=Severity.WARNING,
                            recommendation="Consider renaming or disabling this account"
                        ))

            # Check if Guest is enabled
            guest_user = next((u for u in users if u.get("name", "").lower() == "guest"), None)
            if guest_user and not guest_user.get("disabled"):
                findings.append(self._finding(
                    title="Guest account is enabled",
                    description="The built-in Guest account is active",
                    severity=Severity.WARNING,
                    recommendation="Disable the Guest account if not needed"
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_local_users(self) -> List[dict]:
        """Get local user accounts."""
        users = []

        try:
            # Get users from WMI
            wmi_users = wmi_query("Win32_UserAccount")
            admin_group = self._get_admin_group_members()

            for user in wmi_users:
                if user.get("LocalAccount"):
                    name = user.get("Name", "")
                    users.append({
                        "name": name,
                        "full_name": user.get("FullName", ""),
                        "disabled": user.get("Disabled", False),
                        "locked": user.get("Lockout", False),
                        "password_required": user.get("PasswordRequired", True),
                        "password_changeable": user.get("PasswordChangeable", True),
                        "sid": user.get("SID", ""),
                        "is_admin": name.lower() in [a.lower() for a in admin_group],
                        "last_login": "Unknown"  # Would need different method
                    })

        except Exception:
            # Fallback to net user
            try:
                result = subprocess.run(
                    ["net", "user"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and not line.startswith('-') and not line.startswith('User accounts') and not line.startswith('The command'):
                            names = line.split()
                            for name in names:
                                if name.strip():
                                    users.append({
                                        "name": name.strip(),
                                        "is_admin": False,
                                        "disabled": False
                                    })
            except Exception:
                pass

        return users

    def _get_admin_group_members(self) -> List[str]:
        """Get members of the Administrators group."""
        admins = []
        try:
            result = subprocess.run(
                ["net", "localgroup", "Administrators"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_members = False
                for line in lines:
                    if '---' in line:
                        in_members = True
                        continue
                    if in_members and line.strip() and not line.startswith('The command'):
                        admins.append(line.strip())
        except Exception:
            pass
        return admins
