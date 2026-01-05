"""Password Policy Scanner - Windows password policy settings."""
import subprocess
from typing import List, Dict

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class PasswordPolicyScanner(BaseScanner):
    """Check Windows password policy settings."""

    name = "Password Policy"
    category = "security"
    description = "Password policy and account lockout settings"
    requires_admin = False
    dependencies = []

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "min_password_length": None,
            "password_history": None,
            "max_password_age": None,
            "min_password_age": None,
            "complexity_enabled": None,
            "lockout_threshold": None,
            "lockout_duration": None,
            "lockout_observation_window": None,
        }

        # Get password policy using net accounts
        policy = self._get_password_policy()
        raw_data.update(policy)

        # Check minimum password length
        min_length = policy.get("min_password_length", 0)
        if min_length >= 14:
            findings.append(self._finding(
                title=f"Min Password Length: {min_length} chars",
                description="Strong minimum password length",
                severity=Severity.PASS
            ))
        elif min_length >= 8:
            findings.append(self._finding(
                title=f"Min Password Length: {min_length} chars",
                description="Acceptable but could be stronger",
                severity=Severity.WARNING,
                recommendation="Consider increasing to 12+ characters"
            ))
        elif min_length > 0:
            findings.append(self._finding(
                title=f"Min Password Length: {min_length} chars",
                description="Weak minimum password length!",
                severity=Severity.CRITICAL,
                recommendation="Increase minimum password length to at least 8"
            ))
        else:
            findings.append(self._finding(
                title="Min Password Length: Not Set",
                description="No minimum password length enforced",
                severity=Severity.CRITICAL,
                recommendation="Set a minimum password length policy"
            ))

        # Check password history
        history = policy.get("password_history", 0)
        if history >= 12:
            findings.append(self._finding(
                title=f"Password History: {history} passwords",
                description="Strong password history enforcement",
                severity=Severity.PASS
            ))
        elif history >= 5:
            findings.append(self._finding(
                title=f"Password History: {history} passwords",
                description="Moderate password history",
                severity=Severity.INFO
            ))
        else:
            findings.append(self._finding(
                title=f"Password History: {history} passwords",
                description="Weak or no password history",
                severity=Severity.WARNING,
                recommendation="Increase password history to prevent reuse"
            ))

        # Check max password age
        max_age = policy.get("max_password_age")
        if max_age is not None:
            if max_age == 0 or max_age > 365:
                findings.append(self._finding(
                    title=f"Password Expiry: Never/Very Long",
                    description="Passwords don't expire or have long validity",
                    severity=Severity.INFO,
                    recommendation="Consider 90-180 day password rotation" if max_age == 0 else None
                ))
            elif max_age <= 90:
                findings.append(self._finding(
                    title=f"Password Expiry: {max_age} days",
                    description="Passwords expire regularly",
                    severity=Severity.PASS
                ))
            else:
                findings.append(self._finding(
                    title=f"Password Expiry: {max_age} days",
                    description="Moderate password expiration period",
                    severity=Severity.INFO
                ))

        # Check account lockout
        lockout_threshold = policy.get("lockout_threshold", 0)
        lockout_duration = policy.get("lockout_duration", 0)

        if lockout_threshold > 0:
            findings.append(self._finding(
                title=f"Account Lockout: After {lockout_threshold} attempts",
                description=f"Locked for {lockout_duration} minutes",
                severity=Severity.PASS,
                details={"threshold": lockout_threshold, "duration": lockout_duration}
            ))
        else:
            findings.append(self._finding(
                title="Account Lockout: Disabled",
                description="No lockout after failed login attempts",
                severity=Severity.WARNING,
                recommendation="Enable account lockout to prevent brute force attacks"
            ))

        # Overall policy assessment
        issues = 0
        if min_length < 8:
            issues += 2
        if history < 5:
            issues += 1
        if lockout_threshold == 0:
            issues += 1

        if issues == 0:
            findings.insert(0, self._finding(
                title="Password Policy: Strong",
                description="Password policies are well configured",
                severity=Severity.PASS
            ))
        elif issues <= 2:
            findings.insert(0, self._finding(
                title="Password Policy: Moderate",
                description="Some password policies could be improved",
                severity=Severity.WARNING
            ))
        else:
            findings.insert(0, self._finding(
                title="Password Policy: Weak",
                description="Password policies need significant improvement",
                severity=Severity.CRITICAL,
                recommendation="Configure stronger password policies"
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _get_password_policy(self) -> Dict:
        """Get password policy using 'net accounts' command."""
        policy = {}

        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        key, value = line.rsplit(':', 1)
                        key = key.strip().lower()
                        value = value.strip()

                        # Parse numeric values
                        try:
                            if 'never' in value.lower():
                                num_value = 0
                            else:
                                # Extract first number from value
                                import re
                                match = re.search(r'(\d+)', value)
                                num_value = int(match.group(1)) if match else 0
                        except (ValueError, AttributeError):
                            num_value = 0

                        if 'minimum password length' in key:
                            policy['min_password_length'] = num_value
                        elif 'password history' in key or 'length of password history' in key:
                            policy['password_history'] = num_value
                        elif 'maximum password age' in key:
                            policy['max_password_age'] = num_value if num_value > 0 else 0
                        elif 'minimum password age' in key:
                            policy['min_password_age'] = num_value
                        elif 'lockout threshold' in key:
                            policy['lockout_threshold'] = num_value
                        elif 'lockout duration' in key:
                            policy['lockout_duration'] = num_value
                        elif 'lockout observation' in key or 'lockout window' in key:
                            policy['lockout_observation_window'] = num_value

        except Exception:
            pass

        return policy
