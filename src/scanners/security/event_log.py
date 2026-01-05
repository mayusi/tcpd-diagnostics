"""Event Log Scanner - Security event analysis."""
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict
import xml.etree.ElementTree as ET

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class EventLogScanner(BaseScanner):
    """Analyze Windows Security Event Logs for suspicious activity."""

    name = "Event Log"
    category = "security"
    description = "Security event log analysis"
    requires_admin = True  # Reading security logs requires admin
    dependencies = []

    # Important security event IDs
    EVENT_IDS = {
        # Logon events
        4624: ("Successful Logon", "info"),
        4625: ("Failed Logon", "warning"),
        4634: ("Logoff", "info"),
        4648: ("Explicit Credentials Logon", "info"),

        # Account changes
        4720: ("User Account Created", "warning"),
        4722: ("User Account Enabled", "info"),
        4723: ("Password Change Attempted", "info"),
        4724: ("Password Reset Attempted", "warning"),
        4725: ("User Account Disabled", "info"),
        4726: ("User Account Deleted", "warning"),
        4738: ("User Account Changed", "info"),

        # Privilege use
        4672: ("Special Privileges Assigned", "info"),
        4673: ("Privileged Service Called", "info"),
        4674: ("Operation on Privileged Object", "info"),

        # Security policy
        4719: ("System Audit Policy Changed", "critical"),
        4907: ("Auditing Settings Changed", "warning"),

        # Account lockout
        4740: ("Account Locked Out", "critical"),
        4767: ("Account Unlocked", "info"),
    }

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "failed_logins_24h": 0,
            "failed_logins_7d": 0,
            "account_lockouts": 0,
            "account_changes": 0,
            "privilege_escalations": 0,
            "policy_changes": 0,
            "events_analyzed": 0,
            "recent_events": [],
        }

        # Query security event log
        events = self._query_security_events()
        raw_data["events_analyzed"] = len(events)

        if not events:
            findings.append(self._finding(
                title="Event Log: No Access",
                description="Could not read Security event log (requires admin)",
                severity=Severity.INFO,
                recommendation="Run as Administrator for full security analysis"
            ))
            return self._create_result(findings=findings, raw_data=raw_data)

        # Analyze events
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)

        failed_logins_24h = []
        failed_logins_7d = []
        lockouts = []
        account_changes = []
        policy_changes = []

        for event in events:
            event_id = event.get("event_id")
            event_time = event.get("time")

            # Failed logins (4625)
            if event_id == 4625:
                if event_time and event_time > day_ago:
                    failed_logins_24h.append(event)
                if event_time and event_time > week_ago:
                    failed_logins_7d.append(event)

            # Account lockouts (4740)
            elif event_id == 4740:
                lockouts.append(event)

            # Account changes (4720, 4724, 4726)
            elif event_id in [4720, 4724, 4726]:
                account_changes.append(event)

            # Policy changes (4719, 4907)
            elif event_id in [4719, 4907]:
                policy_changes.append(event)

        raw_data["failed_logins_24h"] = len(failed_logins_24h)
        raw_data["failed_logins_7d"] = len(failed_logins_7d)
        raw_data["account_lockouts"] = len(lockouts)
        raw_data["account_changes"] = len(account_changes)
        raw_data["policy_changes"] = len(policy_changes)

        # Report failed login attempts
        if len(failed_logins_24h) > 10:
            findings.append(self._finding(
                title=f"Failed Logins (24h): {len(failed_logins_24h)}",
                description="High number of failed login attempts - possible brute force",
                severity=Severity.CRITICAL,
                recommendation="Check for unauthorized access attempts"
            ))
        elif len(failed_logins_24h) > 3:
            findings.append(self._finding(
                title=f"Failed Logins (24h): {len(failed_logins_24h)}",
                description="Multiple failed login attempts detected",
                severity=Severity.WARNING,
                recommendation="Review failed login sources"
            ))
        else:
            findings.append(self._finding(
                title=f"Failed Logins (24h): {len(failed_logins_24h)}",
                description="Normal login failure rate",
                severity=Severity.PASS
            ))

        # Report account lockouts
        if lockouts:
            findings.append(self._finding(
                title=f"Account Lockouts: {len(lockouts)}",
                description="Accounts have been locked due to failed attempts",
                severity=Severity.CRITICAL,
                recommendation="Investigate locked accounts for attack attempts",
                details={"lockouts": [e.get("account", "Unknown") for e in lockouts[:5]]}
            ))
        else:
            findings.append(self._finding(
                title="Account Lockouts: None",
                description="No account lockouts detected",
                severity=Severity.PASS
            ))

        # Report account changes
        if account_changes:
            severity = Severity.WARNING if len(account_changes) <= 3 else Severity.CRITICAL
            findings.append(self._finding(
                title=f"Account Changes: {len(account_changes)}",
                description="User accounts have been created, deleted, or had passwords reset",
                severity=severity,
                recommendation="Verify these changes were authorized"
            ))

        # Report policy changes
        if policy_changes:
            findings.append(self._finding(
                title=f"Security Policy Changes: {len(policy_changes)}",
                description="Audit policies have been modified",
                severity=Severity.CRITICAL,
                recommendation="Investigate policy changes - could indicate tampering"
            ))

        # Store recent significant events
        significant_events = failed_logins_24h[:5] + lockouts[:5] + account_changes[:5]
        raw_data["recent_events"] = significant_events

        # Overall security assessment
        if len(failed_logins_24h) > 10 or lockouts or policy_changes:
            findings.insert(0, self._finding(
                title="Security Events: Suspicious Activity",
                description="Potential security incidents detected in event log",
                severity=Severity.CRITICAL,
                recommendation="Review security events and investigate anomalies"
            ))
        elif len(failed_logins_24h) > 3 or account_changes:
            findings.insert(0, self._finding(
                title="Security Events: Notable Activity",
                description="Some security events require attention",
                severity=Severity.WARNING
            ))
        else:
            findings.insert(0, self._finding(
                title="Security Events: Normal",
                description="No suspicious security events detected",
                severity=Severity.PASS
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _query_security_events(self) -> List[Dict]:
        """Query Windows Security Event Log for important events."""
        events = []

        # Build event ID filter
        event_ids = list(self.EVENT_IDS.keys())
        id_filter = " or ".join([f"EventID={eid}" for eid in event_ids])

        # Query last 7 days
        query = f"*[System[({id_filter}) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"

        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Security", "/q:" + query, "/f:xml", "/c:500"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout:
                # Parse XML events
                # Wrap in root element for valid XML
                xml_content = f"<Events>{result.stdout}</Events>"
                try:
                    root = ET.fromstring(xml_content)

                    for event_elem in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Event'):
                        event = self._parse_event(event_elem)
                        if event:
                            events.append(event)
                except ET.ParseError:
                    # Try parsing individual events if wrapped parse fails
                    pass

        except Exception:
            pass

        return events

    def _parse_event(self, event_elem) -> Dict:
        """Parse an event XML element."""
        try:
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            system = event_elem.find('e:System', ns)
            if system is None:
                return None

            event_id_elem = system.find('e:EventID', ns)
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0

            time_elem = system.find('e:TimeCreated', ns)
            time_str = time_elem.get('SystemTime') if time_elem is not None else None

            event_time = None
            if time_str:
                try:
                    # Parse ISO format timestamp
                    time_str = time_str.split('.')[0]  # Remove milliseconds
                    event_time = datetime.fromisoformat(time_str.replace('Z', ''))
                except ValueError:
                    pass

            # Get event description
            event_name, severity = self.EVENT_IDS.get(event_id, ("Unknown", "info"))

            return {
                "event_id": event_id,
                "event_name": event_name,
                "time": event_time,
                "severity": severity,
            }

        except Exception:
            return None
