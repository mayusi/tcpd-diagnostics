"""Services Scanner - Windows services analysis."""
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class ServicesScanner(BaseScanner):
    """Scan Windows services."""

    name = "Services"
    category = "security"
    description = "Windows services status"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "total_services": 0,
            "running": 0,
            "stopped": 0,
            "services": []
        }

        try:
            # Get all services
            services = wmi_query("Win32_Service")
            raw_data["total_services"] = len(services)

            running = 0
            stopped = 0
            suspicious = []

            for svc in services:
                state = svc.get("State", "Unknown")
                if state == "Running":
                    running += 1
                else:
                    stopped += 1

                # Check for suspicious characteristics
                path = svc.get("PathName", "") or ""
                name = svc.get("Name", "")
                display_name = svc.get("DisplayName", "")
                start_mode = svc.get("StartMode", "")

                is_suspicious, reason = self._check_suspicious_service(name, path, start_mode)
                if is_suspicious:
                    suspicious.append({
                        "name": name,
                        "display_name": display_name,
                        "path": path,
                        "state": state,
                        "reason": reason
                    })

                raw_data["services"].append({
                    "name": name,
                    "display_name": display_name,
                    "state": state,
                    "start_mode": start_mode,
                    "path": path[:100] if path else ""
                })

            raw_data["running"] = running
            raw_data["stopped"] = stopped

            # Summary
            findings.append(self._finding(
                title=f"Services: {running} running, {stopped} stopped",
                description=f"Total: {len(services)} services",
                severity=Severity.INFO
            ))

            # Report suspicious services
            if suspicious:
                for svc in suspicious:
                    findings.append(self._finding(
                        title=f"Review service: {svc['display_name']}",
                        description=f"{svc['reason']}",
                        severity=Severity.WARNING,
                        recommendation="Verify this service is legitimate"
                    ))
            else:
                findings.append(self._finding(
                    title="No obviously suspicious services detected",
                    description="Service configurations appear normal",
                    severity=Severity.PASS
                ))

            # Check critical security services
            security_services = self._check_security_services(services)
            for name, status in security_services.items():
                if not status["running"]:
                    findings.append(self._finding(
                        title=f"Security service not running: {name}",
                        description=f"{name} is currently stopped",
                        severity=Severity.WARNING,
                        recommendation=f"Consider enabling {name}"
                    ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _check_suspicious_service(self, name: str, path: str, start_mode: str) -> tuple:
        """Check if a service has suspicious characteristics."""
        path_lower = path.lower() if path else ""

        # Suspicious patterns
        if r'\appdata\local\temp' in path_lower:
            return True, "Service binary in temp folder"
        if r'\users\public' in path_lower:
            return True, "Service binary in public folder"
        if path and not (path_lower.startswith('"c:\\windows') or
                         path_lower.startswith('c:\\windows') or
                         path_lower.startswith('"c:\\program files') or
                         path_lower.startswith('c:\\program files')):
            # Not in standard locations - note but not necessarily suspicious
            pass

        return False, ""

    def _check_security_services(self, services: List[dict]) -> dict:
        """Check status of important security services."""
        security_service_names = {
            "WinDefend": "Windows Defender",
            "MpsSvc": "Windows Firewall",
            "wscsvc": "Security Center",
            "WdNisSvc": "Defender Network Inspection",
        }

        status = {}
        for svc in services:
            name = svc.get("Name", "")
            if name in security_service_names:
                status[security_service_names[name]] = {
                    "running": svc.get("State") == "Running",
                    "start_mode": svc.get("StartMode")
                }

        return status
