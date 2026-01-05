"""Ports Scanner - Open ports and listening services."""
import psutil
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


# Known service ports
COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet (insecure)"),
    25: ("SMTP", "Email Server"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Email Client"),
    135: ("RPC", "Windows RPC"),
    139: ("NetBIOS", "Windows Networking"),
    143: ("IMAP", "Email Client"),
    443: ("HTTPS", "Secure Web Server"),
    445: ("SMB", "Windows File Sharing"),
    993: ("IMAPS", "Secure IMAP"),
    995: ("POP3S", "Secure POP3"),
    1433: ("MSSQL", "SQL Server"),
    1434: ("MSSQL", "SQL Server Browser"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "VNC Remote Desktop"),
    8080: ("HTTP-Alt", "Alternative Web Server"),
}

# Potentially risky ports
RISKY_PORTS = {23, 21, 135, 139, 445, 3389, 5900}


class PortsScanner(BaseScanner):
    """Scan open network ports."""

    name = "Open Ports"
    category = "security"
    description = "Listening ports and services"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {"listening_ports": [], "established_connections": 0}

        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')

            listening = []
            established = 0

            for conn in connections:
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    pid = conn.pid

                    # Get process name
                    try:
                        proc = psutil.Process(pid) if pid else None
                        proc_name = proc.name() if proc else "Unknown"
                    except Exception:
                        proc_name = "Unknown"

                    port_info = COMMON_PORTS.get(port, ("Unknown", ""))

                    listening.append({
                        "port": port,
                        "address": conn.laddr.ip,
                        "pid": pid,
                        "process": proc_name,
                        "service": port_info[0],
                        "description": port_info[1]
                    })
                elif conn.status == 'ESTABLISHED':
                    established += 1

            raw_data["listening_ports"] = listening
            raw_data["established_connections"] = established

            # Summary
            findings.append(self._finding(
                title=f"Listening ports: {len(listening)}",
                description=f"{established} established connections",
                severity=Severity.INFO
            ))

            # Check for risky ports
            risky_found = []
            for port_info in listening:
                port = port_info["port"]
                if port in RISKY_PORTS:
                    risky_found.append(port_info)
                    findings.append(self._finding(
                        title=f"Potentially risky port: {port} ({port_info['service']})",
                        description=f"Process: {port_info['process']} (PID: {port_info['pid']})",
                        severity=Severity.WARNING,
                        recommendation=f"Verify {port_info['service']} service is intended to be running"
                    ))

            # Check for RDP
            rdp_ports = [p for p in listening if p["port"] == 3389]
            if rdp_ports:
                findings.append(self._finding(
                    title="Remote Desktop (RDP) is enabled",
                    description="Port 3389 is listening for RDP connections",
                    severity=Severity.WARNING,
                    recommendation="Ensure RDP is properly secured with strong credentials and NLA"
                ))

            # List other listening ports
            for port_info in listening:
                if port_info["port"] not in RISKY_PORTS:
                    findings.append(self._finding(
                        title=f"Port {port_info['port']}: {port_info['service']}",
                        description=f"Process: {port_info['process']}",
                        severity=Severity.INFO
                    ))

            if not risky_found:
                findings.insert(1, self._finding(
                    title="No high-risk ports detected",
                    description="Common risky ports are not exposed",
                    severity=Severity.PASS
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
