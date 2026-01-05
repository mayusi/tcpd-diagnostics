"""Processes Scanner - Running processes analysis."""
import psutil
import os
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


# Suspicious process locations
SUSPICIOUS_LOCATIONS = [
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
    r"\programdata",
]

# Known suspicious process names (commonly used by malware)
SUSPICIOUS_NAMES = [
    "powershell.exe",  # Not inherently bad, but watch for it
]


class ProcessesScanner(BaseScanner):
    """Scan running processes for anomalies."""

    name = "Processes"
    category = "security"
    description = "Running process analysis"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "total_processes": 0,
            "suspicious": [],
            "high_cpu": [],
            "high_memory": []
        }

        try:
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'username']))
            raw_data["total_processes"] = len(processes)

            suspicious = []
            high_cpu = []
            high_memory = []

            for proc in processes:
                try:
                    info = proc.info
                    pid = info['pid']
                    name = info['name'] or "Unknown"
                    exe = info['exe'] or ""
                    cpu = info['cpu_percent'] or 0
                    memory = info['memory_percent'] or 0
                    username = info['username'] or "Unknown"

                    # Check for suspicious location
                    exe_lower = exe.lower() if exe else ""
                    is_suspicious = False
                    suspicious_reason = ""

                    for sus_loc in SUSPICIOUS_LOCATIONS:
                        if sus_loc in exe_lower:
                            is_suspicious = True
                            suspicious_reason = f"Running from suspicious location: {exe}"
                            break

                    # Check for processes without executable path
                    if not exe and name not in ["System", "Registry", "Memory Compression", "Idle"]:
                        # Could indicate hidden process
                        pass

                    if is_suspicious:
                        suspicious.append({
                            "pid": pid,
                            "name": name,
                            "exe": exe,
                            "reason": suspicious_reason,
                            "username": username
                        })

                    # High resource usage
                    if cpu > 50:
                        high_cpu.append({"pid": pid, "name": name, "cpu": cpu})
                    if memory > 10:
                        high_memory.append({"pid": pid, "name": name, "memory": memory})

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            raw_data["suspicious"] = suspicious
            raw_data["high_cpu"] = high_cpu
            raw_data["high_memory"] = high_memory

            # Summary finding
            findings.append(self._finding(
                title=f"Running processes: {len(processes)}",
                description=f"{len(suspicious)} flagged for review",
                severity=Severity.INFO
            ))

            # Suspicious processes
            if suspicious:
                for proc in suspicious:
                    findings.append(self._finding(
                        title=f"Suspicious: {proc['name']} (PID: {proc['pid']})",
                        description=proc['reason'][:100],
                        severity=Severity.WARNING,
                        recommendation="Investigate this process"
                    ))
            else:
                findings.append(self._finding(
                    title="No obviously suspicious processes detected",
                    description="Process locations appear normal",
                    severity=Severity.PASS
                ))

            # High resource processes
            if high_cpu:
                top_cpu = sorted(high_cpu, key=lambda x: x['cpu'], reverse=True)[:3]
                for proc in top_cpu:
                    findings.append(self._finding(
                        title=f"High CPU: {proc['name']}",
                        description=f"Using {proc['cpu']:.0f}% CPU",
                        severity=Severity.INFO
                    ))

            if high_memory:
                top_mem = sorted(high_memory, key=lambda x: x['memory'], reverse=True)[:3]
                for proc in top_mem:
                    findings.append(self._finding(
                        title=f"High Memory: {proc['name']}",
                        description=f"Using {proc['memory']:.1f}% RAM",
                        severity=Severity.INFO
                    ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
