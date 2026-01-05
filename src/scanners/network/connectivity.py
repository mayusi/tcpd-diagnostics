"""Connectivity Scanner - Internet connectivity and latency tests."""
import subprocess
import socket
import time
from typing import List, Dict, Optional
from urllib.request import urlopen
from urllib.error import URLError

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class ConnectivityScanner(BaseScanner):
    """Test internet connectivity, DNS resolution, and latency."""

    name = "Connectivity"
    category = "network"
    description = "Internet connectivity and latency tests"
    requires_admin = False
    dependencies = []

    # Test targets
    PING_TARGETS = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("208.67.222.222", "OpenDNS"),
    ]

    DNS_TARGETS = [
        "google.com",
        "microsoft.com",
        "cloudflare.com",
    ]

    HTTP_TARGETS = [
        ("https://www.google.com", "Google"),
        ("https://www.microsoft.com", "Microsoft"),
        ("https://www.cloudflare.com", "Cloudflare"),
    ]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "ping_results": [],
            "dns_results": [],
            "http_results": [],
        }

        # Run all connectivity tests
        ping_ok = self._run_ping_tests(findings, raw_data)
        dns_ok = self._run_dns_tests(findings, raw_data)
        http_ok = self._run_http_tests(findings, raw_data)

        # Overall connectivity status
        if ping_ok and dns_ok and http_ok:
            findings.insert(0, self._finding(
                title="Internet Connectivity OK",
                description="All connectivity tests passed successfully",
                severity=Severity.PASS
            ))
        elif ping_ok and not dns_ok:
            findings.insert(0, self._finding(
                title="DNS Issues Detected",
                description="Can reach internet but DNS resolution is failing",
                severity=Severity.WARNING,
                recommendation="Check DNS server settings or try 8.8.8.8/1.1.1.1"
            ))
        elif not ping_ok:
            findings.insert(0, self._finding(
                title="No Internet Connection",
                description="Cannot reach any external hosts",
                severity=Severity.CRITICAL,
                recommendation="Check network cable/WiFi connection and router"
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _run_ping_tests(self, findings: List[Finding], raw_data: Dict) -> bool:
        """Run ping tests to multiple targets."""
        successful_pings = 0

        for ip, name in self.PING_TARGETS:
            result = self._ping(ip)
            raw_data["ping_results"].append({
                "target": ip,
                "name": name,
                "success": result["success"],
                "latency_ms": result.get("latency_ms"),
            })

            if result["success"]:
                successful_pings += 1
                latency = result.get("latency_ms", 0)

                severity = Severity.PASS
                if latency > 200:
                    severity = Severity.WARNING
                elif latency > 500:
                    severity = Severity.CRITICAL

                findings.append(self._finding(
                    title=f"Ping {name}",
                    description=f"{ip} - {latency:.0f}ms latency",
                    severity=severity,
                    details={"latency_ms": latency}
                ))
            else:
                findings.append(self._finding(
                    title=f"Ping {name} Failed",
                    description=f"Cannot reach {ip}",
                    severity=Severity.WARNING
                ))

        return successful_pings > 0

    def _run_dns_tests(self, findings: List[Finding], raw_data: Dict) -> bool:
        """Run DNS resolution tests."""
        successful_dns = 0

        for domain in self.DNS_TARGETS:
            start = time.perf_counter()
            try:
                ip = socket.gethostbyname(domain)
                latency = (time.perf_counter() - start) * 1000
                successful_dns += 1

                raw_data["dns_results"].append({
                    "domain": domain,
                    "ip": ip,
                    "success": True,
                    "latency_ms": latency,
                })

                findings.append(self._finding(
                    title=f"DNS Resolve: {domain}",
                    description=f"Resolved to {ip} in {latency:.0f}ms",
                    severity=Severity.PASS,
                    details={"ip": ip, "latency_ms": latency}
                ))

            except socket.gaierror as e:
                latency = (time.perf_counter() - start) * 1000
                raw_data["dns_results"].append({
                    "domain": domain,
                    "success": False,
                    "error": str(e),
                    "latency_ms": latency,
                })

                findings.append(self._finding(
                    title=f"DNS Resolve Failed: {domain}",
                    description=f"Could not resolve domain",
                    severity=Severity.WARNING,
                    recommendation="Check DNS settings"
                ))

        return successful_dns > 0

    def _run_http_tests(self, findings: List[Finding], raw_data: Dict) -> bool:
        """Run HTTP/HTTPS connectivity tests."""
        successful_http = 0

        for url, name in self.HTTP_TARGETS:
            start = time.perf_counter()
            try:
                response = urlopen(url, timeout=10)
                latency = (time.perf_counter() - start) * 1000
                status = response.getcode()
                successful_http += 1

                raw_data["http_results"].append({
                    "url": url,
                    "name": name,
                    "success": True,
                    "status_code": status,
                    "latency_ms": latency,
                })

                severity = Severity.PASS
                if latency > 3000:
                    severity = Severity.WARNING

                findings.append(self._finding(
                    title=f"HTTP {name}",
                    description=f"Status {status} in {latency:.0f}ms",
                    severity=severity,
                    details={"status_code": status, "latency_ms": latency}
                ))

            except (URLError, Exception) as e:
                latency = (time.perf_counter() - start) * 1000
                raw_data["http_results"].append({
                    "url": url,
                    "name": name,
                    "success": False,
                    "error": str(e),
                    "latency_ms": latency,
                })

                findings.append(self._finding(
                    title=f"HTTP {name} Failed",
                    description=f"Could not connect: {str(e)[:50]}",
                    severity=Severity.WARNING
                ))

        return successful_http > 0

    def _ping(self, host: str, timeout: int = 3) -> Dict:
        """Ping a host and return results."""
        try:
            # Windows ping command
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            start = time.perf_counter()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            elapsed = (time.perf_counter() - start) * 1000

            if result.returncode == 0:
                # Parse latency from output
                latency = self._parse_ping_latency(result.stdout) or elapsed
                return {"success": True, "latency_ms": latency}
            else:
                return {"success": False}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_ping_latency(self, output: str) -> Optional[float]:
        """Parse latency from Windows ping output."""
        try:
            # Look for "time=XXms" or "time<1ms"
            for line in output.split('\n'):
                if 'time=' in line.lower() or 'time<' in line.lower():
                    # Extract the number
                    import re
                    match = re.search(r'time[=<](\d+)', line, re.IGNORECASE)
                    if match:
                        return float(match.group(1))
        except Exception:
            pass
        return None
