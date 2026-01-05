"""DNS Scanner - DNS server response times and configuration."""
import socket
import subprocess
import time
import re
from typing import List, Dict, Optional

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class DNSScanner(BaseScanner):
    """Test DNS servers and resolution performance."""

    name = "DNS"
    category = "network"
    description = "DNS server performance and configuration"
    requires_admin = False
    dependencies = []

    # Common DNS servers to test
    DNS_SERVERS = [
        ("8.8.8.8", "Google DNS"),
        ("8.8.4.4", "Google DNS Secondary"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("1.0.0.1", "Cloudflare DNS Secondary"),
        ("208.67.222.222", "OpenDNS"),
        ("9.9.9.9", "Quad9 DNS"),
    ]

    # Test domains for resolution
    TEST_DOMAINS = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "cloudflare.com",
        "github.com",
    ]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "configured_dns": [],
            "dns_benchmarks": [],
            "resolution_tests": [],
        }

        # Get configured DNS servers
        configured = self._get_configured_dns()
        raw_data["configured_dns"] = configured

        if configured:
            dns_list = ", ".join(configured[:3])
            findings.append(self._finding(
                title="Configured DNS Servers",
                description=dns_list,
                severity=Severity.INFO,
                details={"servers": configured}
            ))
        else:
            findings.append(self._finding(
                title="DNS Configuration",
                description="Could not detect configured DNS servers",
                severity=Severity.INFO
            ))

        # Benchmark DNS servers
        benchmarks = self._benchmark_dns_servers()
        raw_data["dns_benchmarks"] = benchmarks

        if benchmarks:
            # Find fastest
            fastest = min(benchmarks, key=lambda x: x.get("avg_ms", 9999))

            findings.append(self._finding(
                title=f"Fastest DNS: {fastest['name']}",
                description=f"{fastest['server']} - {fastest['avg_ms']:.0f}ms avg",
                severity=Severity.PASS,
                details={"server": fastest['server'], "latency_ms": fastest['avg_ms']}
            ))

            # Show current DNS performance vs best
            if configured:
                current_bench = next(
                    (b for b in benchmarks if b['server'] in configured),
                    None
                )
                if current_bench and current_bench.get('avg_ms', 0) > fastest['avg_ms'] * 2:
                    findings.append(self._finding(
                        title="Faster DNS Available",
                        description=f"Your DNS ({current_bench['avg_ms']:.0f}ms) is slower than {fastest['name']} ({fastest['avg_ms']:.0f}ms)",
                        severity=Severity.INFO,
                        recommendation=f"Consider switching to {fastest['server']} for faster DNS"
                    ))

            # Show all benchmarks
            for bench in sorted(benchmarks, key=lambda x: x.get("avg_ms", 9999)):
                if bench.get("success"):
                    severity = Severity.PASS if bench['avg_ms'] < 100 else Severity.INFO
                    findings.append(self._finding(
                        title=f"DNS: {bench['name']}",
                        description=f"{bench['server']} - {bench['avg_ms']:.0f}ms (min: {bench['min_ms']:.0f}ms, max: {bench['max_ms']:.0f}ms)",
                        severity=severity,
                        details=bench
                    ))
                else:
                    findings.append(self._finding(
                        title=f"DNS: {bench['name']} - Failed",
                        description=f"{bench['server']} - Could not reach",
                        severity=Severity.WARNING
                    ))

        # Test resolution with current DNS
        resolution_results = self._test_resolution()
        raw_data["resolution_tests"] = resolution_results

        success_count = sum(1 for r in resolution_results if r.get("success"))
        if success_count == len(resolution_results):
            findings.append(self._finding(
                title="DNS Resolution: All Tests Passed",
                description=f"Successfully resolved {success_count} domains",
                severity=Severity.PASS
            ))
        elif success_count > 0:
            findings.append(self._finding(
                title="DNS Resolution: Partial",
                description=f"Resolved {success_count}/{len(resolution_results)} domains",
                severity=Severity.WARNING,
                recommendation="Some domains failed to resolve"
            ))
        else:
            findings.append(self._finding(
                title="DNS Resolution: Failed",
                description="Could not resolve any test domains",
                severity=Severity.CRITICAL,
                recommendation="Check DNS settings and internet connection"
            ))

        # Check for DNS hijacking indicators
        hijack_check = self._check_dns_hijacking()
        if hijack_check.get("suspicious"):
            findings.append(self._finding(
                title="Possible DNS Hijacking Detected",
                description=hijack_check.get("reason", "Suspicious DNS behavior"),
                severity=Severity.CRITICAL,
                recommendation="Check for malware, run antivirus scan"
            ))
        else:
            findings.append(self._finding(
                title="DNS Hijacking Check: OK",
                description="No signs of DNS manipulation",
                severity=Severity.PASS
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _get_configured_dns(self) -> List[str]:
        """Get currently configured DNS servers."""
        dns_servers = []

        try:
            # Use ipconfig /all to get DNS servers
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                in_dns_section = False
                for line in result.stdout.split('\n'):
                    if 'DNS Servers' in line or 'DNS-Server' in line:
                        in_dns_section = True
                        # Extract IP from same line if present
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            dns_servers.append(match.group(1))
                    elif in_dns_section:
                        # Check for additional DNS on next lines
                        match = re.search(r'^\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            dns_servers.append(match.group(1))
                        elif line.strip() and ':' in line:
                            # New section started
                            in_dns_section = False

        except Exception:
            pass

        return list(set(dns_servers))  # Remove duplicates

    def _benchmark_dns_servers(self) -> List[Dict]:
        """Benchmark response times for various DNS servers."""
        results = []

        for server, name in self.DNS_SERVERS:
            timings = []
            success = False

            # Do 3 tests per server
            for _ in range(3):
                start = time.perf_counter()
                try:
                    # Use nslookup to test specific DNS server
                    result = subprocess.run(
                        ["nslookup", "google.com", server],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    elapsed = (time.perf_counter() - start) * 1000

                    if result.returncode == 0 and "Address" in result.stdout:
                        timings.append(elapsed)
                        success = True

                except Exception:
                    pass

            if timings:
                results.append({
                    "server": server,
                    "name": name,
                    "success": success,
                    "min_ms": min(timings),
                    "max_ms": max(timings),
                    "avg_ms": sum(timings) / len(timings),
                })
            else:
                results.append({
                    "server": server,
                    "name": name,
                    "success": False,
                })

        return results

    def _test_resolution(self) -> List[Dict]:
        """Test DNS resolution for various domains."""
        results = []

        for domain in self.TEST_DOMAINS:
            start = time.perf_counter()
            try:
                ip = socket.gethostbyname(domain)
                elapsed = (time.perf_counter() - start) * 1000
                results.append({
                    "domain": domain,
                    "success": True,
                    "ip": ip,
                    "latency_ms": elapsed,
                })
            except socket.gaierror as e:
                elapsed = (time.perf_counter() - start) * 1000
                results.append({
                    "domain": domain,
                    "success": False,
                    "error": str(e),
                    "latency_ms": elapsed,
                })

        return results

    def _check_dns_hijacking(self) -> Dict:
        """Check for signs of DNS hijacking."""
        # Test by resolving a domain that should definitely not exist
        # If it resolves to an IP, something is intercepting DNS

        fake_domains = [
            "thisshouldnotexist12345.com",
            "definitelyfakedomainxyz987.net",
        ]

        for domain in fake_domains:
            try:
                ip = socket.gethostbyname(domain)
                # If we get an IP for a fake domain, that's suspicious
                return {
                    "suspicious": True,
                    "reason": f"Fake domain {domain} resolved to {ip} - possible DNS hijacking"
                }
            except socket.gaierror:
                # Expected - domain should not resolve
                pass

        return {"suspicious": False}
