"""Speed Test Scanner - Network speed estimation."""
import time
import socket
import subprocess
from typing import List, Dict, Optional
from urllib.request import urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class SpeedTestScanner(BaseScanner):
    """Estimate network download/upload speeds and latency."""

    name = "Speed Test"
    category = "network"
    description = "Network speed and latency estimation"
    requires_admin = False
    dependencies = []

    # Test files for download speed estimation (small files for quick test)
    DOWNLOAD_URLS = [
        ("https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png", "Google", 13504),
        ("https://www.cloudflare.com/favicon.ico", "Cloudflare", 1406),
        ("https://github.githubassets.com/favicons/favicon.png", "GitHub", 1374),
    ]

    # Ping targets for latency
    PING_TARGETS = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare"),
    ]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "download_tests": [],
            "latency_tests": [],
            "estimated_download_mbps": None,
            "average_latency_ms": None,
            "packet_loss_percent": 0,
        }

        # Run latency tests first
        latency_results = self._test_latency()
        raw_data["latency_tests"] = latency_results

        if latency_results:
            successful = [r for r in latency_results if r.get("success")]
            if successful:
                avg_latency = sum(r["avg_ms"] for r in successful) / len(successful)
                raw_data["average_latency_ms"] = avg_latency

                severity = Severity.PASS
                quality = "Excellent"
                if avg_latency > 150:
                    severity = Severity.CRITICAL
                    quality = "Poor"
                elif avg_latency > 100:
                    severity = Severity.WARNING
                    quality = "Fair"
                elif avg_latency > 50:
                    severity = Severity.PASS
                    quality = "Good"

                findings.append(self._finding(
                    title=f"Network Latency: {avg_latency:.0f}ms",
                    description=f"Average ping latency ({quality})",
                    severity=severity,
                    details={"latency_ms": avg_latency}
                ))

                # Check packet loss
                total_sent = sum(r.get("sent", 0) for r in latency_results)
                total_lost = sum(r.get("lost", 0) for r in latency_results)
                if total_sent > 0:
                    loss_pct = (total_lost / total_sent) * 100
                    raw_data["packet_loss_percent"] = loss_pct

                    if loss_pct > 5:
                        findings.append(self._finding(
                            title=f"Packet Loss: {loss_pct:.1f}%",
                            description="Significant packet loss detected",
                            severity=Severity.CRITICAL,
                            recommendation="Check network connection stability"
                        ))
                    elif loss_pct > 0:
                        findings.append(self._finding(
                            title=f"Packet Loss: {loss_pct:.1f}%",
                            description="Minor packet loss detected",
                            severity=Severity.WARNING
                        ))
                    else:
                        findings.append(self._finding(
                            title="Packet Loss: 0%",
                            description="No packet loss detected",
                            severity=Severity.PASS
                        ))

        # Run download speed tests
        download_results = self._test_download_speed()
        raw_data["download_tests"] = download_results

        if download_results:
            successful = [r for r in download_results if r.get("success")]
            if successful:
                # Calculate estimated speed from all tests
                total_bytes = sum(r["bytes"] for r in successful)
                total_time = sum(r["time_seconds"] for r in successful)

                if total_time > 0:
                    bytes_per_second = total_bytes / total_time
                    mbps = (bytes_per_second * 8) / (1024 * 1024)
                    raw_data["estimated_download_mbps"] = mbps

                    # Estimate actual speed (small files underestimate)
                    # Real speed is likely 10-50x higher due to test file sizes
                    estimated_real = mbps * 20  # Rough estimate multiplier

                    severity = Severity.PASS
                    quality = "Fast"
                    if estimated_real < 10:
                        severity = Severity.CRITICAL
                        quality = "Very Slow"
                    elif estimated_real < 25:
                        severity = Severity.WARNING
                        quality = "Slow"
                    elif estimated_real < 50:
                        severity = Severity.PASS
                        quality = "Moderate"
                    elif estimated_real < 100:
                        severity = Severity.PASS
                        quality = "Good"

                    findings.append(self._finding(
                        title=f"Download Speed Estimate",
                        description=f"Approx. {estimated_real:.0f}+ Mbps ({quality}) - Based on small file tests",
                        severity=severity,
                        details={"measured_mbps": mbps, "estimated_mbps": estimated_real},
                        recommendation="For accurate speed test, use speedtest.net" if estimated_real < 25 else None
                    ))

            failed = len(download_results) - len(successful)
            if failed > 0:
                findings.append(self._finding(
                    title=f"Download Tests Failed: {failed}",
                    description="Some download tests could not complete",
                    severity=Severity.WARNING
                ))
        else:
            findings.append(self._finding(
                title="Download Speed Test Failed",
                description="Could not perform download speed test",
                severity=Severity.WARNING,
                recommendation="Check internet connection"
            ))

        # Connection quality summary
        latency_ok = raw_data.get("average_latency_ms", 999) < 100
        speed_ok = raw_data.get("estimated_download_mbps", 0) > 0.5
        no_loss = raw_data.get("packet_loss_percent", 100) < 1

        if latency_ok and speed_ok and no_loss:
            findings.insert(0, self._finding(
                title="Connection Quality: Good",
                description="Low latency, stable connection, acceptable speed",
                severity=Severity.PASS
            ))
        elif latency_ok and speed_ok:
            findings.insert(0, self._finding(
                title="Connection Quality: Fair",
                description="Connection works but has some issues",
                severity=Severity.WARNING
            ))
        else:
            findings.insert(0, self._finding(
                title="Connection Quality: Poor",
                description="High latency or connection issues detected",
                severity=Severity.CRITICAL,
                recommendation="Check network hardware and ISP connection"
            ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _test_latency(self) -> List[Dict]:
        """Test network latency using ping."""
        results = []

        for host, name in self.PING_TARGETS:
            try:
                # Run ping with 5 packets
                result = subprocess.run(
                    ["ping", "-n", "5", "-w", "2000", host],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if result.returncode == 0:
                    # Parse results
                    output = result.stdout

                    # Get packet stats
                    sent, received, lost = 5, 5, 0
                    stats_match = None
                    for line in output.split('\n'):
                        if 'Sent' in line or 'Packets' in line:
                            import re
                            nums = re.findall(r'(\d+)', line)
                            if len(nums) >= 3:
                                sent, received, lost = int(nums[0]), int(nums[1]), int(nums[2])

                    # Get latency stats
                    min_ms, max_ms, avg_ms = 0, 0, 0
                    for line in output.split('\n'):
                        if 'Minimum' in line or 'Average' in line:
                            import re
                            nums = re.findall(r'(\d+)', line)
                            if len(nums) >= 3:
                                min_ms, max_ms, avg_ms = int(nums[0]), int(nums[1]), int(nums[2])

                    results.append({
                        "host": host,
                        "name": name,
                        "success": True,
                        "sent": sent,
                        "received": received,
                        "lost": lost,
                        "min_ms": min_ms,
                        "max_ms": max_ms,
                        "avg_ms": avg_ms,
                    })
                else:
                    results.append({
                        "host": host,
                        "name": name,
                        "success": False,
                    })

            except Exception as e:
                results.append({
                    "host": host,
                    "name": name,
                    "success": False,
                    "error": str(e),
                })

        return results

    def _test_download_speed(self) -> List[Dict]:
        """Test download speed by downloading small files."""
        results = []

        for url, name, expected_size in self.DOWNLOAD_URLS:
            try:
                start = time.perf_counter()
                response = urlopen(url, timeout=10)
                data = response.read()
                elapsed = time.perf_counter() - start

                actual_size = len(data)

                results.append({
                    "url": url,
                    "name": name,
                    "success": True,
                    "bytes": actual_size,
                    "time_seconds": elapsed,
                    "speed_mbps": (actual_size * 8) / (elapsed * 1024 * 1024),
                })

            except Exception as e:
                results.append({
                    "url": url,
                    "name": name,
                    "success": False,
                    "error": str(e),
                })

        return results
