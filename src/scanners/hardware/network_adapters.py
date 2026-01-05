"""Network Adapters Scanner - Network interface information."""
import psutil
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class NetworkAdaptersScanner(BaseScanner):
    """Scan network adapter information."""

    name = "Network Adapters"
    category = "hardware"
    description = "Network interfaces and connectivity"
    requires_admin = False
    dependencies = ["psutil"]

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {"adapters": []}

        try:
            # Get adapter configurations from WMI
            configs = {}
            config_info = wmi_query("Win32_NetworkAdapterConfiguration")
            for cfg in config_info:
                index = cfg.get("Index")
                if index is not None:
                    configs[index] = cfg

            # Get physical adapters from WMI
            adapters = wmi_query("Win32_NetworkAdapter")
            for adapter in adapters:
                # Only physical adapters
                if not adapter.get("PhysicalAdapter"):
                    continue

                index = adapter.get("Index")
                config = configs.get(index, {})

                # Get IP addresses
                ip_addresses = config.get("IPAddress", []) or []
                ipv4 = [ip for ip in ip_addresses if ip and ":" not in ip]
                ipv6 = [ip for ip in ip_addresses if ip and ":" in ip]

                # Get speed in Mbps
                speed = adapter.get("Speed")
                speed_mbps = int(speed) // 1_000_000 if speed else 0

                adapter_info = {
                    "name": adapter.get("Name", "Unknown"),
                    "description": adapter.get("Description", ""),
                    "mac_address": adapter.get("MACAddress", ""),
                    "speed_mbps": speed_mbps,
                    "status": adapter.get("NetConnectionStatus", 0),
                    "ipv4_addresses": ipv4,
                    "ipv6_addresses": ipv6,
                    "gateway": (config.get("DefaultIPGateway") or [None])[0],
                    "dns_servers": config.get("DNSServerSearchOrder") or [],
                    "dhcp_enabled": config.get("DHCPEnabled", False)
                }

                raw_data["adapters"].append(adapter_info)

                # Determine connection status
                status_map = {
                    0: "Disconnected",
                    1: "Connecting",
                    2: "Connected",
                    3: "Disconnecting",
                    4: "Hardware not present",
                    5: "Hardware disabled",
                    6: "Hardware malfunction",
                    7: "Media disconnected",
                    8: "Authenticating",
                    9: "Authentication succeeded",
                    10: "Authentication failed",
                    11: "Invalid address",
                    12: "Credentials required"
                }
                status_text = status_map.get(adapter_info["status"], "Unknown")

                # Determine adapter type
                name_lower = adapter_info["name"].lower()
                if "wi-fi" in name_lower or "wireless" in name_lower or "wlan" in name_lower:
                    adapter_type = "WiFi"
                elif "ethernet" in name_lower or "lan" in name_lower:
                    adapter_type = "Ethernet"
                elif "bluetooth" in name_lower:
                    adapter_type = "Bluetooth"
                else:
                    adapter_type = "Network"

                # Connection status severity
                severity = Severity.PASS if adapter_info["status"] == 2 else Severity.INFO

                # IP info string
                ip_str = ", ".join(ipv4) if ipv4 else "No IP"
                speed_str = f"{speed_mbps} Mbps" if speed_mbps else "Unknown speed"

                findings.append(self._finding(
                    title=f"{adapter_type}: {adapter_info['name'][:40]}",
                    description=f"{status_text} | {ip_str} | {speed_str}",
                    severity=severity,
                    details={"mac": adapter_info["mac_address"]}
                ))

            # Get network IO stats
            try:
                io_stats = psutil.net_io_counters()
                raw_data["total_bytes_sent"] = io_stats.bytes_sent
                raw_data["total_bytes_recv"] = io_stats.bytes_recv
                raw_data["packets_sent"] = io_stats.packets_sent
                raw_data["packets_recv"] = io_stats.packets_recv
                raw_data["errors_in"] = io_stats.errin
                raw_data["errors_out"] = io_stats.errout

                if io_stats.errin > 0 or io_stats.errout > 0:
                    findings.append(self._finding(
                        title="Network errors detected",
                        description=f"In: {io_stats.errin}, Out: {io_stats.errout}",
                        severity=Severity.WARNING,
                        recommendation="Check network cables and drivers"
                    ))
            except Exception:
                pass

            if not raw_data["adapters"]:
                findings.append(self._finding(
                    title="No network adapters detected",
                    description="Could not find any physical network adapters",
                    severity=Severity.WARNING
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
