"""WiFi Scanner - Wireless network information and signal strength."""
import subprocess
import re
from typing import List, Dict, Optional

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity


class WiFiScanner(BaseScanner):
    """Scan WiFi connection details and signal strength."""

    name = "WiFi"
    category = "network"
    description = "WiFi signal strength and security"
    requires_admin = False
    dependencies = []

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "connected": False,
            "ssid": None,
            "signal_percent": None,
            "security": None,
            "channel": None,
            "band": None,
            "available_networks": [],
        }

        # Get current WiFi connection info
        current = self._get_current_connection()

        if current:
            raw_data["connected"] = True
            raw_data["ssid"] = current.get("ssid")
            raw_data["signal_percent"] = current.get("signal")
            raw_data["security"] = current.get("auth")
            raw_data["channel"] = current.get("channel")
            raw_data["band"] = current.get("band")

            signal = current.get("signal", 0)
            ssid = current.get("ssid", "Unknown")
            auth = current.get("auth", "Unknown")

            # Signal strength finding
            if signal >= 80:
                severity = Severity.PASS
                signal_desc = "Excellent"
            elif signal >= 60:
                severity = Severity.PASS
                signal_desc = "Good"
            elif signal >= 40:
                severity = Severity.WARNING
                signal_desc = "Fair"
            else:
                severity = Severity.CRITICAL
                signal_desc = "Poor"

            findings.append(self._finding(
                title=f"Connected to: {ssid}",
                description=f"Signal: {signal}% ({signal_desc})",
                severity=severity,
                details={"signal_percent": signal}
            ))

            # Security check
            if "WPA3" in auth:
                findings.append(self._finding(
                    title="WiFi Security: WPA3",
                    description="Using latest WPA3 security",
                    severity=Severity.PASS
                ))
            elif "WPA2" in auth:
                findings.append(self._finding(
                    title="WiFi Security: WPA2",
                    description="Using WPA2 security (standard)",
                    severity=Severity.PASS
                ))
            elif "WPA" in auth:
                findings.append(self._finding(
                    title="WiFi Security: WPA",
                    description="Using older WPA security",
                    severity=Severity.WARNING,
                    recommendation="Consider upgrading to WPA2/WPA3"
                ))
            elif "WEP" in auth or "Open" in auth.lower():
                findings.append(self._finding(
                    title="WiFi Security: INSECURE",
                    description=f"Using {auth} - easily hackable!",
                    severity=Severity.CRITICAL,
                    recommendation="Use WPA2 or WPA3 encryption immediately"
                ))
            else:
                findings.append(self._finding(
                    title=f"WiFi Security: {auth}",
                    description="Security type detected",
                    severity=Severity.INFO
                ))

            # Channel info
            if current.get("channel"):
                band = current.get("band", "Unknown")
                channel = current.get("channel")
                findings.append(self._finding(
                    title=f"WiFi Channel: {channel}",
                    description=f"Band: {band}",
                    severity=Severity.INFO,
                    details={"channel": channel, "band": band}
                ))

        else:
            # Not connected to WiFi
            findings.append(self._finding(
                title="WiFi Not Connected",
                description="No active WiFi connection detected",
                severity=Severity.INFO,
                recommendation="May be using Ethernet connection"
            ))

        # Scan for available networks
        networks = self._scan_networks()
        raw_data["available_networks"] = networks

        if networks:
            findings.append(self._finding(
                title=f"Available Networks: {len(networks)}",
                description=f"Found {len(networks)} WiFi networks in range",
                severity=Severity.INFO,
                details={"count": len(networks)}
            ))

            # Check for open networks (security risk)
            open_networks = [n for n in networks if n.get("security") == "Open"]
            if open_networks:
                findings.append(self._finding(
                    title=f"Open Networks Detected: {len(open_networks)}",
                    description="Unsecured WiFi networks found nearby",
                    severity=Severity.WARNING,
                    recommendation="Never connect to open networks"
                ))

        return self._create_result(findings=findings, raw_data=raw_data)

    def _get_current_connection(self) -> Optional[Dict]:
        """Get current WiFi connection details using netsh."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            info = {}

            # Parse the output
            for line in output.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if 'ssid' in key and 'bssid' not in key:
                        info['ssid'] = value
                    elif 'signal' in key:
                        # Extract percentage
                        match = re.search(r'(\d+)', value)
                        if match:
                            info['signal'] = int(match.group(1))
                    elif 'authentication' in key:
                        info['auth'] = value
                    elif 'channel' in key:
                        info['channel'] = value
                    elif 'radio type' in key or 'band' in key:
                        info['band'] = value

            # Only return if we have SSID (meaning connected)
            if info.get('ssid'):
                return info
            return None

        except Exception:
            return None

    def _scan_networks(self) -> List[Dict]:
        """Scan for available WiFi networks."""
        networks = []

        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return networks

            output = result.stdout
            current_network = {}

            for line in output.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if 'ssid' in key and 'bssid' not in key and value:
                        # New network
                        if current_network.get('ssid'):
                            networks.append(current_network)
                        current_network = {'ssid': value}
                    elif 'signal' in key:
                        match = re.search(r'(\d+)', value)
                        if match:
                            current_network['signal'] = int(match.group(1))
                    elif 'authentication' in key:
                        current_network['security'] = value
                    elif 'channel' in key:
                        current_network['channel'] = value

            # Add last network
            if current_network.get('ssid'):
                networks.append(current_network)

        except Exception:
            pass

        return networks
