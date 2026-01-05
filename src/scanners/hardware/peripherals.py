"""Peripherals Scanner - USB devices, audio, monitors."""
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class PeripheralsScanner(BaseScanner):
    """Scan USB devices, audio devices, and monitors."""

    name = "Peripherals"
    category = "hardware"
    description = "USB devices, audio, monitors"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {
            "usb_devices": [],
            "audio_devices": [],
            "monitors": []
        }

        try:
            # Get USB devices
            usb_devices = self._get_usb_devices()
            raw_data["usb_devices"] = usb_devices

            findings.append(self._finding(
                title=f"USB Devices: {len(usb_devices)} connected",
                description="USB peripherals attached to system",
                severity=Severity.INFO
            ))

            # List important USB devices
            for device in usb_devices[:5]:  # Top 5
                if device["name"] != "Unknown USB Device":
                    findings.append(self._finding(
                        title=f"USB: {device['name'][:50]}",
                        description=device.get("manufacturer", ""),
                        severity=Severity.INFO
                    ))

            # Get audio devices
            audio_devices = self._get_audio_devices()
            raw_data["audio_devices"] = audio_devices

            if audio_devices:
                findings.append(self._finding(
                    title=f"Audio Devices: {len(audio_devices)} detected",
                    description=", ".join(d["name"][:30] for d in audio_devices[:3]),
                    severity=Severity.PASS
                ))
            else:
                findings.append(self._finding(
                    title="No audio devices detected",
                    description="No sound devices found",
                    severity=Severity.WARNING
                ))

            # Get monitors
            monitors = self._get_monitors()
            raw_data["monitors"] = monitors

            if monitors:
                findings.append(self._finding(
                    title=f"Monitors: {len(monitors)} connected",
                    description=", ".join(m["name"][:30] for m in monitors),
                    severity=Severity.PASS
                ))
            else:
                findings.append(self._finding(
                    title="Monitor information unavailable",
                    description="Could not detect monitor details",
                    severity=Severity.INFO
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_usb_devices(self) -> List[dict]:
        """Get connected USB devices."""
        devices = []
        try:
            pnp_devices = wmi_query("Win32_PnPEntity")
            for device in pnp_devices:
                device_id = device.get("DeviceID", "")
                if device_id.startswith("USB"):
                    devices.append({
                        "name": device.get("Name") or "Unknown USB Device",
                        "device_id": device_id,
                        "manufacturer": device.get("Manufacturer", ""),
                        "status": device.get("Status", "Unknown"),
                        "description": device.get("Description", "")
                    })
        except Exception:
            pass
        return devices

    def _get_audio_devices(self) -> List[dict]:
        """Get audio devices."""
        devices = []
        try:
            sound_devices = wmi_query("Win32_SoundDevice")
            for device in sound_devices:
                devices.append({
                    "name": device.get("Name", "Unknown"),
                    "manufacturer": device.get("Manufacturer", ""),
                    "status": device.get("Status", "Unknown"),
                    "device_id": device.get("DeviceID", "")
                })
        except Exception:
            pass
        return devices

    def _get_monitors(self) -> List[dict]:
        """Get connected monitors."""
        monitors = []
        try:
            # Try WMI monitor ID
            monitor_info = wmi_query("WmiMonitorID", "root\\WMI")
            for mon in monitor_info:
                name = self._decode_wmi_string(mon.get("UserFriendlyName"))
                manufacturer = self._decode_wmi_string(mon.get("ManufacturerName"))
                serial = self._decode_wmi_string(mon.get("SerialNumberID"))

                monitors.append({
                    "name": name or "Unknown Monitor",
                    "manufacturer": manufacturer or "Unknown",
                    "serial": serial or "",
                    "active": mon.get("Active", True)
                })
        except Exception:
            pass

        # Fallback to desktop monitors
        if not monitors:
            try:
                desktop_monitors = wmi_query("Win32_DesktopMonitor")
                for mon in desktop_monitors:
                    monitors.append({
                        "name": mon.get("Name", "Unknown Monitor"),
                        "manufacturer": mon.get("MonitorManufacturer", "Unknown"),
                        "screen_width": mon.get("ScreenWidth"),
                        "screen_height": mon.get("ScreenHeight"),
                        "pnp_device_id": mon.get("PNPDeviceID", "")
                    })
            except Exception:
                pass

        return monitors

    def _decode_wmi_string(self, wmi_array) -> str:
        """Decode WMI uint16 array to string."""
        if not wmi_array:
            return ""
        try:
            return ''.join(chr(c) for c in wmi_array if c and c != 0)
        except Exception:
            return ""
