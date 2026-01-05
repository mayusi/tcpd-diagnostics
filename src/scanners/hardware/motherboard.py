"""Motherboard Scanner - Motherboard and BIOS information."""
from typing import List

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class MotherboardScanner(BaseScanner):
    """Scan motherboard and BIOS information."""

    name = "Motherboard"
    category = "hardware"
    description = "Motherboard and BIOS details"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {}

        try:
            # Get motherboard info
            board_info = wmi_query("Win32_BaseBoard")
            if board_info:
                board = board_info[0]
                raw_data["manufacturer"] = board.get("Manufacturer", "Unknown")
                raw_data["model"] = board.get("Product", "Unknown")
                raw_data["serial"] = board.get("SerialNumber", "")
                raw_data["version"] = board.get("Version", "")

                findings.append(self._finding(
                    title=f"{raw_data['manufacturer']} {raw_data['model']}",
                    description=f"Motherboard",
                    severity=Severity.PASS
                ))

            # Get BIOS info
            bios_info = wmi_query("Win32_BIOS")
            if bios_info:
                bios = bios_info[0]
                raw_data["bios_vendor"] = bios.get("Manufacturer", "Unknown")
                raw_data["bios_version"] = bios.get("SMBIOSBIOSVersion", "Unknown")
                raw_data["bios_date"] = bios.get("ReleaseDate", "Unknown")
                raw_data["smbios_version"] = f"{bios.get('SMBIOSMajorVersion', 0)}.{bios.get('SMBIOSMinorVersion', 0)}"

                # Parse BIOS date
                bios_date = raw_data["bios_date"]
                if bios_date and len(bios_date) >= 8:
                    try:
                        year = bios_date[:4]
                        month = bios_date[4:6]
                        day = bios_date[6:8]
                        bios_date = f"{year}-{month}-{day}"
                    except Exception:
                        pass

                findings.append(self._finding(
                    title=f"BIOS: {raw_data['bios_version']}",
                    description=f"{raw_data['bios_vendor']}, Date: {bios_date}",
                    severity=Severity.PASS
                ))

            # Get system info
            system_info = wmi_query("Win32_ComputerSystem")
            if system_info:
                system = system_info[0]
                raw_data["system_manufacturer"] = system.get("Manufacturer", "Unknown")
                raw_data["system_model"] = system.get("Model", "Unknown")
                raw_data["system_type"] = system.get("SystemType", "Unknown")
                raw_data["total_physical_memory_gb"] = int(system.get("TotalPhysicalMemory", 0)) / (1024 ** 3)

                findings.append(self._finding(
                    title=f"System: {raw_data['system_manufacturer']} {raw_data['system_model']}",
                    description=f"Type: {raw_data['system_type']}",
                    severity=Severity.INFO
                ))

            # Get computer system product (for laptops/OEM systems)
            product_info = wmi_query("Win32_ComputerSystemProduct")
            if product_info:
                product = product_info[0]
                raw_data["product_name"] = product.get("Name", "")
                raw_data["product_uuid"] = product.get("UUID", "")
                raw_data["product_vendor"] = product.get("Vendor", "")

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))
