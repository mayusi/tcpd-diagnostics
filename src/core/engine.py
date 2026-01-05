"""Scan engine - Orchestrates all diagnostic scanners."""
from typing import List, Dict, Type, Optional, Callable
from datetime import datetime

from .scanner import BaseScanner
from .result import DiagnosticsReport, ScanResult


class ScanEngine:
    """Orchestrates diagnostic scans across all registered scanners."""

    # Scan mode definitions
    MODES = {
        "quick": ["cpu", "memory", "disk_usage", "antivirus", "firewall"],
        "full": None,  # None means all scanners
        "hardware": ["cpu", "gpu", "memory", "storage", "battery", "motherboard", "network_adapters", "peripherals"],
        "security": ["antivirus", "firewall", "windows_update", "ports", "processes", "startup", "services", "registry", "users", "bitlocker", "secure_boot", "uac", "password_policy", "event_log"],
        "network": ["network_adapters", "connectivity", "wifi", "dns", "speed_test"]
    }

    def __init__(self, is_admin: bool = False):
        self.is_admin = is_admin
        self._scanners: Dict[str, BaseScanner] = {}
        self._report: Optional[DiagnosticsReport] = None

    def register_scanner(self, scanner: BaseScanner):
        """Register a scanner instance."""
        scanner.set_admin_status(self.is_admin)
        # Use a normalized key based on scanner name
        key = scanner.name.lower().replace(" ", "_")
        self._scanners[key] = scanner

    def register_scanners(self, scanners: List[BaseScanner]):
        """Register multiple scanners."""
        for scanner in scanners:
            self.register_scanner(scanner)

    def get_scanners_for_mode(self, mode: str) -> List[BaseScanner]:
        """Get list of scanners for a given mode."""
        allowed = self.MODES.get(mode)

        if allowed is None:
            # Full mode - return all scanners
            return list(self._scanners.values())

        # Filter scanners by mode
        result = []
        for key, scanner in self._scanners.items():
            # Match by key or category
            if key in allowed or scanner.category in allowed:
                result.append(scanner)

        return result

    def run_scan(
        self,
        mode: str = "quick",
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> DiagnosticsReport:
        """
        Run diagnostics scan.

        Args:
            mode: Scan mode (quick, full, hardware, security, network)
            progress_callback: Optional callback(current, total, scanner_name)

        Returns:
            DiagnosticsReport with all results
        """
        self._report = DiagnosticsReport()
        scanners = self.get_scanners_for_mode(mode)
        total = len(scanners)

        for i, scanner in enumerate(scanners):
            if progress_callback:
                progress_callback(i, total, scanner.name)

            result = scanner.run()
            self._report.add_result(result)

        self._report.finalize()

        if progress_callback:
            progress_callback(total, total, "Complete")

        return self._report

    def run_single_scanner(self, scanner_name: str) -> Optional[ScanResult]:
        """Run a single scanner by name."""
        key = scanner_name.lower().replace(" ", "_")
        scanner = self._scanners.get(key)

        if scanner:
            return scanner.run()
        return None

    @property
    def available_scanners(self) -> List[str]:
        """List all registered scanner names."""
        return list(self._scanners.keys())

    @property
    def scanner_count(self) -> int:
        """Number of registered scanners."""
        return len(self._scanners)
