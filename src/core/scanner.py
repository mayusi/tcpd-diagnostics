"""Base scanner interface."""
from abc import ABC, abstractmethod
from typing import List, Optional, Callable
import time

from .result import ScanResult, Finding, Severity


class BaseScanner(ABC):
    """Abstract base class for all diagnostic scanners."""

    # Scanner metadata - override in subclasses
    name: str = "BaseScanner"
    category: str = "general"
    description: str = "Base scanner"
    requires_admin: bool = False
    dependencies: List[str] = []

    def __init__(self):
        self._start_time: float = 0
        self._is_admin: bool = False

    def set_admin_status(self, is_admin: bool):
        """Set whether running with admin privileges."""
        self._is_admin = is_admin

    @abstractmethod
    def scan(self) -> ScanResult:
        """
        Execute the scan and return results.

        Must be implemented by all scanner subclasses.
        """
        pass

    def is_available(self) -> bool:
        """
        Check if this scanner can run in the current environment.

        Override to add custom availability checks.
        """
        if self.requires_admin and not self._is_admin:
            return False
        return self._check_dependencies()

    def _check_dependencies(self) -> bool:
        """Check if all required dependencies are available."""
        for dep in self.dependencies:
            try:
                __import__(dep)
            except ImportError:
                return False
        return True

    def run(self) -> ScanResult:
        """
        Run the scanner with timing and error handling.

        This is the main entry point for running a scanner.
        """
        self._start_time = time.perf_counter()

        try:
            if not self.is_available():
                return ScanResult(
                    scanner_name=self.name,
                    category=self.category,
                    success=False,
                    error="Scanner not available (missing dependencies or admin rights)",
                    duration_ms=self._elapsed_ms()
                )

            result = self.scan()
            result.duration_ms = self._elapsed_ms()
            return result

        except Exception as e:
            return ScanResult(
                scanner_name=self.name,
                category=self.category,
                success=False,
                error=str(e),
                duration_ms=self._elapsed_ms()
            )

    def _elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        return (time.perf_counter() - self._start_time) * 1000

    def _create_result(
        self,
        findings: List[Finding] = None,
        raw_data: dict = None,
        success: bool = True,
        error: str = None
    ) -> ScanResult:
        """Helper to create a ScanResult."""
        return ScanResult(
            scanner_name=self.name,
            category=self.category,
            success=success,
            findings=findings or [],
            raw_data=raw_data or {},
            error=error,
            duration_ms=self._elapsed_ms()
        )

    def _finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        component: str = None,
        recommendation: str = None,
        details: dict = None
    ) -> Finding:
        """Helper to create a Finding."""
        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            component=component or self.name,
            recommendation=recommendation,
            details=details or {}
        )
