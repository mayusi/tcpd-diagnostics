"""Result models for diagnostic findings."""
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json


class Severity(Enum):
    """Severity levels for findings."""
    PASS = "pass"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single diagnostic finding."""
    title: str
    description: str
    severity: Severity
    category: str
    component: Optional[str] = None
    recommendation: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "component": self.component,
            "recommendation": self.recommendation,
            "details": self.details
        }


@dataclass
class ScanResult:
    """Result from a single scanner."""
    scanner_name: str
    category: str
    success: bool
    findings: List[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "category": self.category,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "raw_data": self.raw_data,
            "error": self.error,
            "timestamp": self.timestamp.isoformat()
        }

    @property
    def critical_count(self) -> int:
        """Count critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        """Count warning findings."""
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def pass_count(self) -> int:
        """Count passed findings."""
        return sum(1 for f in self.findings if f.severity == Severity.PASS)


@dataclass
class DiagnosticsReport:
    """Complete diagnostics report."""
    results: List[ScanResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    system_info: Dict[str, Any] = field(default_factory=dict)

    def add_result(self, result: ScanResult):
        """Add a scan result."""
        self.results.append(result)

    def finalize(self):
        """Mark report as complete."""
        self.end_time = datetime.now()

    @property
    def total_duration_ms(self) -> float:
        """Total scan duration in milliseconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return sum(r.duration_ms for r in self.results)

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings from all results."""
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    @property
    def critical_count(self) -> int:
        """Total critical findings."""
        return sum(r.critical_count for r in self.results)

    @property
    def warning_count(self) -> int:
        """Total warning findings."""
        return sum(r.warning_count for r in self.results)

    @property
    def pass_count(self) -> int:
        """Total passed findings."""
        return sum(r.pass_count for r in self.results)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_duration_ms": self.total_duration_ms,
            "summary": {
                "total_scanners": len(self.results),
                "successful_scans": sum(1 for r in self.results if r.success),
                "failed_scans": sum(1 for r in self.results if not r.success),
                "critical_issues": self.critical_count,
                "warnings": self.warning_count,
                "passed": self.pass_count
            },
            "system_info": self.system_info,
            "results": [r.to_dict() for r in self.results]
        }

    def to_json(self, indent: int = 2) -> str:
        """Export report as JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, filepath: str):
        """Save report to JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
