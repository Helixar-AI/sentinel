"""Core data models for sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        try:
            return cls(value.upper())
        except (ValueError, AttributeError):
            raise ValueError(f"Unknown severity: {value!r}")


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    location: str
    remediation: str = ""
    reference: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)


@dataclass
class ScanResult:
    module: str
    target: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def counts_by_severity(self) -> dict:
        counts: dict = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
