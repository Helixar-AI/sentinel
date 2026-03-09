"""9 tests for core data models: Severity, Finding, ScanResult."""
import pytest

from sentinel.core import Finding, ScanResult, Severity


class TestSeverity:
    def test_severity_ordering_critical_highest(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_severity_from_string_valid(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM

    def test_severity_from_string_invalid(self):
        with pytest.raises(ValueError):
            Severity.from_string("unknown")

    def test_severity_comparison_le_ge(self):
        assert Severity.LOW <= Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.CRITICAL >= Severity.CRITICAL


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            rule_id="CFG-001",
            severity=Severity.CRITICAL,
            title="No auth",
            detail="Auth block missing.",
            location="/etc/mcp.json",
        )
        assert f.rule_id == "CFG-001"
        assert f.severity == Severity.CRITICAL
        assert f.title == "No auth"

    def test_finding_severity_coercion_from_string(self):
        f = Finding(
            rule_id="CFG-002",
            severity="HIGH",
            title="Plaintext secret",
            detail="Key found.",
            location="/etc/mcp.json",
        )
        assert f.severity == Severity.HIGH

    def test_finding_defaults(self):
        f = Finding(
            rule_id="CFG-010",
            severity=Severity.LOW,
            title="No timeout",
            detail="Missing timeout.",
            location="config.json",
        )
        assert f.remediation == ""
        assert f.reference == ""


class TestScanResult:
    def test_scan_result_empty(self):
        r = ScanResult(module="config", target="test.json")
        assert not r.has_findings
        assert r.highest_severity is None
        assert r.counts_by_severity[Severity.CRITICAL] == 0

    def test_scan_result_add_finding(self):
        r = ScanResult(module="config", target="test.json")
        f = Finding("CFG-001", Severity.CRITICAL, "No auth", "Missing.", "test.json")
        r.add_finding(f)
        assert r.has_findings
        assert len(r.findings) == 1

    def test_scan_result_counts_by_severity(self):
        r = ScanResult(module="config", target="test.json")
        r.add_finding(Finding("CFG-001", Severity.CRITICAL, "A", "B", "C"))
        r.add_finding(Finding("CFG-004", Severity.HIGH, "A", "B", "C"))
        r.add_finding(Finding("CFG-005", Severity.HIGH, "A", "B", "C"))
        counts = r.counts_by_severity
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.MEDIUM] == 0

    def test_scan_result_highest_severity(self):
        r = ScanResult(module="config", target="test.json")
        r.add_finding(Finding("CFG-004", Severity.HIGH, "A", "B", "C"))
        r.add_finding(Finding("CFG-010", Severity.LOW, "A", "B", "C"))
        assert r.highest_severity == Severity.HIGH
