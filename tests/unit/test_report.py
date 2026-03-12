"""17 tests for HTML, SARIF, and terminal renderers."""

from __future__ import annotations

from sentinel.core import Finding, ScanResult, Severity
from sentinel.report import html as html_report
from sentinel.report import sarif as sarif_report
from sentinel.report import terminal as terminal_report


def _make_result(module: str = "config", target: str = "test.json") -> ScanResult:
    return ScanResult(module=module, target=target)


def _make_finding(
    rule_id: str = "CFG-001",
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    detail: str = "Detail text.",
    location: str = "test.json",
    remediation: str = "Fix it.",
    reference: str = "https://checklist.helixar.ai#auth-001",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        location=location,
        remediation=remediation,
        reference=reference,
    )


# ── Terminal renderer ──────────────────────────────────────────────────────


class TestTerminalRenderer:
    def test_plain_output_is_string(self):
        r = _make_result()
        output = terminal_report.render_to_string([r])
        assert isinstance(output, str)
        assert len(output) > 0

    def test_empty_results_shows_no_findings(self):
        r = _make_result()
        output = terminal_report.render_to_string([r])
        assert "No findings" in output

    def test_findings_appear_in_output(self):
        r = _make_result()
        r.add_finding(_make_finding())
        output = terminal_report.render_to_string([r])
        assert "CFG-001" in output
        assert "Test finding" in output

    def test_helixar_footer_present(self):
        output = terminal_report.render_to_string([_make_result()])
        assert "helixar" in output.lower()

    def test_multiple_results_rendered(self):
        r1 = _make_result("config", "a.json")
        r2 = _make_result("probe", "https://example.com")
        r1.add_finding(_make_finding("CFG-001", Severity.CRITICAL))
        r2.add_finding(_make_finding("PRB-003", Severity.HIGH))
        output = terminal_report.render_to_string([r1, r2])
        assert "CFG-001" in output
        assert "PRB-003" in output
        assert "config" in output
        assert "probe" in output

    def test_severity_counts_in_summary(self):
        r = _make_result()
        r.add_finding(_make_finding("CFG-001", Severity.CRITICAL))
        r.add_finding(_make_finding("CFG-004", Severity.HIGH))
        output = terminal_report.render_to_string([r])
        assert "CRITICAL" in output
        assert "HIGH" in output


# ── HTML renderer ──────────────────────────────────────────────────────────


class TestHTMLRenderer:
    def test_returns_string(self):
        output = html_report.render([_make_result()])
        assert isinstance(output, str)

    def test_valid_html_structure(self):
        output = html_report.render([_make_result()])
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output

    def test_finding_appears_in_report(self):
        r = _make_result()
        r.add_finding(_make_finding(title="Critical Auth Issue"))
        output = html_report.render([r])
        assert "Critical Auth Issue" in output
        assert "CFG-001" in output

    def test_empty_results_shows_clean(self):
        output = html_report.render([_make_result()])
        assert "No findings" in output

    def test_helixar_footer_in_html(self):
        output = html_report.render([_make_result()])
        assert "helixar.ai" in output

    def test_severity_badge_in_html(self):
        r = _make_result()
        r.add_finding(_make_finding("CFG-001", Severity.CRITICAL))
        output = html_report.render([r])
        assert "CRITICAL" in output


# ── SARIF renderer ─────────────────────────────────────────────────────────


class TestSARIFRenderer:
    def test_sarif_returns_dict(self):
        sarif = sarif_report.render_sarif([_make_result()])
        assert isinstance(sarif, dict)

    def test_sarif_has_version(self):
        sarif = sarif_report.render_sarif([_make_result()])
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_runs(self):
        sarif = sarif_report.render_sarif([_make_result()])
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_finding_maps_correctly(self):
        r = _make_result()
        r.add_finding(_make_finding("CFG-001", Severity.CRITICAL))
        sarif = sarif_report.render_sarif([r])
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CFG-001"
        assert results[0]["level"] == "error"

    def test_sarif_empty_results(self):
        sarif = sarif_report.render_sarif([_make_result()])
        assert sarif["runs"][0]["results"] == []

    def test_json_renderer_returns_dict(self):
        data = sarif_report.render_json([_make_result()])
        assert isinstance(data, dict)
        assert "results" in data
        assert "sentinel_version" in data

    def test_json_renderer_findings(self):
        r = _make_result()
        r.add_finding(_make_finding("CFG-004", Severity.HIGH))
        data = sarif_report.render_json([r])
        findings = data["results"][0]["findings"]
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CFG-004"

    def test_sarif_help_uri_format(self):
        r = _make_result()
        r.add_finding(_make_finding(reference="https://checklist.helixar.ai#auth-001"))
        sarif = sarif_report.render_sarif([r])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["helpUri"] == "https://checklist.helixar.ai#auth-001"

    def test_json_renderer_empty(self):
        data = sarif_report.render_json([])
        assert data["results"] == []
