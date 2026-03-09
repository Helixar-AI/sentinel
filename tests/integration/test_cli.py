"""CLI integration tests"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from sentinel.cli import cli
from tests.fixtures.configs import INSECURE_CONFIG

_CLEAN_CONFIG = {
    "auth": {"scheme": "bearer", "validation_mode": "strict"},
    "tls": {"cert": "/etc/ssl/certs/server.crt", "min_version": "TLS1.2"},
    "rate_limit": {"requests_per_minute": 60},
    "debug": False,
    "cors": {"allowed_origins": ["https://app.example.com"]},
    "input_validation": {"enabled": True},
    "logging": {"level": "info", "log_sensitive": False, "log_body": False, "log_auth": False},
    "timeout_seconds": 30,
    "permissions": ["read_resource"],
}
_HIGH_ONLY_CONFIG = {
    "auth": {"scheme": "bearer"},
    "permissions": ["read_resource"],
    "cors": {"allowed_origins": ["https://example.com"]},
    "input_validation": {"enabled": True},
    "timeout_seconds": 30,
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def insecure_file(tmp_path):
    p = tmp_path / "insecure.json"
    p.write_text(json.dumps(INSECURE_CONFIG))
    return str(p)


@pytest.fixture
def clean_file(tmp_path):
    p = tmp_path / "clean.json"
    p.write_text(json.dumps(_CLEAN_CONFIG))
    return str(p)


@pytest.fixture
def high_only_file(tmp_path):
    p = tmp_path / "high_only.json"
    p.write_text(json.dumps(_HIGH_ONLY_CONFIG))
    return str(p)


class TestConfigCommandExitCodes:
    def test_insecure_config_exits_1(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file])
        assert result.exit_code == 1

    def test_clean_config_exits_0(self, runner, clean_file):
        result = runner.invoke(cli, ["config", clean_file])
        assert result.exit_code == 0

    def test_fail_on_critical_passes_when_only_high_findings(self, runner, high_only_file):
        result = runner.invoke(cli, ["config", high_only_file, "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_fail_on_high_fails_on_high_findings(self, runner, high_only_file):
        result = runner.invoke(cli, ["config", high_only_file, "--fail-on", "high"])
        assert result.exit_code == 1

    def test_fail_on_medium_passes_when_no_findings(self, runner, clean_file):
        result = runner.invoke(cli, ["config", clean_file, "--fail-on", "medium"])
        assert result.exit_code == 0

    def test_nonexistent_file_exits_nonzero(self, runner):
        result = runner.invoke(cli, ["config", "/tmp/does-not-exist-sentinel-xyz.json"])
        assert result.exit_code != 0


class TestConfigCommandOutputFormats:
    def test_json_output_is_valid_json(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file, "--format", "json"])
        data = json.loads(result.output)
        assert "results" in data
        assert "sentinel_version" in data

    def test_json_output_contains_expected_findings(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file, "--format", "json"])
        data = json.loads(result.output)
        rule_ids = [f["rule_id"] for r in data["results"] for f in r["findings"]]
        assert "CFG-001" in rule_ids
        assert "CFG-002" in rule_ids

    def test_sarif_output_is_valid(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file, "--format", "sarif"])
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_findings_map_to_error_level(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file, "--format", "sarif"])
        data = json.loads(result.output)
        sarif_results = data["runs"][0]["results"]
        critical_results = [r for r in sarif_results if r.get("ruleId") == "CFG-001"]
        assert critical_results[0]["level"] == "error"

    def test_html_output_is_valid(self, runner, insecure_file):
        result = runner.invoke(cli, ["config", insecure_file, "--format", "html"])
        assert "<!DOCTYPE html>" in result.output
        assert "CFG-001" in result.output

    def test_output_file_is_written(self, runner, insecure_file, tmp_path):
        out = str(tmp_path / "report.json")
        runner.invoke(cli, ["config", insecure_file, "--format", "json", "--output", out])
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert "results" in data

    def test_output_file_does_not_print_content_to_stdout(self, runner, insecure_file, tmp_path):
        out = str(tmp_path / "report.json")
        result = runner.invoke(cli, ["config", insecure_file, "--format", "json", "--output", out])
        assert "Report written to:" in result.output
        assert "sentinel_version" not in result.output


class TestScanCommand:
    def test_no_targets_exits_2(self, runner):
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 2

    def test_no_targets_prints_usage_hint(self, runner):
        result = runner.invoke(cli, ["scan"])
        assert "No targets" in result.output or "No targets" in (result.stderr or "")

    def test_config_only_insecure_exits_1(self, runner, insecure_file):
        result = runner.invoke(cli, ["scan", "--config", insecure_file])
        assert result.exit_code == 1

    def test_config_only_clean_exits_0(self, runner, clean_file):
        result = runner.invoke(cli, ["scan", "--config", clean_file])
        assert result.exit_code == 0

    def test_scan_json_output_includes_module_name(self, runner, insecure_file):
        result = runner.invoke(cli, ["scan", "--config", insecure_file, "--format", "json"])
        data = json.loads(result.output)
        assert len(data["results"]) == 1
        assert data["results"][0]["module"] == "config"

    def test_scan_writes_sarif_file(self, runner, insecure_file, tmp_path):
        out = str(tmp_path / "out.sarif.json")
        runner.invoke(
            cli, ["scan", "--config", insecure_file, "--format", "sarif", "--output", out]
        )
        assert Path(out).exists()
        sarif = json.loads(Path(out).read_text())
        assert sarif["version"] == "2.1.0"

    def test_scan_fail_on_threshold_respected(self, runner, high_only_file):
        result = runner.invoke(cli, ["scan", "--config", high_only_file, "--fail-on", "critical"])
        assert result.exit_code == 0


class TestVersionFlag:
    def test_version_flag_exits_0(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_shows_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert "0.1.0" in result.output
