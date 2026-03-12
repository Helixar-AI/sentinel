"""CLI integration tests"""

from __future__ import annotations

import json
import signal as _signal
from pathlib import Path
from unittest.mock import patch

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


class TestWatchCommand:
    """Tests for `sentinel watch`

    As watch runs an infinite loop all tests patch ``signal.signal``
    to capture the SIGINT handler and ``time.sleep`` to fire it after the
    first sleep call, giving exactly one full scan cycle per invocation
    """

    @pytest.fixture
    def _one_cycle(self):
        """Patch signal + sleep so the watch loop executes exactly one cycle."""
        captured = {}

        def _mock_signal(sig, handler):
            if sig == _signal.SIGINT:
                captured["handler"] = handler

        def _mock_sleep(_secs):
            if "handler" in captured:
                captured["handler"](None, None)

        with (
            patch("signal.signal", side_effect=_mock_signal),
            patch("time.sleep", side_effect=_mock_sleep),
        ):
            yield

    @pytest.fixture
    def _two_cycles(self):
        """Patch signal + sleep so the watch loop executes exactly two cycles."""
        captured = {}
        call_count = {"n": 0}

        def _mock_signal(sig, handler):
            if sig == _signal.SIGINT:
                captured["handler"] = handler

        def _mock_sleep(_secs):
            call_count["n"] += 1
            if call_count["n"] >= 2 and "handler" in captured:
                captured["handler"](None, None)

        with (
            patch("signal.signal", side_effect=_mock_signal),
            patch("time.sleep", side_effect=_mock_sleep),
        ):
            yield

    def test_no_targets_exits_2(self, runner):
        result = runner.invoke(cli, ["watch"])
        assert result.exit_code == 2

    def test_no_targets_prints_usage_hint(self, runner):
        result = runner.invoke(cli, ["watch"])
        assert "No targets" in result.output or "No targets" in (result.stderr or "")

    def test_one_cycle_outputs_cycle_header(self, runner, insecure_file, _one_cycle):
        result = runner.invoke(cli, ["watch", "--config", insecure_file, "--interval", "1"])
        assert result.exit_code == 0
        assert "Cycle 1" in result.output

    def test_one_cycle_prints_stop_message(self, runner, insecure_file, _one_cycle):
        result = runner.invoke(cli, ["watch", "--config", insecure_file, "--interval", "1"])
        assert "sentinel watch stopped" in result.output

    def test_one_cycle_contains_findings(self, runner, insecure_file, _one_cycle):
        result = runner.invoke(cli, ["watch", "--config", insecure_file, "--interval", "1"])
        assert "CFG-001" in result.output

    def test_two_cycles_second_shows_no_change(self, runner, insecure_file, _two_cycles):
        result = runner.invoke(cli, ["watch", "--config", insecure_file, "--interval", "1"])
        assert "Cycle 2" in result.output
        assert "no change" in result.output

    def test_two_cycles_second_shows_changed_when_findings_differ(
        self, runner, tmp_path, _two_cycles
    ):
        cfg = tmp_path / "mutable.json"
        cfg.write_text(json.dumps(INSECURE_CONFIG))

        call_count = {"n": 0}
        original_scan = None

        # clean config on the second scan cycle
        from sentinel.modules.config import ConfigScanner

        original_scan = ConfigScanner.scan

        def _patched_scan(self, path):
            call_count["n"] += 1
            if call_count["n"] == 2:
                import json as _json

                from tests.fixtures.configs import SECURE_CONFIG

                path.write_text(_json.dumps(SECURE_CONFIG))
            return original_scan(self, path)

        with patch.object(ConfigScanner, "scan", _patched_scan):
            result = runner.invoke(cli, ["watch", "--config", str(cfg), "--interval", "1"])

        assert "CHANGED" in result.output

    def test_on_change_suppresses_report_when_no_change(self, runner, insecure_file, _two_cycles):
        result = runner.invoke(
            cli,
            ["watch", "--config", insecure_file, "--interval", "1", "--on-change"],
        )
        assert "no change, skipping report" in result.output
        # header should appear once (cycle 1 only — cycle 2 is suppressed)
        assert result.output.count("Cycle 1") == 1
        assert result.output.count("CFG-001") == 1

    def test_on_change_emits_report_on_first_cycle(self, runner, insecure_file, _one_cycle):
        result = runner.invoke(
            cli,
            ["watch", "--config", insecure_file, "--interval", "1", "--on-change"],
        )
        assert "CFG-001" in result.output

    def test_output_file_written_each_cycle(self, runner, insecure_file, tmp_path, _one_cycle):
        out = str(tmp_path / "watch_report.json")
        runner.invoke(
            cli,
            [
                "watch",
                "--config",
                insecure_file,
                "--format",
                "json",
                "--output",
                out,
                "--interval",
                "1",
            ],
        )
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert "results" in data

    def test_json_format_per_cycle(self, runner, insecure_file, tmp_path, _one_cycle):
        out = str(tmp_path / "out.json")
        runner.invoke(
            cli,
            [
                "watch",
                "--config",
                insecure_file,
                "--format",
                "json",
                "--output",
                out,
                "--interval",
                "1",
            ],
        )
        data = json.loads(Path(out).read_text())
        rule_ids = [f["rule_id"] for r in data["results"] for f in r["findings"]]
        assert "CFG-001" in rule_ids


class TestVersionFlag:
    def test_version_flag_exits_0(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_shows_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert "0.1.0" in result.output
