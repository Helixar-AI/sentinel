"""25 tests for ConfigScanner."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from sentinel.core import ScanResult, Severity
from sentinel.modules.config import ConfigScanner
from tests.fixtures.configs import INSECURE_CONFIG, SECURE_CONFIG


def write_json(data: dict) -> Path:
    """Write dict as a JSON file and return its Path."""
    f = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False)
    json.dump(data, f)
    f.flush()
    return Path(f.name)


class TestConfigScannerSetup:
    def test_scanner_initializes(self):
        scanner = ConfigScanner()
        assert scanner is not None
        assert scanner.rules is not None

    def test_scan_nonexistent_file_raises(self):
        scanner = ConfigScanner()
        with pytest.raises(FileNotFoundError):
            scanner.scan(Path("/tmp/does-not-exist-sentinel.json"))

    def test_scan_returns_scan_result(self):
        scanner = ConfigScanner()
        path = write_json(SECURE_CONFIG)
        result = scanner.scan(path)
        assert isinstance(result, ScanResult)
        assert result.module == "config"

    def test_scan_empty_config_has_findings(self):
        scanner = ConfigScanner()
        path = write_json({})
        result = scanner.scan(path)
        # Empty config should trigger several rules
        assert result.has_findings

    def test_findings_have_rule_id(self):
        scanner = ConfigScanner()
        path = write_json(INSECURE_CONFIG)
        result = scanner.scan(path)
        for finding in result.findings:
            assert finding.rule_id.startswith("CFG-")

    def test_findings_have_severity(self):
        scanner = ConfigScanner()
        path = write_json(INSECURE_CONFIG)
        result = scanner.scan(path)
        for finding in result.findings:
            assert isinstance(finding.severity, Severity)


class TestNoAuth:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_no_auth_detected(self):
        path = write_json({})
        result = self.scanner.scan(path)
        assert "CFG-001" in self.ids(result)

    def test_auth_present_clears_cfg001(self):
        path = write_json({"auth": {"scheme": "bearer"}})
        result = self.scanner.scan(path)
        assert "CFG-001" not in self.ids(result)

    def test_authentication_key_accepted(self):
        path = write_json({"authentication": {"scheme": "api_key"}})
        result = self.scanner.scan(path)
        assert "CFG-001" not in self.ids(result)


class TestPlaintextSecrets:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_plaintext_api_key_detected(self):
        path = write_json({"api_key": "sk-realvalue123"})
        result = self.scanner.scan(path)
        assert "CFG-002" in self.ids(result)

    def test_env_var_reference_not_flagged(self):
        path = write_json({"api_key": "${MY_API_KEY}"})
        result = self.scanner.scan(path)
        assert "CFG-002" not in self.ids(result)

    def test_no_secrets_no_cfg002(self):
        path = write_json({"host": "localhost", "port": 8080})
        result = self.scanner.scan(path)
        assert "CFG-002" not in self.ids(result)


class TestWildcardPermissions:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_string_wildcard_detected(self):
        path = write_json({"permissions": "*"})
        result = self.scanner.scan(path)
        assert "CFG-003" in self.ids(result)

    def test_list_wildcard_detected(self):
        path = write_json({"permissions": ["read", "*"]})
        result = self.scanner.scan(path)
        assert "CFG-003" in self.ids(result)

    def test_specific_permissions_no_cfg003(self):
        path = write_json({"permissions": ["read_resource", "call_tool"]})
        result = self.scanner.scan(path)
        assert "CFG-003" not in self.ids(result)


class TestRateLimiting:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_no_rate_limit_detected(self):
        path = write_json({})
        result = self.scanner.scan(path)
        assert "CFG-004" in self.ids(result)

    def test_rate_limit_present_no_cfg004(self):
        path = write_json({"rate_limit": {"requests_per_minute": 60}})
        result = self.scanner.scan(path)
        assert "CFG-004" not in self.ids(result)


class TestDebugMode:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_debug_true_detected(self):
        path = write_json({"debug": True})
        result = self.scanner.scan(path)
        assert "CFG-005" in self.ids(result)

    def test_debug_false_no_cfg005(self):
        path = write_json({"debug": False})
        result = self.scanner.scan(path)
        assert "CFG-005" not in self.ids(result)

    def test_no_debug_key_no_cfg005(self):
        path = write_json({})
        result = self.scanner.scan(path)
        assert "CFG-005" not in self.ids(result)


class TestTLS:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_no_tls_detected(self):
        path = write_json({})
        result = self.scanner.scan(path)
        assert "CFG-006" in self.ids(result)

    def test_tls_configured_no_cfg006(self):
        path = write_json({"tls": {"cert": "/path/to/cert.pem"}})
        result = self.scanner.scan(path)
        assert "CFG-006" not in self.ids(result)


class TestCORS:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_wildcard_cors_detected(self):
        path = write_json({"cors": {"allowed_origins": "*"}})
        result = self.scanner.scan(path)
        assert "CFG-007" in self.ids(result)

    def test_restricted_cors_no_cfg007(self):
        path = write_json({"cors": {"allowed_origins": ["https://app.example.com"]}})
        result = self.scanner.scan(path)
        assert "CFG-007" not in self.ids(result)


class TestTimeout:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def ids(self, result: ScanResult) -> list:
        return [f.rule_id for f in result.findings]

    def test_no_timeout_detected(self):
        path = write_json({})
        result = self.scanner.scan(path)
        assert "CFG-010" in self.ids(result)

    def test_timeout_present_no_cfg010(self):
        path = write_json({"timeout_seconds": 30})
        result = self.scanner.scan(path)
        assert "CFG-010" not in self.ids(result)
