from __future__ import annotations

from unittest.mock import MagicMock, patch

from sentinel.modules.probe import ProbeScanner


def _resp(status=200, headers=None, text="ok"):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    return r


def _url_mock(*routes):
    def dispatch(url, **kwargs):
        for substr, resp in routes:
            if substr in url:
                return resp
        return _resp()

    return dispatch


_SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


class TestNoAuthCheck:
    def test_200_triggers_prb003(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(200)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-003" for f in result.findings)

    def test_401_suppresses_prb003(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-003" for f in result.findings)

    def test_403_suppresses_prb003(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(403)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-003" for f in result.findings)

    def test_finding_includes_status_code_in_detail(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(200)):
            result = scanner.scan("http://example.com")
        finding = next(f for f in result.findings if f.rule_id == "PRB-003")
        assert "200" in finding.detail


class TestInfoDisclosureHeaders:
    def test_server_header_with_version_triggers_prb004(self):
        scanner = ProbeScanner()
        headers = {"server": "Apache/2.4.41 (Ubuntu)", **_SECURE_HEADERS}
        with patch("requests.get", return_value=_resp(401, headers=headers)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-004" for f in result.findings)

    def test_x_powered_by_with_version_triggers_prb004(self):
        scanner = ProbeScanner()
        headers = {"x-powered-by": "PHP/8.1.0", **_SECURE_HEADERS}
        with patch("requests.get", return_value=_resp(401, headers=headers)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-004" for f in result.findings)

    def test_server_header_without_version_no_prb004(self):
        scanner = ProbeScanner()
        headers = {"server": "sentinel", **_SECURE_HEADERS}
        with patch("requests.get", return_value=_resp(401, headers=headers)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-004" for f in result.findings)

    def test_no_version_headers_no_prb004(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401, headers=_SECURE_HEADERS)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-004" for f in result.findings)


class TestMissingSecurityHeaders:
    def test_no_security_headers_triggers_prb005(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-005" for f in result.findings)

    def test_all_security_headers_present_suppresses_prb005(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401, headers=_SECURE_HEADERS)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-005" for f in result.findings)

    def test_partial_headers_still_triggers_prb005(self):
        scanner = ProbeScanner()
        partial = {"strict-transport-security": "max-age=31536000"}
        with patch("requests.get", return_value=_resp(401, headers=partial)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-005" for f in result.findings)

    def test_finding_names_missing_headers_in_detail(self):
        scanner = ProbeScanner()
        partial = {"strict-transport-security": "max-age=31536000"}
        with patch("requests.get", return_value=_resp(401, headers=partial)):
            result = scanner.scan("http://example.com")
        finding = next(f for f in result.findings if f.rule_id == "PRB-005")
        assert "x-content-type-options" in finding.detail
        assert "x-frame-options" in finding.detail


class TestToolListingExposed:
    def test_tools_list_200_triggers_prb006(self):
        scanner = ProbeScanner()
        dispatch = _url_mock(
            ("/tools/list", _resp(200)),
            ("example.com", _resp(401, headers=_SECURE_HEADERS)),
        )
        with patch("requests.get", side_effect=dispatch):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-006" for f in result.findings)

    def test_tools_list_401_suppresses_prb006(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401, headers=_SECURE_HEADERS)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-006" for f in result.findings)

    def test_finding_includes_tools_list_url(self):
        scanner = ProbeScanner()
        dispatch = _url_mock(
            ("/tools/list", _resp(200)),
            ("example.com", _resp(401, headers=_SECURE_HEADERS)),
        )
        with patch("requests.get", side_effect=dispatch):
            result = scanner.scan("http://example.com")
        finding = next(f for f in result.findings if f.rule_id == "PRB-006")
        assert "/tools/list" in finding.location


class TestVerboseErrors:
    _TRACEBACK_BODY = "Traceback (most recent call last):\n  File app.py, line 42\nValueError"

    def test_traceback_in_error_response_triggers_prb007(self):
        scanner = ProbeScanner(safe_mode=True)
        dispatch = _url_mock(
            ("nonexistent-sentinel-probe", _resp(500, text=self._TRACEBACK_BODY)),
            ("example.com", _resp(401, headers={**_SECURE_HEADERS, "x-ratelimit-limit": "100"})),
        )
        with patch("requests.get", side_effect=dispatch):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-007" for f in result.findings)

    def test_clean_error_response_suppresses_prb007(self):
        scanner = ProbeScanner(safe_mode=True)
        dispatch = _url_mock(
            ("nonexistent-sentinel-probe", _resp(404, text="Not Found")),
            ("example.com", _resp(401, headers={**_SECURE_HEADERS, "x-ratelimit-limit": "100"})),
        )
        with patch("requests.get", side_effect=dispatch):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-007" for f in result.findings)

    def test_safe_mode_false_skips_check_entirely(self):
        scanner = ProbeScanner(safe_mode=False)
        dispatch = _url_mock(
            ("nonexistent-sentinel-probe", _resp(500, text=self._TRACEBACK_BODY)),
            ("example.com", _resp(401, headers={**_SECURE_HEADERS, "x-ratelimit-limit": "100"})),
        )
        with patch("requests.get", side_effect=dispatch):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-007" for f in result.findings)


class TestRateLimiting:
    def test_no_rate_limit_headers_triggers_prb008(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(401, headers=_SECURE_HEADERS)):
            result = scanner.scan("http://example.com")
        assert any(f.rule_id == "PRB-008" for f in result.findings)

    def test_x_ratelimit_limit_header_suppresses_prb008(self):
        scanner = ProbeScanner()
        headers = {**_SECURE_HEADERS, "x-ratelimit-limit": "100"}
        with patch("requests.get", return_value=_resp(401, headers=headers)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-008" for f in result.findings)

    def test_retry_after_header_suppresses_prb008(self):
        scanner = ProbeScanner()
        headers = {**_SECURE_HEADERS, "retry-after": "60"}
        with patch("requests.get", return_value=_resp(401, headers=headers)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-008" for f in result.findings)

    def test_429_response_suppresses_prb008(self):
        scanner = ProbeScanner()
        with patch("requests.get", return_value=_resp(429, headers=_SECURE_HEADERS)):
            result = scanner.scan("http://example.com")
        assert not any(f.rule_id == "PRB-008" for f in result.findings)


class TestEndpointUnreachable:
    def test_connection_error_returns_info_finding(self):
        import requests as _req

        scanner = ProbeScanner()
        with patch("requests.get", side_effect=_req.exceptions.ConnectionError("refused")):
            result = scanner.scan("http://unreachable.example.com")
        assert result.has_findings
        assert any(f.rule_id == "PRB-ERR" for f in result.findings)

    def test_timeout_error_returns_info_finding(self):
        import requests as _req

        scanner = ProbeScanner()
        with patch("requests.get", side_effect=_req.exceptions.Timeout("timed out")):
            result = scanner.scan("http://slow.example.com")
        assert any(f.rule_id == "PRB-ERR" for f in result.findings)

    def test_result_module_is_probe(self):
        import requests as _req

        scanner = ProbeScanner()
        with patch("requests.get", side_effect=_req.exceptions.ConnectionError("refused")):
            result = scanner.scan("http://unreachable.example.com")
        assert result.module == "probe"
