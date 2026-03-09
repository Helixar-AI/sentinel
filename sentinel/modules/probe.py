"""Live MCP endpoint security analysis."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from sentinel.core import Finding, ScanResult
from sentinel.rules import RuleRegistry

_SECURITY_HEADERS = ["strict-transport-security", "x-content-type-options", "x-frame-options"]
_VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
_DANGEROUS_PORTS = {22, 23, 2375, 2376}


class ProbeScanner:
    def __init__(self, rules: Optional[RuleRegistry] = None, safe_mode: bool = True) -> None:
        self.rules = rules or RuleRegistry()
        self.safe_mode = safe_mode

    def _make_finding(self, check_key: str, location: str, detail: str) -> Optional[Finding]:
        rule = self.rules.by_check_key(check_key)
        if rule is None:
            return None
        return Finding(
            rule_id=rule.id,
            severity=rule.severity,
            title=rule.title,
            detail=detail,
            location=location,
            remediation=rule.remediation,
            reference=f"https://checklist.helixar.ai#{rule.reference}" if rule.reference else "",
        )

    def scan(self, endpoint: str, timeout: int = 10) -> ScanResult:
        try:
            import requests
            from requests.exceptions import RequestException
        except ImportError:
            raise RuntimeError("requests is required for probe scanning: pip install requests")

        result = ScanResult(module="probe", target=endpoint)
        parsed = urlparse(endpoint)
        scheme = parsed.scheme.lower()

        # TLS checks
        if scheme == "https":
            self._check_tls_certificate(parsed, result, timeout)
            self._check_tls_version(parsed, result, timeout)
        else:
            # Non-HTTPS endpoint — mark no_tls implicitly via no_auth_endpoint
            pass

        # HTTP-level checks
        try:
            resp = requests.get(endpoint, timeout=timeout, verify=False, allow_redirects=False)
        except RequestException as exc:
            result.add_finding(Finding(
                rule_id="PRB-ERR",
                severity=__import__("sentinel.core", fromlist=["Severity"]).Severity.INFO,
                title="Endpoint unreachable",
                detail=str(exc),
                location=endpoint,
            ))
            return result

        self._check_no_auth(resp, result, endpoint)
        self._check_info_disclosure_headers(resp, result, endpoint)
        self._check_missing_security_headers(resp, result, endpoint)
        self._check_tool_listing_exposed(endpoint, result, timeout)
        self._check_verbose_errors(endpoint, result, timeout)
        self._check_rate_limiting(resp, result, endpoint)

        return result

    # ── Individual checks ─────────────────────────────────────────────────

    def _check_tls_certificate(self, parsed, result: ScanResult, timeout: int) -> None:
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        cert_fmt = "%b %d %H:%M:%S %Y %Z"
                        expiry = datetime.strptime(not_after, cert_fmt).replace(
                            tzinfo=timezone.utc
                        )
                        if expiry < datetime.now(timezone.utc):
                            f = self._make_finding(
                                "tls_cert_invalid", f"{host}:{port}",
                                f"Certificate expired on {not_after}.",
                            )
                            if f:
                                result.add_finding(f)
        except ssl.SSLCertVerificationError as exc:
            f = self._make_finding("tls_cert_invalid", f"{host}:{port}", str(exc))
            if f:
                result.add_finding(f)
        except Exception:
            pass

    def _check_tls_version(self, parsed, result: ScanResult, timeout: int) -> None:
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            min_ver = (
                ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else ssl.TLSVersion.TLSv1
            )
            ctx.minimum_version = min_ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
                        f = self._make_finding(
                            "weak_tls_version", f"{host}:{port}",
                            f"Server negotiated {version} — upgrade to TLS 1.2+.",
                        )
                        if f:
                            result.add_finding(f)
        except Exception:
            pass

    def _check_no_auth(self, resp, result: ScanResult, endpoint: str) -> None:
        if resp.status_code not in (401, 403):
            f = self._make_finding(
                "no_auth_endpoint", endpoint,
                f"Unauthenticated GET returned HTTP {resp.status_code} (expected 401/403).",
            )
            if f:
                result.add_finding(f)

    def _check_info_disclosure_headers(self, resp, result: ScanResult, endpoint: str) -> None:
        for header in _VERSION_HEADERS:
            value = resp.headers.get(header, "")
            if value and any(char.isdigit() for char in value):
                f = self._make_finding(
                    "info_disclosure_headers", endpoint,
                    f"Header '{header}: {value}' discloses version information.",
                )
                if f:
                    result.add_finding(f)
                return

    def _check_missing_security_headers(self, resp, result: ScanResult, endpoint: str) -> None:
        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in _SECURITY_HEADERS if h not in lower_headers]
        if missing:
            f = self._make_finding(
                "missing_security_headers", endpoint,
                f"Missing security headers: {', '.join(missing)}.",
            )
            if f:
                result.add_finding(f)

    def _check_tool_listing_exposed(self, endpoint: str, result: ScanResult, timeout: int) -> None:
        try:
            import requests
            base = endpoint.rstrip("/")
            list_url = f"{base}/tools/list"
            resp = requests.get(list_url, timeout=timeout, verify=False)
            if resp.status_code == 200:
                f = self._make_finding(
                    "tool_listing_exposed", list_url,
                    f"GET {list_url} returned 200 without authentication.",
                )
                if f:
                    result.add_finding(f)
        except Exception:
            pass

    def _check_verbose_errors(self, endpoint: str, result: ScanResult, timeout: int) -> None:
        if not self.safe_mode:
            return
        try:
            import requests
            bad_url = endpoint.rstrip("/") + "/nonexistent-sentinel-probe-12345"
            resp = requests.get(bad_url, timeout=timeout, verify=False)
            body = resp.text.lower()
            verbose_markers = ["traceback", "stack trace", "exception", "at line", "file \""]
            if any(marker in body for marker in verbose_markers):
                f = self._make_finding(
                    "verbose_errors", bad_url,
                    "Error response contains stack trace or verbose debug information.",
                )
                if f:
                    result.add_finding(f)
        except Exception:
            pass

    def _check_rate_limiting(self, resp, result: ScanResult, endpoint: str) -> None:
        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        has_rl = any(
            h in lower_headers
            for h in ["x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit", "retry-after"]
        )
        if not has_rl and resp.status_code != 429:
            f = self._make_finding(
                "no_rate_limiting_probe", endpoint,
                "No rate-limiting headers detected in response (X-RateLimit-Limit, Retry-After).",
            )
            if f:
                result.add_finding(f)
