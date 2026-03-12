"""Static analysis of MCP server configuration files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from sentinel.core import Finding, ScanResult
from sentinel.rules import RuleRegistry

# Patterns that suggest plaintext secrets
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|api[_-]?secret|secret[_-]?key|password|passwd|token|"
    r"private[_-]?key|access[_-]?key|auth[_-]?token|bearer)",
    re.IGNORECASE,
)

_DANGEROUS_PORTS = {22, 23, 2375, 2376, 3306, 5432, 6379, 27017}


def _get_nested(d: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _flatten_keys(d: Any, prefix: str = "") -> dict:
    """Recursively flatten a nested dict to key→value pairs."""
    result = {}
    if not isinstance(d, dict):
        return result
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.update(_flatten_keys(v, full_key))
        else:
            result[full_key] = v
    return result


class ConfigScanner:
    def __init__(self, rules: Optional[RuleRegistry] = None) -> None:
        self.rules = rules or RuleRegistry()

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

    def scan(self, path: Path) -> ScanResult:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        text = path.read_text()
        suffix = path.suffix.lower()
        if suffix in (".yaml", ".yml"):
            config = yaml.safe_load(text) or {}
        elif suffix == ".json":
            config = json.loads(text)
        else:
            # Try JSON first, then YAML
            try:
                config = json.loads(text)
            except json.JSONDecodeError:
                config = yaml.safe_load(text) or {}

        if not isinstance(config, dict):
            config = {}

        result = ScanResult(module="config", target=str(path))

        self._check_no_auth(config, result, path)
        self._check_plaintext_secrets(config, result, path)
        self._check_wildcard_permissions(config, result, path)
        self._check_no_rate_limiting(config, result, path)
        self._check_debug_mode(config, result, path)
        self._check_no_tls(config, result, path)
        self._check_wildcard_cors(config, result, path)
        self._check_no_input_validation(config, result, path)
        self._check_sensitive_logging(config, result, path)
        self._check_no_timeout(config, result, path)

        return result

    # ── Individual checks ─────────────────────────────────────────────────

    def _check_no_auth(self, config: dict, result: ScanResult, path: Path) -> None:
        auth = _get_nested(config, "auth") or _get_nested(config, "authentication")
        if auth is None:
            f = self._make_finding(
                "no_auth",
                str(path),
                "No 'auth' or 'authentication' block found in config.",
            )
            if f:
                result.add_finding(f)

    def _check_plaintext_secrets(self, config: dict, result: ScanResult, path: Path) -> None:
        flat = _flatten_keys(config)
        for key, value in flat.items():
            if _SECRET_PATTERNS.search(key) and isinstance(value, str) and len(value) > 0:
                # Skip obvious placeholder values
                if value.lower() in ("", "null", "none", "false", "true", "env"):
                    continue
                if value.startswith("$") or value.startswith("${"):
                    continue
                f = self._make_finding(
                    "plaintext_secrets",
                    str(path),
                    f"Possible plaintext secret at key '{key}'.",
                )
                if f:
                    result.add_finding(f)
                return  # one finding per scan

    def _check_wildcard_permissions(self, config: dict, result: ScanResult, path: Path) -> None:
        perms = (
            _get_nested(config, "permissions")
            or _get_nested(config, "tools", "permissions")
            or _get_nested(config, "access")
        )
        if perms is None:
            return
        if isinstance(perms, str) and perms in ("*", "all"):
            f = self._make_finding(
                "wildcard_permissions",
                str(path),
                f"Tool permissions set to wildcard value '{perms}'.",
            )
            if f:
                result.add_finding(f)
        elif isinstance(perms, list) and ("*" in perms or "all" in perms):
            f = self._make_finding(
                "wildcard_permissions",
                str(path),
                "Tool permissions list contains wildcard entry.",
            )
            if f:
                result.add_finding(f)

    def _check_no_rate_limiting(self, config: dict, result: ScanResult, path: Path) -> None:
        rl = (
            _get_nested(config, "rate_limit")
            or _get_nested(config, "rate_limiting")
            or _get_nested(config, "ratelimit")
            or _get_nested(config, "throttle")
        )
        if rl is None:
            f = self._make_finding(
                "no_rate_limiting",
                str(path),
                "No rate_limit or throttle block found in config.",
            )
            if f:
                result.add_finding(f)

    def _check_debug_mode(self, config: dict, result: ScanResult, path: Path) -> None:
        debug = _get_nested(config, "debug")
        debug_on = ("true", "1", "yes", "on")
        if debug is True or (isinstance(debug, str) and debug.lower() in debug_on):
            f = self._make_finding(
                "debug_mode_enabled",
                str(path),
                f"'debug' is set to {debug!r} — disable in production.",
            )
            if f:
                result.add_finding(f)

    def _check_no_tls(self, config: dict, result: ScanResult, path: Path) -> None:
        tls = (
            _get_nested(config, "tls")
            or _get_nested(config, "ssl")
            or _get_nested(config, "https")
            or _get_nested(config, "transport", "tls")
        )
        if tls is None:
            f = self._make_finding(
                "no_tls_config",
                str(path),
                "No tls/ssl block found in config. Transport encryption not configured.",
            )
            if f:
                result.add_finding(f)

    def _check_wildcard_cors(self, config: dict, result: ScanResult, path: Path) -> None:
        cors = _get_nested(config, "cors")
        if cors is None:
            return
        origins = None
        if isinstance(cors, dict):
            origins = (
                cors.get("allowed_origins") or cors.get("origins") or cors.get("allow_origins")
            )
        elif isinstance(cors, str):
            origins = cors

        if origins == "*":
            f = self._make_finding(
                "wildcard_cors",
                str(path),
                "CORS allowed_origins is set to '*', permitting all origins.",
            )
            if f:
                result.add_finding(f)
        elif isinstance(origins, list) and "*" in origins:
            f = self._make_finding(
                "wildcard_cors",
                str(path),
                "CORS allowed_origins list contains wildcard '*'.",
            )
            if f:
                result.add_finding(f)

    def _check_no_input_validation(self, config: dict, result: ScanResult, path: Path) -> None:
        iv = (
            _get_nested(config, "input_validation")
            or _get_nested(config, "validation")
            or _get_nested(config, "schema_validation")
        )
        if iv is None:
            f = self._make_finding(
                "no_input_validation",
                str(path),
                "No input_validation block found in config.",
            )
            if f:
                result.add_finding(f)

    def _check_sensitive_logging(self, config: dict, result: ScanResult, path: Path) -> None:
        logging_cfg = _get_nested(config, "logging") or _get_nested(config, "log")
        if logging_cfg is None:
            return
        if isinstance(logging_cfg, dict):
            log_sensitive = logging_cfg.get("log_sensitive") or logging_cfg.get("include_secrets")
            log_body = logging_cfg.get("log_body") or logging_cfg.get("log_request_body")
            log_auth = logging_cfg.get("log_auth") or logging_cfg.get("log_headers")
            for flag_name, flag_val in [
                ("log_sensitive", log_sensitive),
                ("log_body", log_body),
                ("log_auth", log_auth),
            ]:
                flag_on = ("true", "1", "yes")
                if flag_val is True or (isinstance(flag_val, str) and flag_val.lower() in flag_on):
                    f = self._make_finding(
                        "sensitive_logging",
                        str(path),
                        f"Logging config has '{flag_name}' enabled — may expose sensitive data.",
                    )
                    if f:
                        result.add_finding(f)
                    return

    def _check_no_timeout(self, config: dict, result: ScanResult, path: Path) -> None:
        timeout = (
            _get_nested(config, "timeout")
            or _get_nested(config, "timeout_seconds")
            or _get_nested(config, "request_timeout")
        )
        if timeout is None:
            f = self._make_finding(
                "no_timeout",
                str(path),
                "No timeout or timeout_seconds field found in config.",
            )
            if f:
                result.add_finding(f)
