"""Docker container and image security inspection."""

from __future__ import annotations

import re
from typing import Optional

from sentinel.core import Finding, ScanResult
from sentinel.rules import RuleRegistry

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|api[_-]?secret|secret[_-]?key|password|passwd|token|"
    r"private[_-]?key|access[_-]?key|auth[_-]?token|bearer|aws_secret)",
    re.IGNORECASE,
)
_DANGEROUS_PORTS = {22, 23, 2375, 2376}


class ContainerScanner:
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

    def scan(self, target: str) -> ScanResult:
        try:
            import docker
        except ImportError:
            raise RuntimeError("docker SDK is required: pip install docker")

        client = docker.from_env()
        result = ScanResult(module="container", target=target)

        # Try as running container first, then as image name
        container_obj = None
        image_obj = None

        try:
            container_obj = client.containers.get(target)
        except Exception:
            pass

        if container_obj is None:
            try:
                image_obj = client.images.get(target)
            except Exception:
                pass

        if container_obj is None and image_obj is None:
            result.add_finding(
                Finding(
                    rule_id="CTR-ERR",
                    severity=__import__("sentinel.core", fromlist=["Severity"]).Severity.INFO,
                    title="Container/image not found",
                    detail=f"Could not find container or image: {target}",
                    location=target,
                )
            )
            return result

        if container_obj is not None:
            self._scan_container(container_obj, result)
        else:
            self._scan_image(image_obj, result, target)

        return result

    def _scan_container(self, container, result: ScanResult) -> None:
        attrs = container.attrs or {}
        host_config = attrs.get("HostConfig", {})
        config = attrs.get("Config", {})
        target = container.name or container.id

        self._check_running_as_root(config, result, target)
        self._check_privileged(host_config, result, target)
        self._check_resource_limits(host_config, result, target)
        self._check_sensitive_env_vars(config, result, target)
        self._check_writable_filesystem(host_config, result, target)
        self._check_health_check(config, result, target)
        self._check_outdated_image(config, attrs, result, target)
        self._check_dangerous_ports(host_config, result, target)

    def _scan_image(self, image, result: ScanResult, target: str) -> None:
        attrs = image.attrs or {}
        config = attrs.get("Config", {})
        self._check_running_as_root(config, result, target)
        self._check_sensitive_env_vars(config, result, target)
        self._check_health_check(config, result, target)
        self._check_dangerous_ports_image(config, result, target)

    # ── Individual checks ─────────────────────────────────────────────────

    def _check_running_as_root(self, config: dict, result: ScanResult, target: str) -> None:
        user = config.get("User", "")
        if user in ("", "0", "root"):
            f = self._make_finding(
                "running_as_root",
                target,
                f"Container User is {user!r} — process runs as UID 0 (root).",
            )
            if f:
                result.add_finding(f)

    def _check_privileged(self, host_config: dict, result: ScanResult, target: str) -> None:
        if host_config.get("Privileged", False):
            f = self._make_finding(
                "privileged_container",
                target,
                "Container is running with --privileged flag.",
            )
            if f:
                result.add_finding(f)

    def _check_resource_limits(self, host_config: dict, result: ScanResult, target: str) -> None:
        memory = host_config.get("Memory", 0)
        nano_cpus = host_config.get("NanoCpus", 0)
        cpu_quota = host_config.get("CpuQuota", 0)
        if not memory and not nano_cpus and not cpu_quota:
            f = self._make_finding(
                "no_resource_limits",
                target,
                "No memory or CPU limits set on container.",
            )
            if f:
                result.add_finding(f)

    def _check_sensitive_env_vars(self, config: dict, result: ScanResult, target: str) -> None:
        env_list = config.get("Env") or []
        for entry in env_list:
            if "=" not in entry:
                continue
            key, _, value = entry.partition("=")
            if _SECRET_KEY_RE.search(key) and value and not value.startswith("$"):
                f = self._make_finding(
                    "sensitive_env_vars",
                    target,
                    f"Environment variable '{key}' appears to contain a plaintext secret.",
                )
                if f:
                    result.add_finding(f)
                return  # one finding per scan

    def _check_writable_filesystem(
        self, host_config: dict, result: ScanResult, target: str
    ) -> None:
        read_only = host_config.get("ReadonlyRootfs", False)
        if not read_only:
            f = self._make_finding(
                "writable_filesystem",
                target,
                "Container root filesystem is writable (ReadonlyRootfs=false).",
            )
            if f:
                result.add_finding(f)

    def _check_health_check(self, config: dict, result: ScanResult, target: str) -> None:
        health = config.get("Healthcheck")
        if health is None:
            f = self._make_finding(
                "no_health_check",
                target,
                "No HEALTHCHECK configured in container/image.",
            )
            if f:
                result.add_finding(f)

    def _check_outdated_image(
        self, config: dict, attrs: dict, result: ScanResult, target: str
    ) -> None:
        # Heuristic: check if image has known old-format metadata suggesting staleness
        created = attrs.get("Created", "")
        # We check via image labels for update advisories — lightweight heuristic
        labels = config.get("Labels") or {}
        if labels.get("org.opencontainers.image.created"):
            pass  # image has OCI metadata, considered maintained
        elif not created:
            f = self._make_finding(
                "outdated_base_image",
                target,
                "Image has no creation timestamp — may be using an outdated or untracked base.",
            )
            if f:
                result.add_finding(f)

    def _check_dangerous_ports(self, host_config: dict, result: ScanResult, target: str) -> None:
        port_bindings = host_config.get("PortBindings") or {}
        for port_proto in port_bindings:
            try:
                port_num = int(port_proto.split("/")[0])
                if port_num in _DANGEROUS_PORTS:
                    f = self._make_finding(
                        "dangerous_ports",
                        target,
                        f"Dangerous port {port_num} is exposed on the container.",
                    )
                    if f:
                        result.add_finding(f)
                    return
            except (ValueError, IndexError):
                continue

    def _check_dangerous_ports_image(self, config: dict, result: ScanResult, target: str) -> None:
        exposed = config.get("ExposedPorts") or {}
        for port_proto in exposed:
            try:
                port_num = int(port_proto.split("/")[0])
                if port_num in _DANGEROUS_PORTS:
                    f = self._make_finding(
                        "dangerous_ports",
                        target,
                        f"Image exposes dangerous port {port_num}.",
                    )
                    if f:
                        result.add_finding(f)
                    return
            except (ValueError, IndexError):
                continue
