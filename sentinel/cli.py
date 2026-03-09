"""sentinel CLI — 4 commands: config, probe, container, scan."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from sentinel.core import Severity
from sentinel.modules.config import ConfigScanner
from sentinel.report import html as html_report
from sentinel.report import sarif as sarif_report
from sentinel.report import terminal as terminal_report

_FAIL_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_FMT_CHOICES = click.Choice(["terminal", "json", "sarif", "html"])


def _should_fail(results, fail_on: str) -> bool:
    try:
        threshold = Severity.from_string(fail_on)
    except ValueError:
        threshold = Severity.HIGH
    for result in results:
        for f in result.findings:
            if f.severity >= threshold:
                return True
    return False


def _write_output(results, fmt: str, output: Optional[str]) -> None:
    if fmt == "html":
        content = html_report.render(results)
    elif fmt == "sarif":
        content = sarif_report.render_sarif_string(results)
    elif fmt == "json":
        content = sarif_report.render_json_string(results)
    else:
        content = terminal_report.render_to_string(results)

    if output:
        Path(output).write_text(content)
        click.echo(f"Report written to: {output}")
    elif fmt in ("html", "sarif", "json"):
        click.echo(content)
    else:
        terminal_report.render(results)


@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def cli() -> None:
    """sentinel — MCP security scanner by Helixar."""


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--format", "fmt", default="terminal", type=_FMT_CHOICES)
@click.option("--output", default=None, help="Write report to file instead of stdout.")
@click.option(
    "--fail-on",
    default="high",
    help="Exit 1 if findings >= this severity (critical/high/medium/low/info).",
)
def config(config_path: str, fmt: str, output: Optional[str], fail_on: str) -> None:
    """Scan an MCP server config file for security issues."""
    scanner = ConfigScanner()
    result = scanner.scan(Path(config_path))
    results = [result]

    _write_output(results, fmt, output)

    if _should_fail(results, fail_on):
        sys.exit(1)


@cli.command()
@click.argument("endpoint")
@click.option("--format", "fmt", default="terminal", type=_FMT_CHOICES)
@click.option("--output", default=None)
@click.option("--fail-on", default="high")
@click.option(
    "--safe-mode/--no-safe-mode",
    default=True,
    help="Safe mode: observe only, no mutations.",
)
@click.option("--timeout", default=10, help="Request timeout in seconds.")
def probe(
    endpoint: str,
    fmt: str,
    output: Optional[str],
    fail_on: str,
    safe_mode: bool,
    timeout: int,
) -> None:
    """Probe a live MCP endpoint for security issues."""
    from sentinel.modules.probe import ProbeScanner

    scanner = ProbeScanner(safe_mode=safe_mode)
    result = scanner.scan(endpoint, timeout=timeout)
    results = [result]

    _write_output(results, fmt, output)

    if _should_fail(results, fail_on):
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--format", "fmt", default="terminal", type=_FMT_CHOICES)
@click.option("--output", default=None)
@click.option("--fail-on", default="high")
def container(target: str, fmt: str, output: Optional[str], fail_on: str) -> None:
    """Inspect a Docker container or image for security issues."""
    from sentinel.modules.container import ContainerScanner

    scanner = ContainerScanner()
    result = scanner.scan(target)
    results = [result]

    _write_output(results, fmt, output)

    if _should_fail(results, fail_on):
        sys.exit(1)


@cli.command()
@click.option("--config", "config_path", default=None, type=click.Path())
@click.option("--endpoint", default=None)
@click.option("--container", "container_target", default=None)
@click.option("--format", "fmt", default="terminal", type=_FMT_CHOICES)
@click.option("--output", default=None)
@click.option("--fail-on", default="high")
@click.option("--safe-mode/--no-safe-mode", default=True)
@click.option("--timeout", default=10)
def scan(
    config_path: Optional[str],
    endpoint: Optional[str],
    container_target: Optional[str],
    fmt: str,
    output: Optional[str],
    fail_on: str,
    safe_mode: bool,
    timeout: int,
) -> None:
    """Run all applicable scanners in one pass."""
    results = []

    if config_path:
        scanner = ConfigScanner()
        results.append(scanner.scan(Path(config_path)))

    if endpoint:
        from sentinel.modules.probe import ProbeScanner

        scanner_p = ProbeScanner(safe_mode=safe_mode)
        results.append(scanner_p.scan(endpoint, timeout=timeout))

    if container_target:
        from sentinel.modules.container import ContainerScanner

        scanner_c = ContainerScanner()
        results.append(scanner_c.scan(container_target))

    if not results:
        click.echo("No targets specified. Use --config, --endpoint, or --container.", err=True)
        sys.exit(2)

    _write_output(results, fmt, output)

    if _should_fail(results, fail_on):
        sys.exit(1)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
