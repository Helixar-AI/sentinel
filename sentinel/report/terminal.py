"""Terminal output renderer — Rich if available, plain fallback."""

from __future__ import annotations

from typing import List

from sentinel.core import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[ MED]",
    Severity.LOW: "[ LOW]",
    Severity.INFO: "[INFO]",
}


def render(results: List[ScanResult], use_rich: bool = True) -> None:
    """Render scan results to the terminal."""
    if use_rich:
        try:
            _render_rich(results)
            return
        except ImportError:
            pass
    _render_plain(results)


def render_to_string(results: List[ScanResult]) -> str:
    """Return a plain-text representation of results."""
    lines: List[str] = []
    total_findings = sum(len(r.findings) for r in results)

    lines.append("=" * 60)
    lines.append("  sentinel — MCP Security Scanner")
    lines.append("=" * 60)

    for result in results:
        lines.append(f"\nModule : {result.module}")
        lines.append(f"Target : {result.target}")
        lines.append(f"Findings: {len(result.findings)}")
        lines.append("-" * 40)

        if not result.findings:
            lines.append("  No findings.")
        else:
            for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
                icon = _SEVERITY_ICONS.get(f.severity, "[????]")
                lines.append(f"  {icon}  {f.rule_id}  {f.title}")
                lines.append(f"         {f.detail}")
                lines.append(f"         Location: {f.location}")
                if f.remediation:
                    lines.append(f"         Fix: {f.remediation[:100]}")
                lines.append("")

    counts: dict = {s: 0 for s in Severity}
    for result in results:
        for finding in result.findings:
            counts[finding.severity] += 1

    lines.append("=" * 60)
    lines.append(f"  Total findings: {total_findings}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev]:
            lines.append(f"    {sev.value:8s}: {counts[sev]}")
    lines.append("")
    lines.append("  sentinel by Helixar · Runtime protection: helixar.ai")
    lines.append("=" * 60)

    return "\n".join(lines)


def _render_plain(results: List[ScanResult]) -> None:
    print(render_to_string(results))


def _render_rich(results: List[ScanResult]) -> None:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    console = Console()
    total_findings = sum(len(r.findings) for r in results)

    console.print()
    console.print("[bold]sentinel[/bold] — MCP Security Scanner", style="bold white on blue")
    console.print()

    for result in results:
        console.print(f"[bold]Module:[/bold] {result.module}  [bold]Target:[/bold] {result.target}")

        if not result.findings:
            console.print("  [green]No findings.[/green]")
            console.print()
            continue

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=10)
        table.add_column("Title")
        table.add_column("Location")

        for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
            color = _SEVERITY_COLORS.get(f.severity, "white")
            table.add_row(
                Text(f.severity.value, style=color),
                f.rule_id,
                f.title,
                f.location[:60],
            )

        console.print(table)

    # Summary
    counts: dict = {s: 0 for s in Severity}
    for result in results:
        for finding in result.findings:
            counts[finding.severity] += 1

    summary = f"Total: {total_findings} findings"
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if counts[sev]:
            color = _SEVERITY_COLORS[sev]
            summary += f"  [{color}]{sev.value}: {counts[sev]}[/{color}]"

    console.print(summary)
    console.print()
    console.print("[dim]sentinel by Helixar · Runtime protection: helixar.ai[/dim]")
    console.print()
