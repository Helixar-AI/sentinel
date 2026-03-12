"""SARIF 2.1 and plain JSON output renderers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from sentinel.core import ScanResult

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

SENTINEL_VERSION = "0.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def render_sarif(results: List[ScanResult]) -> Dict[str, Any]:
    """Return a SARIF 2.1 document as a Python dict."""
    rules_seen: Dict[str, dict] = {}
    run_results: List[dict] = []

    for result in results:
        for f in result.findings:
            if f.rule_id not in rules_seen:
                help_uri = f.reference or f"https://checklist.helixar.ai#{f.rule_id.lower()}"
                rules_seen[f.rule_id] = {
                    "id": f.rule_id,
                    "name": _to_camel(f.title),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.detail},
                    "helpUri": help_uri,
                    "properties": {
                        "tags": ["security", "mcp"],
                        "severity": f.severity.value,
                    },
                }
            level = _SARIF_LEVEL.get(f.severity.value, "warning")
            run_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": level,
                    "message": {"text": f.detail},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.location},
                            }
                        }
                    ],
                    "fixes": [
                        {
                            "description": {"text": f.remediation},
                        }
                    ]
                    if f.remediation
                    else [],
                }
            )

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel",
                        "version": SENTINEL_VERSION,
                        "informationUri": "https://github.com/Helixar-AI/sentinel",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": run_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return sarif


def render_sarif_string(results: List[ScanResult], indent: int = 2) -> str:
    """Return a SARIF document as a JSON string."""
    return json.dumps(render_sarif(results), indent=indent)


def render_json(results: List[ScanResult]) -> Dict[str, Any]:
    """Return a plain JSON-serialisable dict of results."""
    output = {
        "sentinel_version": SENTINEL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [],
    }
    for result in results:
        output["results"].append(
            {
                "module": result.module,
                "target": result.target,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "title": f.title,
                        "detail": f.detail,
                        "location": f.location,
                        "remediation": f.remediation,
                        "reference": f.reference,
                    }
                    for f in result.findings
                ],
            }
        )
    return output


def render_json_string(results: List[ScanResult], indent: int = 2) -> str:
    """Return plain JSON as a string."""
    return json.dumps(render_json(results), indent=indent)


def _to_camel(title: str) -> str:
    """Convert 'Some title here' to 'SomeTitleHere'."""
    return "".join(word.capitalize() for word in title.split())
