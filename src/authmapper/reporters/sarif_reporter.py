"""SARIF 2.1.0 reporter.

SARIF (Static Analysis Results Interchange Format) is the standard consumed by
GitHub code scanning, Azure DevOps, and many IDEs. Emitting it lets the tool
plug into existing security dashboards with no glue code.

Only non-suppressed, actionable findings (EXPOSED / UNKNOWN) are emitted as
results; PROTECTED/PUBLIC endpoints are informational and omitted to keep the
security view focused.
"""

from __future__ import annotations

import json

from ..core.model import AuthState, ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_REPORTABLE = {AuthState.EXPOSED, AuthState.UNKNOWN}


def render_sarif(result: ScanResult) -> str:
    """Render ``result`` as a SARIF 2.1.0 document string."""
    rules = _rules()
    results = [
        _result(f)
        for f in result.sorted_findings()
        if f.auth_state in _REPORTABLE
    ]

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "endpoint-auth-mapper",
                        "informationUri": "https://example.invalid/endpoint-auth-mapper",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)


def _rules() -> list[dict]:
    return [
        {
            "id": "exposed-endpoint",
            "name": "ExposedEndpoint",
            "shortDescription": {"text": "Endpoint has no detected authentication guard."},
            "helpUri": "https://example.invalid/endpoint-auth-mapper/docs/USAGE.md",
        },
        {
            "id": "unknown-endpoint",
            "name": "UnknownEndpointAuth",
            "shortDescription": {"text": "Endpoint authentication could not be resolved."},
            "helpUri": "https://example.invalid/endpoint-auth-mapper/docs/USAGE.md",
        },
    ]


def _result(finding) -> dict:  # noqa: ANN001 - internal helper
    rule_id = "exposed-endpoint" if finding.auth_state is AuthState.EXPOSED else "unknown-endpoint"
    ep = finding.endpoint
    message = f"{finding.auth_state}: {ep.method} {ep.route} — {finding.rationale}"
    return {
        "ruleId": rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": ep.file},
                    "region": {"startLine": max(1, ep.line)},
                }
            }
        ],
        "properties": {
            "confidence": str(finding.confidence),
            "severity": str(finding.severity),
            "language": ep.language,
            "framework": ep.framework,
        },
    }
