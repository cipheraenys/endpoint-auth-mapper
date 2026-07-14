"""SARIF 2.1.0 reporter.

SARIF (Static Analysis Results Interchange Format) is the standard consumed by
GitHub code scanning, Azure DevOps, and many IDEs. Emitting it lets the tool
plug into existing security dashboards with no glue code.

Actionable findings (EXPOSED / UNKNOWN) are always emitted.  Suppressed
findings of these states are also emitted — with a SARIF ``suppressions``
array — so that auditors can verify suppression justifications.
PROTECTED/PUBLIC endpoints are informational and omitted.
"""

from __future__ import annotations

import json

from authmapper import __version__

from ..core.model import AuthState, CoverageStatus, Finding, ScanResult, Severity, SourceCoverage

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
        for f in result.sorted_findings(include_suppressed=True)
        if f.auth_state in _REPORTABLE
    ]
    results.extend(_coverage_result(record) for record in result.incomplete_coverage())

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "endpoint-auth-mapper",
                        "informationUri": "https://github.com/cipheraenys/endpoint-auth-mapper",
                        "version": __version__,
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
            "helpUri": "https://github.com/cipheraenys/endpoint-auth-mapper/blob/main/docs/reference/output-states.md",
        },
        {
            "id": "unknown-endpoint",
            "name": "UnknownEndpointAuth",
            "shortDescription": {"text": "Endpoint authentication could not be resolved."},
            "helpUri": "https://github.com/cipheraenys/endpoint-auth-mapper/blob/main/docs/reference/output-states.md",
        },
        {
            "id": "source-coverage",
            "name": "IncompleteSourceCoverage",
            "shortDescription": {"text": "Eligible source was not fully analyzed."},
            "helpUri": "https://github.com/cipheraenys/endpoint-auth-mapper/blob/main/docs/reference/configuration.md#source-coverage",
        },
    ]


def _result(finding: Finding) -> dict:
    rule_id = "exposed-endpoint" if finding.auth_state is AuthState.EXPOSED else "unknown-endpoint"
    ep = finding.endpoint
    message = f"{finding.auth_state}: {ep.method} {ep.route} — {finding.rationale}"
    result: dict = {
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
    if finding.suppressed:
        result["suppressions"] = [
            {
                "kind": "inSource",
                "justification": finding.suppression_reason or "unspecified",
            }
        ]
    return result


def _coverage_result(record: SourceCoverage) -> dict:
    return {
        "ruleId": "source-coverage",
        "level": "error" if record.status is CoverageStatus.ERROR else "warning",
        "message": {"text": f"{record.status}: {record.reason}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": record.file},
                }
            }
        ],
        "properties": {
            "coverageStatus": str(record.status),
            "rulepacks": list(record.rulepacks),
        },
    }
