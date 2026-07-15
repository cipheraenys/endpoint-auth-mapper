"""Deterministic JSON and SARIF views for evidence gate audit."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from typing import Any

from authmapper.app.evidence_gate import EvidenceGateRun
from authmapper.core.v2 import EvidencePolicy, EvidenceReport
from authmapper.core.v2.report import report_document


def gate_audit_document(
    report: EvidenceReport,
    policy: EvidencePolicy,
    run: EvidenceGateRun,
) -> dict[str, Any]:
    """Return one stable JSON view without changing evidence report semantics."""
    return {
        "audit_version": "1.0",
        "policy": {
            "id": policy.id,
            "schema_version": policy.schema_version,
            "requirements": [_value(item) for item in policy.requirements],
        },
        "gate": {
            "exit_class": run.exit_class.value,
            "exit_code": run.exit_class.code,
            "violations": [_value(item) for item in run.gate.violations],
            "advisories": [_value(item) for item in run.gate.advisories],
        },
        "exception_audit": [_value(item) for item in run.exception_audit],
        "evidence_report": report_document(report),
    }


def render_gate_audit_json(report: EvidenceReport, policy: EvidencePolicy, run: EvidenceGateRun) -> str:
    return json.dumps(gate_audit_document(report, policy, run), indent=2, sort_keys=True, ensure_ascii=False)


def apply_gate_audit_to_sarif(
    sarif: dict[str, Any],
    report: EvidenceReport,
    policy: EvidencePolicy,
    run: EvidenceGateRun,
) -> dict[str, Any]:
    """Add policy audit while preserving every original endpoint result."""
    document = json.loads(json.dumps(sarif))
    sarif_run = document["runs"][0]
    sarif_run.setdefault("properties", {})["authmapGate"] = {
        "policyId": policy.id,
        "policySchemaVersion": policy.schema_version,
        "requirements": [_value(item) for item in policy.requirements],
        "exitClass": run.exit_class.value,
        "exitCode": run.exit_class.code,
        "advisories": [_value(item) for item in run.gate.advisories],
        "exceptionAudit": [_value(item) for item in run.exception_audit],
    }
    endpoints = {item.id: item for item in report.graph.facts if item.method and item.path}
    gate_rules = []
    for issue in run.gate.violations:
        rule_id = f"AMGATE-{issue.kind.value.upper()}"
        gate_rules.append(
            {
                "id": rule_id,
                "name": issue.kind.value,
                "shortDescription": {"text": f"Evidence gate {issue.kind.value} violation"},
            }
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": issue.reason},
            "properties": {"authmap": _value(issue)},
        }
        endpoint = endpoints.get(issue.subject_id)
        if endpoint is not None:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": endpoint.span.path},
                        "region": {
                            "startLine": endpoint.span.start_line,
                            "startColumn": endpoint.span.start_column,
                            "endLine": endpoint.span.end_line,
                            "endColumn": endpoint.span.end_column,
                        },
                    }
                }
            ]
        sarif_run["results"].append(result)
    existing_rules = sarif_run["tool"]["driver"]["rules"]
    sarif_run["tool"]["driver"]["rules"] = sorted(
        [*existing_rules, *gate_rules],
        key=lambda item: item["id"],
    )
    sarif_run["results"] = sorted(
        sarif_run["results"],
        key=lambda item: (
            item.get("ruleId", ""),
            item.get("message", {}).get("text", ""),
        ),
    )
    return document


def render_gate_audit_sarif(
    sarif: dict[str, Any],
    report: EvidenceReport,
    policy: EvidencePolicy,
    run: EvidenceGateRun,
) -> str:
    return json.dumps(
        apply_gate_audit_to_sarif(sarif, report, policy, run),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def _value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_value(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {key: _value(item) for key, item in asdict(value).items()}
    return value
