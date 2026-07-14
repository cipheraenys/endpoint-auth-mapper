"""SARIF 2.1.0 mapping for v2 evidence reports."""

from __future__ import annotations

import json
from typing import Any

from ..core.v2.contracts import SARIF_MAPPING_VERSION
from ..core.v2.fingerprint import endpoint_fingerprint
from ..core.v2.model import CoverageStatus, EndpointVerdict
from ..core.v2.report import EvidenceReport

_RULES = {
    EndpointVerdict.GUARDED: ("AMV2-0001", "Endpoint has associated authentication enforcement", "note"),
    EndpointVerdict.UNGUARDED: (
        "AMV2-0002",
        "Endpoint has complete analysis and no authentication enforcement",
        "error",
    ),
    EndpointVerdict.DECLARED_PUBLIC: ("AMV2-0003", "Endpoint is explicitly declared public", "note"),
    EndpointVerdict.UNRESOLVED: ("AMV2-0004", "Endpoint authentication posture is unresolved", "warning"),
}
_COVERAGE_RULE_ID = "AMV2-0005"


def render_evidence_sarif(report: EvidenceReport) -> str:
    facts = {fact.id: fact for fact in report.graph.facts}
    results: list[dict[str, Any]] = []
    for resolution in report.resolutions:
        endpoint = facts[resolution.endpoint_id]
        rule_id, message, level = _RULES[resolution.verdict]
        fingerprint = endpoint_fingerprint(endpoint)
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [_location(endpoint.span)],
                "partialFingerprints": {"authmapEndpointFingerprint/v1": fingerprint.value},
                "properties": {
                    "authmap": {
                        "endpointId": endpoint.id,
                        "verdict": resolution.verdict.value,
                        "proofIds": list(resolution.proof_ids),
                        "unresolvedIds": list(resolution.unresolved_ids),
                        "fingerprintAlgorithm": fingerprint.algorithm,
                        "sarifMappingVersion": SARIF_MAPPING_VERSION,
                    }
                },
            }
        )
    for coverage in report.graph.coverage:
        if coverage.status is CoverageStatus.ANALYZED:
            continue
        target = facts.get(coverage.target_id)
        span = target.span if target is not None else None
        result: dict[str, Any] = {
            "ruleId": _COVERAGE_RULE_ID,
            "level": "warning" if coverage.status is not CoverageStatus.ERROR else "error",
            "message": {"text": f"Coverage {coverage.status.value}: {coverage.reason or coverage.capability.value}"},
            "properties": {
                "authmap": {
                    "coverageId": coverage.id,
                    "capability": coverage.capability.value,
                    "status": coverage.status.value,
                    "sarifMappingVersion": SARIF_MAPPING_VERSION,
                }
            },
        }
        if span is not None:
            result["locations"] = [_location(span)]
        results.append(result)

    invocation: dict[str, Any] = {
        "commandLine": " ".join(report.invocation.command_line),
        "workingDirectory": {"uri": report.invocation.working_directory},
        "executionSuccessful": not any(item.status is CoverageStatus.ERROR for item in report.graph.coverage),
        "properties": {"authmap": {"sarifMappingVersion": SARIF_MAPPING_VERSION}},
    }
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "endpoint-auth-mapper",
                "semanticVersion": report.invocation.tool_version,
                "informationUri": "https://github.com/cipheraenys/endpoint-auth-mapper",
                "rules": _rule_metadata(),
            }
        },
        "invocations": [invocation],
        "results": results,
        "properties": {"authmap": {"sarifMappingVersion": SARIF_MAPPING_VERSION}},
    }
    if report.invocation.vcs_uri and report.invocation.vcs_revision:
        run["versionControlProvenance"] = [
            {
                "repositoryUri": report.invocation.vcs_uri,
                "revisionId": report.invocation.vcs_revision,
                "mappedTo": {"uri": report.invocation.working_directory},
            }
        ]
    document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def _location(span: Any) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": span.path},
            "region": {
                "startLine": span.start_line,
                "startColumn": span.start_column,
                "endLine": span.end_line,
                "endColumn": span.end_column,
            },
        }
    }


def _rule_metadata() -> list[dict[str, Any]]:
    rules = [
        {"id": rule_id, "name": verdict.value, "shortDescription": {"text": message}}
        for verdict, (rule_id, message, _) in _RULES.items()
    ]
    rules.append(
        {
            "id": _COVERAGE_RULE_ID,
            "name": "INCOMPLETE_COVERAGE",
            "shortDescription": {"text": "Source or capability coverage is incomplete"},
        }
    )
    return rules
