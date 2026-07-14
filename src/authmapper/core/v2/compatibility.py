"""One-way legacy report compatibility artifacts without verdict translation."""

from __future__ import annotations

from typing import Any

from ..model import ScanResult

LEGACY_COMPATIBILITY_VERSION = "1.0"


def legacy_compatibility_document(result: ScanResult) -> dict[str, Any]:
    """Label legacy states as unverified observations, never v2 verdicts."""
    return {
        "compatibility_version": LEGACY_COMPATIBILITY_VERSION,
        "source_contract": "legacy-json-1.1",
        "target_contract": "evidence-report-2.0",
        "classification": "legacy_unverified",
        "migration": "one-way",
        "items": [
            {
                "legacy_state": finding.auth_state.value,
                "legacy_severity": finding.severity.value,
                "method": finding.endpoint.method,
                "route": finding.endpoint.route,
                "file": finding.endpoint.file,
                "line": finding.endpoint.line,
                "v2_verdict": None,
                "reason": "legacy heuristic finding has no v2 evidence proof",
            }
            for finding in result.findings
        ],
    }
