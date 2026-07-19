"""M2-C one-way legacy compatibility contract tests."""

from __future__ import annotations

from authmapper.core.model import (
    AuthState,
    Confidence,
    Endpoint,
    Finding,
    ScanResult,
    Severity,
)
from authmapper.core.v2 import legacy_compatibility_document


def test_legacy_states_are_not_translated_to_v2_verdicts():
    endpoint = Endpoint("GET", "/account", "app.js", 3, "javascript", "express")
    result = ScanResult(
        findings=(
            Finding(endpoint, AuthState.PROTECTED, Confidence.HIGH, Severity.INFO, evidence=("legacy signal",)),
            Finding(endpoint, AuthState.EXPOSED, Confidence.HIGH, Severity.HIGH),
        ),
        coverage=(),
        errors=(),
        files_scanned=1,
        files_skipped=0,
        rulepacks_used=("node-express",),
        duration_seconds=0.001,
    )

    document = legacy_compatibility_document(result)

    assert document["classification"] == "legacy_unverified"
    assert document["migration"] == "one-way"
    assert document["target_contract"] == "evidence-report-2.1"
    assert [item["legacy_state"] for item in document["items"]] == ["PROTECTED", "EXPOSED"]
    assert all(item["v2_verdict"] is None for item in document["items"])
    assert all("no v2 evidence proof" in item["reason"] for item in document["items"])
