"""M2-D stable adapter explainability view tests."""

from __future__ import annotations

import json

import pytest

from authmapper.core.v2 import (
    ActivationEvidence,
    AdapterExplanation,
    ApplicabilityResult,
    ApplicabilityState,
    CapabilityExplanation,
    CapabilityMaturity,
    Diagnostic,
    DiagnosticLevel,
    OwnershipDecision,
    OwnershipState,
    render_adapter_explanation,
)


def _explanation() -> AdapterExplanation:
    return AdapterExplanation(
        "adapter:synthetic",
        "1.0.0",
        ApplicabilityResult(
            "adapter:synthetic",
            ApplicabilityState.AMBIGUOUS,
            (ActivationEvidence("activation:import", "import", "synthetic"),),
            ("dependency identity is unresolved",),
        ),
        (
            OwnershipDecision(
                "subject:route",
                "call-router",
                "adapter:synthetic",
                OwnershipState.AMBIGUOUS,
                ("activation:import",),
                "another adapter claims the same symbol",
            ),
        ),
        (
            CapabilityExplanation("auth_association", CapabilityMaturity.UNAVAILABLE),
            CapabilityExplanation("endpoint_discovery", CapabilityMaturity.EXPERIMENTAL),
        ),
        ("rule.auth.synthetic",),
        (
            Diagnostic(
                "diagnostic:ownership",
                "AM-OWNERSHIP-AMBIGUOUS",
                "adapter ownership is ambiguous",
                DiagnosticLevel.WARNING,
            ),
        ),
    )


def test_internal_explain_view_is_deterministic_and_complete():
    first = render_adapter_explanation(_explanation())
    second = render_adapter_explanation(_explanation())
    document = json.loads(first)

    assert first == second
    assert document["view_version"] == "1.0"
    assert document["applicability"]["evidence"][0]["kind"] == "import"
    assert document["ownership_decisions"][0]["state"] == "ambiguous"
    assert document["capabilities"][1]["maturity"] == "experimental"
    assert document["applied_rule_ids"] == ["rule.auth.synthetic"]
    assert document["diagnostics"][0]["code"] == "AM-OWNERSHIP-AMBIGUOUS"


def test_explain_view_rejects_wrong_adapter_and_unstable_order():
    explanation = _explanation()
    with pytest.raises(ValueError, match="match applicability"):
        AdapterExplanation(
            "adapter:other",
            explanation.adapter_version,
            explanation.applicability,
            explanation.ownership_decisions,
            explanation.capabilities,
            explanation.applied_rule_ids,
            explanation.diagnostics,
        )
    with pytest.raises(ValueError, match="capabilities"):
        AdapterExplanation(
            explanation.adapter_id,
            explanation.adapter_version,
            explanation.applicability,
            explanation.ownership_decisions,
            tuple(reversed(explanation.capabilities)),
            explanation.applied_rule_ids,
            explanation.diagnostics,
        )
