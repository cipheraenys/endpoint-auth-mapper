"""M2-B semantic and package contract tests."""

from __future__ import annotations

import pytest

from authmapper.core.v2 import (
    ApplicabilityState,
    CapabilityMaturity,
    PackageLifecycle,
    SemanticKind,
    SemanticRule,
    SubjectKind,
)


def test_semantic_kinds_distinguish_enforcement_from_weak_evidence():
    assert set(SemanticKind) == {
        SemanticKind.AUTH_ENFORCEMENT,
        SemanticKind.PUBLIC_OVERRIDE,
        SemanticKind.IDENTITY_USE,
        SemanticKind.SESSION_PRESENCE,
        SemanticKind.ROUTING_PREDICATE,
        SemanticKind.WEAK_INDICATOR,
    }


def test_semantic_rule_has_typed_sorted_subjects():
    rule = SemanticRule(
        "rule.auth.guard",
        SemanticKind.AUTH_ENFORCEMENT,
        (SubjectKind.CALLABLE_PARAMETER, SubjectKind.TYPE_ANNOTATION),
        "AuthenticatedUser",
    )
    assert rule.subject_kinds == (SubjectKind.CALLABLE_PARAMETER, SubjectKind.TYPE_ANNOTATION)

    with pytest.raises(ValueError, match="unique and ordered"):
        SemanticRule(
            "rule.bad",
            SemanticKind.AUTH_ENFORCEMENT,
            (SubjectKind.TYPE_ANNOTATION, SubjectKind.CALLABLE_PARAMETER),
            "Guard",
        )


def test_lifecycle_maturity_and_applicability_are_separate_axes():
    assert {item.value for item in PackageLifecycle} == {"draft", "active", "deprecated", "retired"}
    assert {item.value for item in CapabilityMaturity} == {"unavailable", "experimental", "verified"}
    assert {item.value for item in ApplicabilityState} == {"active", "inactive", "ambiguous"}
