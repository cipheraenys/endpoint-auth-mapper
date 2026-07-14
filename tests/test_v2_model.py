"""M2-A tests for immutable, framework-neutral domain values."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from authmapper.core.v2 import (
    CoverageStatus,
    EndpointVerdict,
    Fact,
    FactKind,
    SourceSpan,
    Subject,
    SubjectKind,
)


def test_source_span_validates_one_based_ordered_positions():
    with pytest.raises(ValueError, match="one-based"):
        SourceSpan("app.js", 0, 1, 1, 1)
    with pytest.raises(ValueError, match="precede"):
        SourceSpan("app.js", 2, 1, 1, 5)


def test_domain_values_are_immutable_and_have_no_attribute_bags():
    span = SourceSpan("app.js", 1, 1, 1, 10)
    fact = Fact("fact:endpoint", FactKind.ENDPOINT_DECLARATION, "subject:route", span, method="GET", path="/x")

    with pytest.raises(FrozenInstanceError):
        fact.path = "/changed"  # type: ignore[misc]

    assert "attributes" not in {field.name for field in fields(Fact)}
    assert "verdict" not in {field.name for field in fields(Fact)}
    assert "severity" not in {field.name for field in fields(Fact)}


def test_subject_contract_covers_callable_member_and_type_evidence():
    span = SourceSpan("routes.rs", 1, 1, 1, 20)
    kinds = {
        SubjectKind.ROUTE_CALL,
        SubjectKind.OBJECT_PROPERTY,
        SubjectKind.HANDLER,
        SubjectKind.CALLABLE_PARAMETER,
        SubjectKind.TYPE_ANNOTATION,
        SubjectKind.DECORATOR,
        SubjectKind.MIDDLEWARE,
        SubjectKind.POLICY,
        SubjectKind.PUBLIC_DECLARATION,
    }

    subjects = tuple(Subject(f"subject:{kind.value}", kind, span) for kind in kinds)

    assert {subject.kind for subject in subjects} == kinds
    assert set(EndpointVerdict) == {
        EndpointVerdict.GUARDED,
        EndpointVerdict.UNGUARDED,
        EndpointVerdict.DECLARED_PUBLIC,
        EndpointVerdict.UNRESOLVED,
    }
    assert set(CoverageStatus) == {
        CoverageStatus.ANALYZED,
        CoverageStatus.EXCLUDED,
        CoverageStatus.UNSUPPORTED,
        CoverageStatus.SKIPPED,
        CoverageStatus.ERROR,
    }
