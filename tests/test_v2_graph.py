"""M2-A evidence graph validation tests."""

from __future__ import annotations

import pytest

from authmapper.core.v2 import (
    EvidenceAssociation,
    EvidenceGraph,
    Fact,
    FactKind,
    GraphValidationError,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
)

SPAN = SourceSpan("app.js", 1, 1, 1, 20)


def _valid_graph() -> EvidenceGraph:
    return EvidenceGraph(
        subjects=(
            Subject("subject:auth", SubjectKind.MIDDLEWARE, SPAN),
            Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN),
        ),
        facts=(
            Fact("fact:auth", FactKind.AUTH_ENFORCEMENT, "subject:auth", SPAN),
            Fact("fact:route", FactKind.ENDPOINT_DECLARATION, "subject:route", SPAN, method="GET", path="/users"),
        ),
        scopes=(Scope("scope:route", ScopeKind.ROUTE, "subject:route", SPAN),),
        associations=(
            EvidenceAssociation(
                "association:auth",
                "fact:route",
                "fact:auth",
                "scope:route",
                SPAN,
                ("fact:auth", "fact:route"),
            ),
        ),
    )


def test_valid_graph_accepts_sorted_referenced_evidence():
    _valid_graph().validate()


def test_graph_rejects_duplicate_and_unstable_ids():
    graph = _valid_graph()
    duplicate = EvidenceGraph(subjects=graph.subjects, facts=(graph.facts[0], graph.facts[0]))
    with pytest.raises(GraphValidationError, match="globally unique"):
        duplicate.validate()

    unstable = EvidenceGraph(subjects=tuple(reversed(graph.subjects)))
    with pytest.raises(GraphValidationError, match="ordered by ID"):
        unstable.validate()


def test_graph_rejects_dangling_references_and_missing_provenance():
    graph = _valid_graph()
    dangling = EvidenceGraph(
        subjects=graph.subjects,
        facts=graph.facts,
        scopes=graph.scopes,
        associations=(
            EvidenceAssociation("association:auth", "fact:missing", "fact:auth", "scope:route", SPAN, ("fact:auth",)),
        ),
    )
    with pytest.raises(GraphValidationError, match="endpoint ID"):
        dangling.validate()

    route_identity = EvidenceGraph(
        subjects=(Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN),),
        facts=(Fact("fact:route", FactKind.ROUTE_IDENTITY, "subject:route", SPAN, path="/api/users"),),
    )
    with pytest.raises(GraphValidationError, match="route identity needs provenance"):
        route_identity.validate()


def test_graph_rejects_derivation_cycles():
    graph = EvidenceGraph(
        subjects=(
            Subject("subject:a", SubjectKind.ROUTE_CALL, SPAN),
            Subject("subject:b", SubjectKind.ROUTE_CALL, SPAN),
        ),
        facts=(
            Fact("fact:a", FactKind.ROUTE_IDENTITY, "subject:a", SPAN, derived_from=("fact:b",), path="/a"),
            Fact("fact:b", FactKind.ROUTE_IDENTITY, "subject:b", SPAN, derived_from=("fact:a",), path="/b"),
        ),
    )

    with pytest.raises(GraphValidationError, match="acyclic"):
        graph.validate()
