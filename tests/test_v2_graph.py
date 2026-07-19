"""M2-A evidence graph validation tests."""

from __future__ import annotations

import pytest

from authmapper.core.v2 import (
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
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
    UnresolvedRecord,
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


def test_graph_rejects_coverage_capability_that_does_not_match_provenance():
    graph = _valid_graph()
    graph = EvidenceGraph(
        subjects=graph.subjects,
        facts=graph.facts,
        scopes=graph.scopes,
        associations=graph.associations,
        capability_provenance=(
            CapabilityProvenance(
                "provenance:auth",
                Capability.AUTH_ASSOCIATION,
                "express",
                "0.1.0",
            ),
        ),
        coverage=(
            CoverageRecord(
                "coverage:route",
                "fact:route",
                Capability.ENDPOINT_DISCOVERY,
                CoverageStatus.ANALYZED,
                "provenance:auth",
            ),
        ),
    )

    with pytest.raises(GraphValidationError, match="must match provenance"):
        graph.validate()


def _ambiguity_graph() -> EvidenceGraph:
    return EvidenceGraph(
        subjects=(
            Subject("subject:ambiguity", SubjectKind.POLICY, SPAN),
            Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN),
        ),
        facts=(
            Fact("fact:ambiguity", FactKind.AUTH_AMBIGUITY, "subject:ambiguity", SPAN),
            Fact("fact:route", FactKind.ENDPOINT_DECLARATION, "subject:route", SPAN, method="GET", path="/users"),
        ),
        scopes=(Scope("scope:route", ScopeKind.ROUTE, "subject:route", SPAN),),
        associations=(
            EvidenceAssociation(
                "association:ambiguity",
                "fact:route",
                "fact:ambiguity",
                "scope:route",
                SPAN,
                ("fact:ambiguity", "fact:route"),
            ),
        ),
        unresolved=(
            UnresolvedRecord(
                "unresolved:ambiguity",
                "auth evidence cannot be proven",
                "fact:route",
                SPAN,
                ("association:ambiguity", "fact:ambiguity"),
            ),
        ),
    )


def test_graph_accepts_endpoint_bound_auth_ambiguity_shape():
    _ambiguity_graph().validate()


def test_graph_rejects_associated_auth_ambiguity_without_matching_unresolved():
    graph = _ambiguity_graph()

    with pytest.raises(GraphValidationError, match="ambiguity association needs endpoint-bound unresolved evidence"):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            associations=graph.associations,
        ).validate()


@pytest.mark.parametrize(
    ("derived_from", "message"),
    [
        (("fact:ambiguity",), "ambiguity unresolved needs matching association"),
        (("association:ambiguity",), "ambiguity unresolved needs matching fact"),
    ],
)
def test_graph_rejects_malformed_auth_ambiguity_derivation(derived_from, message):
    graph = _ambiguity_graph()
    unresolved = UnresolvedRecord(
        "unresolved:ambiguity",
        "auth evidence cannot be proven",
        "fact:route",
        SPAN,
        derived_from,
    )

    with pytest.raises(GraphValidationError, match=message):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            associations=graph.associations,
            unresolved=(unresolved,),
        ).validate()


def test_graph_rejects_auth_ambiguity_bound_to_wrong_endpoint():
    graph = _ambiguity_graph()
    other_subject = Subject("subject:second", SubjectKind.ROUTE_CALL, SPAN)
    other_endpoint = Fact(
        "fact:second",
        FactKind.ENDPOINT_DECLARATION,
        "subject:second",
        SPAN,
        method="GET",
        path="/second",
    )
    unresolved = UnresolvedRecord(
        "unresolved:ambiguity",
        "auth evidence cannot be proven",
        "fact:second",
        SPAN,
        ("association:ambiguity", "fact:ambiguity"),
    )

    with pytest.raises(GraphValidationError, match="ambiguity unresolved must reference association endpoint"):
        EvidenceGraph(
            subjects=tuple(sorted((*graph.subjects, other_subject), key=lambda item: item.id)),
            facts=tuple(sorted((*graph.facts, other_endpoint), key=lambda item: item.id)),
            scopes=graph.scopes,
            associations=graph.associations,
            unresolved=(unresolved,),
        ).validate()


def test_graph_rejects_auth_ambiguity_association_with_malformed_derivation():
    graph = _ambiguity_graph()
    association = EvidenceAssociation(
        "association:ambiguity",
        "fact:route",
        "fact:ambiguity",
        "scope:route",
        SPAN,
        ("fact:ambiguity",),
    )

    with pytest.raises(GraphValidationError, match="ambiguity association derivation"):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            associations=(association,),
            unresolved=graph.unresolved,
        ).validate()
