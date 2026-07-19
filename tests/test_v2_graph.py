"""M2-A evidence graph validation tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from authmapper.core.v2 import (
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    EndpointVerdict,
    EvidenceAssociation,
    EvidenceGraph,
    Fact,
    FactKind,
    GraphValidationError,
    Proof,
    ProofKind,
    Relation,
    RelationKind,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
    UnresolvedRecord,
    resolve_endpoints,
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
        relations=(
            Relation(
                "relation:auth",
                RelationKind.REFERENCES,
                "subject:route",
                "subject:auth",
                SPAN,
            ),
        ),
        associations=(
            EvidenceAssociation(
                "association:auth",
                "fact:route",
                "fact:auth",
                "scope:route",
                SPAN,
                ("fact:auth", "fact:route", "relation:auth"),
            ),
        ),
    )


def _guard_graph(
    *,
    enforcement_derived_from: tuple[str, ...] = (),
    additional_facts: tuple[Fact, ...] = (),
    relation_derived_from: tuple[str, ...] = (),
    association_derived_from: tuple[str, ...] | None = None,
    proof_derived_from: tuple[str, ...] | None = None,
) -> EvidenceGraph:
    graph = _valid_graph()
    enforcement = Fact(
        "fact:auth",
        FactKind.AUTH_ENFORCEMENT,
        "subject:auth",
        SPAN,
        derived_from=enforcement_derived_from,
    )
    relation = replace(graph.relations[0], derived_from=relation_derived_from)
    association = replace(
        graph.associations[0],
        derived_from=(
            graph.associations[0].derived_from
            if association_derived_from is None
            else association_derived_from
        ),
    )
    proof = Proof(
        "proof:auth",
        ProofKind.AUTH_ENFORCEMENT,
        "fact:route",
        (enforcement.id,),
        ("association:auth",),
        ("relation:auth",),
        (
            ("association:auth", enforcement.id, "fact:route", "relation:auth")
            if proof_derived_from is None
            else proof_derived_from
        ),
    )
    capability_provenance = tuple(
        CapabilityProvenance(
            f"provenance:{capability.value}",
            capability,
            "adapter:test",
            "1.0.0",
        )
        for capability in Capability
    )
    coverage = tuple(
        CoverageRecord(
            f"coverage:{capability.value}",
            "fact:route",
            capability,
            CoverageStatus.ANALYZED,
            f"provenance:{capability.value}",
        )
        for capability in Capability
    )
    return EvidenceGraph(
        subjects=graph.subjects,
        facts=tuple(sorted((*additional_facts, enforcement, graph.facts[1]), key=lambda item: item.id)),
        scopes=graph.scopes,
        relations=(relation,),
        associations=(association,),
        proofs=(proof,),
        capability_provenance=tuple(sorted(capability_provenance, key=lambda item: item.id)),
        coverage=tuple(sorted(coverage, key=lambda item: item.id)),
    )


def test_valid_graph_accepts_sorted_referenced_evidence():
    _valid_graph().validate()


def test_graph_accepts_sourced_enforcement_without_fact_derivation():
    _guard_graph().validate()


def test_graph_accepts_enforcement_derived_from_enforcement_and_route_provenance():
    source_enforcement = Fact(
        "fact:auth:source",
        FactKind.AUTH_ENFORCEMENT,
        "subject:auth",
        SPAN,
        derived_from=("fact:route",),
    )
    graph = _guard_graph(
        enforcement_derived_from=(source_enforcement.id,),
        additional_facts=(source_enforcement,),
    )

    graph.validate()


def test_graph_rejects_enforcement_directly_derived_from_weak_indicator():
    weak = Fact("fact:advisory", FactKind.WEAK_INDICATOR, "subject:auth", SPAN)
    graph = _guard_graph(enforcement_derived_from=(weak.id,), additional_facts=(weak,))

    with pytest.raises(GraphValidationError, match="auth enforcement derivation includes advisory fact"):
        graph.validate()


def test_graph_rejects_enforcement_directly_derived_from_auth_ambiguity():
    ambiguity = Fact("fact:advisory", FactKind.AUTH_AMBIGUITY, "subject:auth", SPAN)
    graph = _guard_graph(enforcement_derived_from=(ambiguity.id,), additional_facts=(ambiguity,))
    ambiguity_association = EvidenceAssociation(
        "association:ambiguity",
        "fact:route",
        ambiguity.id,
        "scope:route",
        SPAN,
        (ambiguity.id, "fact:route"),
    )
    graph = EvidenceGraph(
        subjects=graph.subjects,
        facts=graph.facts,
        scopes=graph.scopes,
        relations=graph.relations,
        associations=(ambiguity_association, *graph.associations),
        proofs=graph.proofs,
        unresolved=(
            UnresolvedRecord(
                "unresolved:ambiguity",
                "auth evidence cannot be proven",
                "fact:route",
                SPAN,
                (ambiguity_association.id, ambiguity.id),
            ),
        ),
    )

    with pytest.raises(GraphValidationError, match="auth enforcement derivation includes advisory fact"):
        graph.validate()


@pytest.mark.parametrize("kind", [FactKind.IDENTITY_USE, FactKind.SESSION_PRESENCE])
def test_graph_rejects_enforcement_directly_derived_from_identity_or_session(kind: FactKind):
    advisory = Fact("fact:advisory", kind, "subject:auth", SPAN)
    graph = _guard_graph(enforcement_derived_from=(advisory.id,), additional_facts=(advisory,))

    with pytest.raises(GraphValidationError, match="auth enforcement derivation includes advisory fact"):
        graph.validate()


def test_graph_rejects_transitively_advisory_enforcement_derivation():
    weak = Fact("fact:advisory", FactKind.WEAK_INDICATOR, "subject:auth", SPAN)
    derived_enforcement = Fact(
        "fact:auth:derived",
        FactKind.AUTH_ENFORCEMENT,
        "subject:auth",
        SPAN,
        derived_from=(weak.id,),
    )
    graph = _guard_graph(
        enforcement_derived_from=(derived_enforcement.id,),
        additional_facts=(weak, derived_enforcement),
    )

    with pytest.raises(GraphValidationError, match="auth enforcement derivation includes advisory fact"):
        graph.validate()


@pytest.mark.parametrize(
    "advisory_kind",
    (
        FactKind.AUTH_AMBIGUITY,
        FactKind.IDENTITY_USE,
        FactKind.SESSION_PRESENCE,
        FactKind.WEAK_INDICATOR,
    ),
)
@pytest.mark.parametrize("selected_entity", ("relation", "association", "proof"))
@pytest.mark.parametrize("transitive", (False, True), ids=("direct", "transitive"))
def test_graph_rejects_advisory_derivation_from_selected_entity(
    advisory_kind: FactKind,
    selected_entity: str,
    transitive: bool,
):
    advisory = Fact("fact:advisory", advisory_kind, "subject:auth", SPAN)
    intermediate = Fact(
        "fact:derivation",
        FactKind.ROUTING_PREDICATE,
        "subject:auth",
        SPAN,
        derived_from=(advisory.id,),
    )
    tainted_derivation = (intermediate.id,) if transitive else (advisory.id,)
    association_derivation = tuple(sorted(("fact:auth", "fact:route", "relation:auth", *tainted_derivation)))
    proof_derivation = tuple(
        sorted(("association:auth", "fact:auth", "fact:route", "relation:auth", *tainted_derivation))
    )
    ambiguity_association = EvidenceAssociation(
        "association:ambiguity",
        "fact:route",
        advisory.id,
        "scope:route",
        SPAN,
        (advisory.id, "fact:route"),
    )
    unresolved = UnresolvedRecord(
        "unresolved:ambiguity",
        "auth evidence cannot be proven",
        "fact:route",
        SPAN,
        (ambiguity_association.id, advisory.id),
    )
    graph = _guard_graph(
        additional_facts=(advisory, intermediate) if transitive else (advisory,),
        relation_derived_from=tainted_derivation if selected_entity == "relation" else (),
        association_derived_from=(
            association_derivation if selected_entity == "association" else None
        ),
        proof_derived_from=proof_derivation if selected_entity == "proof" else None,
    )
    if advisory_kind is FactKind.AUTH_AMBIGUITY:
        graph = replace(
            graph,
            associations=tuple(sorted((*graph.associations, ambiguity_association), key=lambda item: item.id)),
            unresolved=(unresolved,),
        )

    with pytest.raises(GraphValidationError, match="auth enforcement derivation includes advisory fact"):
        graph.validate()


def test_unrelated_advisory_fact_does_not_taint_valid_enforcement_proof():
    advisory = Fact("fact:advisory", FactKind.WEAK_INDICATOR, "subject:auth", SPAN)
    graph = _guard_graph(additional_facts=(advisory,))

    graph.validate()
    assert resolve_endpoints(graph)[0].verdict is EndpointVerdict.GUARDED


def test_graph_rejects_proof_association_with_wrong_route_scope():
    graph = _valid_graph()
    wrong_subject = Subject("subject:wrong-route", SubjectKind.ROUTE_CALL, SPAN)
    wrong_scope = Scope("scope:wrong-route", ScopeKind.ROUTE, wrong_subject.id, SPAN)
    association = EvidenceAssociation(
        "association:auth",
        "fact:route",
        "fact:auth",
        wrong_scope.id,
        SPAN,
        ("fact:auth", "fact:route", "relation:auth"),
    )

    with pytest.raises(GraphValidationError, match="scope must belong to endpoint"):
        EvidenceGraph(
            subjects=tuple(sorted((*graph.subjects, wrong_subject), key=lambda item: item.id)),
            facts=graph.facts,
            scopes=(wrong_scope,),
            relations=graph.relations,
            associations=(association,),
        ).validate()


def test_graph_rejects_proof_association_with_weak_only_derivation():
    graph = _valid_graph()
    association = graph.associations[0]

    with pytest.raises(
        GraphValidationError,
        match="association derivation must include endpoint, evidence, and relation",
    ):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            associations=(
                EvidenceAssociation(
                    association.id,
                    association.endpoint_id,
                    association.evidence_fact_id,
                    association.scope_id,
                    association.span,
                    ("fact:auth", "fact:route"),
                ),
            ),
        ).validate()


def test_graph_rejects_proof_relation_that_does_not_connect_evidence():
    graph = _valid_graph()
    unrelated = Subject("subject:unrelated", SubjectKind.POLICY, SPAN)
    relation = Relation(
        "relation:unrelated",
        RelationKind.REFERENCES,
        "subject:route",
        unrelated.id,
        SPAN,
    )
    association = EvidenceAssociation(
        "association:auth",
        "fact:route",
        "fact:auth",
        "scope:route",
        SPAN,
        ("fact:auth", "fact:route", relation.id),
    )

    with pytest.raises(GraphValidationError, match="relation path must connect endpoint scope to evidence"):
        EvidenceGraph(
            subjects=tuple(sorted((*graph.subjects, unrelated), key=lambda item: item.id)),
            facts=graph.facts,
            scopes=graph.scopes,
            relations=(relation,),
            associations=(association,),
        ).validate()


def test_graph_rejects_proof_with_incomplete_derivation():
    graph = _valid_graph()

    with pytest.raises(GraphValidationError, match="proof derivation must include selected evidence path"):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            relations=graph.relations,
            associations=graph.associations,
            proofs=(
                Proof(
                    "proof:auth",
                    ProofKind.AUTH_ENFORCEMENT,
                    "fact:route",
                    ("fact:auth",),
                    ("association:auth",),
                    ("relation:auth",),
                    ("association:auth", "fact:auth", "relation:auth"),
                ),
            ),
        ).validate()


def test_graph_rejects_enforcement_proof_selected_unrelated_association_relation():
    graph = _valid_graph()
    unrelated = Subject("subject:unrelated", SubjectKind.POLICY, SPAN)
    unrelated_relation = Relation(
        "relation:unrelated",
        RelationKind.REFERENCES,
        "subject:route",
        unrelated.id,
        SPAN,
    )
    association = EvidenceAssociation(
        "association:auth",
        "fact:route",
        "fact:auth",
        "scope:route",
        SPAN,
        ("fact:auth", "fact:route", "relation:auth", unrelated_relation.id),
    )
    proof = Proof(
        "proof:auth",
        ProofKind.AUTH_ENFORCEMENT,
        "fact:route",
        ("fact:auth",),
        (association.id,),
        (unrelated_relation.id,),
        (association.id, "fact:auth", "fact:route", unrelated_relation.id),
    )

    with pytest.raises(GraphValidationError, match="selected relation path must connect endpoint scope to evidence"):
        EvidenceGraph(
            subjects=tuple(sorted((*graph.subjects, unrelated), key=lambda item: item.id)),
            facts=graph.facts,
            scopes=graph.scopes,
            relations=tuple(sorted((*graph.relations, unrelated_relation), key=lambda item: item.id)),
            associations=(association,),
            proofs=(proof,),
        ).validate()


def test_graph_accepts_enforcement_proof_selected_valid_association_relation_path():
    graph = _valid_graph()
    unrelated = Subject("subject:unrelated", SubjectKind.POLICY, SPAN)
    unrelated_relation = Relation(
        "relation:unrelated",
        RelationKind.REFERENCES,
        "subject:route",
        unrelated.id,
        SPAN,
    )
    association = EvidenceAssociation(
        "association:auth",
        "fact:route",
        "fact:auth",
        "scope:route",
        SPAN,
        ("fact:auth", "fact:route", "relation:auth", unrelated_relation.id),
    )
    proof = Proof(
        "proof:auth",
        ProofKind.AUTH_ENFORCEMENT,
        "fact:route",
        ("fact:auth",),
        (association.id,),
        ("relation:auth",),
        (association.id, "fact:auth", "fact:route", "relation:auth"),
    )

    EvidenceGraph(
        subjects=tuple(sorted((*graph.subjects, unrelated), key=lambda item: item.id)),
        facts=graph.facts,
        scopes=graph.scopes,
        relations=tuple(sorted((*graph.relations, unrelated_relation), key=lambda item: item.id)),
        associations=(association,),
        proofs=(proof,),
    ).validate()


def test_graph_rejects_enforcement_proof_relation_outside_association_provenance():
    graph = _valid_graph()
    association = EvidenceAssociation(
        "association:auth",
        "fact:route",
        "fact:auth",
        "scope:route",
        SPAN,
        ("fact:auth", "fact:route", "relation:alternate"),
    )
    alternate_relation = Relation(
        "relation:alternate",
        RelationKind.REFERENCES,
        "subject:route",
        "subject:auth",
        SPAN,
    )
    proof = Proof(
        "proof:auth",
        ProofKind.AUTH_ENFORCEMENT,
        "fact:route",
        ("fact:auth",),
        (association.id,),
        ("relation:auth",),
        (association.id, "fact:auth", "fact:route", "relation:auth"),
    )

    with pytest.raises(GraphValidationError, match="relations must be in association provenance"):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
            relations=(alternate_relation, *graph.relations),
            associations=(association,),
            proofs=(proof,),
        ).validate()


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
        relations=graph.relations,
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
    graph = _ambiguity_graph()
    endpoint = next(item for item in graph.facts if item.id == graph.associations[0].endpoint_id)
    scope = next(item for item in graph.scopes if item.id == graph.associations[0].scope_id)

    assert scope.subject_id == endpoint.subject_id
    graph.validate()


def test_graph_rejects_auth_ambiguity_association_using_another_endpoint_scope():
    graph = _ambiguity_graph()
    other_subject = Subject("subject:route:other", SubjectKind.ROUTE_CALL, SPAN)
    other_endpoint = Fact(
        "fact:route:other",
        FactKind.ENDPOINT_DECLARATION,
        other_subject.id,
        SPAN,
        method="GET",
        path="/other",
    )
    other_scope = Scope("scope:route:other", ScopeKind.ROUTE, other_subject.id, SPAN)
    association = EvidenceAssociation(
        "association:ambiguity",
        "fact:route",
        "fact:ambiguity",
        other_scope.id,
        SPAN,
        ("fact:ambiguity", "fact:route"),
    )

    with pytest.raises(GraphValidationError, match="ambiguity scope must belong to endpoint"):
        EvidenceGraph(
            subjects=tuple(sorted((*graph.subjects, other_subject), key=lambda item: item.id)),
            facts=tuple(sorted((*graph.facts, other_endpoint), key=lambda item: item.id)),
            scopes=tuple(sorted((*graph.scopes, other_scope), key=lambda item: item.id)),
            associations=(association,),
            unresolved=graph.unresolved,
            capability_provenance=graph.capability_provenance,
            coverage=graph.coverage,
        ).validate()


def test_graph_rejects_orphan_auth_ambiguity_fact():
    graph = _ambiguity_graph()

    with pytest.raises(GraphValidationError, match="ambiguity fact needs endpoint association"):
        EvidenceGraph(
            subjects=graph.subjects,
            facts=graph.facts,
            scopes=graph.scopes,
        ).validate()


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
