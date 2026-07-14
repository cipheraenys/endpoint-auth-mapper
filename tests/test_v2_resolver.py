"""M2-A resolver proof-obligation tests."""

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
    Proof,
    ProofKind,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
    UnresolvedRecord,
    resolve_endpoints,
)

SPAN = SourceSpan("app.js", 1, 1, 1, 20)
CAPABILITIES = tuple(Capability)


def _graph(evidence_kind: FactKind | None = None, proof_kind: ProofKind | None = None) -> EvidenceGraph:
    subjects = [Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN)]
    facts = [
        Fact("fact:route", FactKind.ENDPOINT_DECLARATION, "subject:route", SPAN, method="GET", path="/account")
    ]
    associations: tuple[EvidenceAssociation, ...] = ()
    proofs: tuple[Proof, ...] = ()
    if evidence_kind is not None:
        subjects.insert(0, Subject("subject:evidence", SubjectKind.POLICY, SPAN))
        facts.insert(0, Fact("fact:evidence", evidence_kind, "subject:evidence", SPAN))
        associations = (
            EvidenceAssociation(
                "association:evidence",
                "fact:route",
                "fact:evidence",
                "scope:route",
                SPAN,
                ("fact:evidence", "fact:route"),
            ),
        )
    if proof_kind is not None:
        proofs = (
            Proof(
                "proof:result",
                proof_kind,
                "fact:route",
                ("fact:evidence",),
                ("association:evidence",),
                derived_from=("association:evidence", "fact:evidence"),
            ),
        )
    provenance = tuple(
        sorted(
            (
                CapabilityProvenance(f"provenance:{capability.value}", capability, "adapter:test", "1.0.0")
                for capability in CAPABILITIES
            ),
            key=lambda item: item.id,
        )
    )
    coverage = tuple(
        sorted(
            (
                CoverageRecord(
                    f"coverage:{capability.value}",
                    "fact:route",
                    capability,
                    CoverageStatus.ANALYZED,
                    f"provenance:{capability.value}",
                )
                for capability in CAPABILITIES
            ),
            key=lambda item: item.id,
        )
    )
    return EvidenceGraph(
        subjects=tuple(subjects),
        facts=tuple(facts),
        scopes=(Scope("scope:route", ScopeKind.ROUTE, "subject:route", SPAN),),
        associations=associations,
        proofs=proofs,
        capability_provenance=provenance,
        coverage=coverage,
    )


def test_guarded_requires_associated_auth_enforcement_proof():
    graph = _graph(FactKind.AUTH_ENFORCEMENT, ProofKind.AUTH_ENFORCEMENT)

    assert resolve_endpoints(graph)[0].verdict is EndpointVerdict.GUARDED

    weak = _graph(FactKind.WEAK_INDICATOR, ProofKind.AUTH_ENFORCEMENT)
    assert resolve_endpoints(weak)[0].verdict is EndpointVerdict.UNRESOLVED


@pytest.mark.parametrize(
    "fact_kind",
    [FactKind.IDENTITY_USE, FactKind.SESSION_PRESENCE, FactKind.ROUTING_PREDICATE, FactKind.WEAK_INDICATOR],
)
def test_non_enforcement_facts_never_guard_endpoint(fact_kind: FactKind):
    graph = _graph(fact_kind)

    assert resolve_endpoints(graph)[0].verdict is EndpointVerdict.UNGUARDED


def test_unguarded_requires_all_relevant_coverage():
    graph = _graph()
    assert resolve_endpoints(graph)[0].verdict is EndpointVerdict.UNGUARDED

    incomplete = replace(graph, coverage=graph.coverage[:-1])
    resolution = resolve_endpoints(incomplete)[0]
    assert resolution.verdict is EndpointVerdict.UNRESOLVED
    assert resolution.coverage_ids == tuple(item.id for item in incomplete.coverage)

    errored = replace(
        graph,
        coverage=tuple(
            replace(item, status=CoverageStatus.ERROR) if item.capability is Capability.ROUTE_COMPOSITION else item
            for item in graph.coverage
        ),
    )
    assert resolve_endpoints(errored)[0].verdict is EndpointVerdict.UNRESOLVED


def test_public_declaration_requires_resolved_policy_proof():
    declaration_only = _graph(FactKind.PUBLIC_DECLARATION)
    assert resolve_endpoints(declaration_only)[0].verdict is EndpointVerdict.UNRESOLVED

    resolved = _graph(FactKind.PUBLIC_DECLARATION, ProofKind.PUBLIC_POLICY)
    assert resolve_endpoints(resolved)[0].verdict is EndpointVerdict.DECLARED_PUBLIC


def test_explicit_unresolved_evidence_overrides_positive_proof():
    graph = _graph(FactKind.AUTH_ENFORCEMENT, ProofKind.AUTH_ENFORCEMENT)
    graph = replace(
        graph,
        unresolved=(UnresolvedRecord("unresolved:route", "dynamic scope", "fact:route", SPAN, ("fact:route",)),),
    )

    resolution = resolve_endpoints(graph)[0]

    assert resolution.verdict is EndpointVerdict.UNRESOLVED
    assert resolution.proof_ids == ()
    assert resolution.unresolved_ids == ("unresolved:route",)


def test_coverage_is_not_an_endpoint():
    graph = _graph()

    resolutions = resolve_endpoints(graph)

    assert [item.endpoint_id for item in resolutions] == ["fact:route"]
    assert all(not item.endpoint_id.startswith("coverage:") for item in resolutions)
