"""Framework-neutral endpoint verdict resolution from validated evidence."""

from __future__ import annotations

from .graph import EvidenceGraph
from .model import (
    Capability,
    CoverageStatus,
    EndpointResolution,
    EndpointVerdict,
    FactKind,
    Proof,
    ProofKind,
)

_REQUIRED_COVERAGE = frozenset(
    {
        Capability.ENDPOINT_DISCOVERY,
        Capability.ROUTE_COMPOSITION,
        Capability.SCOPE_RESOLUTION,
        Capability.AUTH_ASSOCIATION,
    }
)


def resolve_endpoints(graph: EvidenceGraph) -> tuple[EndpointResolution, ...]:
    """Validate ``graph`` and derive one conservative verdict per endpoint."""
    graph.validate()
    facts = {fact.id: fact for fact in graph.facts}
    associations = {association.id: association for association in graph.associations}
    endpoint_facts = tuple(
        fact
        for fact in graph.facts
        if fact.kind in {FactKind.ENDPOINT_DECLARATION, FactKind.ROUTE_IDENTITY}
    )
    resolutions: list[EndpointResolution] = []

    for endpoint in endpoint_facts:
        coverage = tuple(record for record in graph.coverage if record.target_id == endpoint.id)
        complete = {
            record.capability
            for record in coverage
            if record.status is CoverageStatus.ANALYZED
        } >= _REQUIRED_COVERAGE
        unresolved = tuple(
            item
            for item in graph.unresolved
            if item.subject_id in {endpoint.id, endpoint.subject_id}
        )
        valid_proofs = tuple(
            proof
            for proof in graph.proofs
            if proof.endpoint_id == endpoint.id and _proof_is_valid(proof, facts, associations)
        )
        public_proofs = tuple(proof for proof in valid_proofs if proof.kind is ProofKind.PUBLIC_POLICY)
        guard_proofs = tuple(proof for proof in valid_proofs if proof.kind is ProofKind.AUTH_ENFORCEMENT)
        associated_fact_kinds = {
            facts[association.evidence_fact_id].kind
            for association in graph.associations
            if association.endpoint_id == endpoint.id
        }
        unresolved_claim = bool(
            {FactKind.AUTH_ENFORCEMENT, FactKind.PUBLIC_DECLARATION} & associated_fact_kinds
        ) and not (public_proofs or guard_proofs)
        invalid_proof = any(proof.endpoint_id == endpoint.id for proof in graph.proofs) and not valid_proofs

        if unresolved or not complete or unresolved_claim or invalid_proof:
            verdict = EndpointVerdict.UNRESOLVED
            selected_proofs: tuple[Proof, ...] = ()
        elif public_proofs:
            verdict = EndpointVerdict.DECLARED_PUBLIC
            selected_proofs = public_proofs
        elif guard_proofs:
            verdict = EndpointVerdict.GUARDED
            selected_proofs = guard_proofs
        else:
            verdict = EndpointVerdict.UNGUARDED
            selected_proofs = ()

        resolutions.append(
            EndpointResolution(
                endpoint_id=endpoint.id,
                verdict=verdict,
                proof_ids=tuple(proof.id for proof in selected_proofs),
                unresolved_ids=tuple(item.id for item in unresolved),
                coverage_ids=tuple(item.id for item in coverage),
            )
        )

    return tuple(resolutions)


def _proof_is_valid(proof: Proof, facts: dict, associations: dict) -> bool:
    required_fact_kind = {
        ProofKind.AUTH_ENFORCEMENT: FactKind.AUTH_ENFORCEMENT,
        ProofKind.PUBLIC_POLICY: FactKind.PUBLIC_DECLARATION,
    }[proof.kind]
    evidence_ids = {fact_id for fact_id in proof.fact_ids if facts[fact_id].kind is required_fact_kind}
    if not evidence_ids or not proof.association_ids:
        return False
    return any(
        association_id in associations
        and associations[association_id].endpoint_id == proof.endpoint_id
        and associations[association_id].evidence_fact_id in evidence_ids
        for association_id in proof.association_ids
    )
