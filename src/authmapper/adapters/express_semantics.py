"""Auditable semantic recognition and proof production for Express evidence."""

from __future__ import annotations

from authmapper.core.v2 import (
    AdapterArtifact,
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    EvidenceAssociation,
    EvidenceGraph,
    Fact,
    FactKind,
    Proof,
    ProofKind,
    RelationKind,
    SubjectKind,
    UnresolvedRecord,
)

_REQUIRED_CAPABILITIES = (
    Capability.AUTH_ASSOCIATION,
    Capability.ENDPOINT_DISCOVERY,
    Capability.ROUTE_COMPOSITION,
    Capability.SCOPE_RESOLUTION,
)


def build_express_graph(artifact: AdapterArtifact, *, adapter_version: str) -> EvidenceGraph:
    """Recognize exact Passport enforcement and conservatively resolve claims."""
    subjects = {item.id: item for item in artifact.subjects}
    endpoints = tuple(item for item in artifact.facts if item.kind is FactKind.ENDPOINT_DECLARATION)
    route_scope_by_subject = {scope.subject_id: scope for scope in artifact.scopes if scope.kind.value == "route"}
    facts = list(artifact.facts)
    associations: list[EvidenceAssociation] = []
    proofs: list[Proof] = []
    unresolved = list(artifact.unresolved)
    provenance = tuple(
        CapabilityProvenance(
            f"provenance:express:{capability.value}", capability, "express", adapter_version,
            ("express.passport.authenticate",) if capability is Capability.AUTH_ASSOCIATION else (),
        )
        for capability in _REQUIRED_CAPABILITIES
    )

    registration = [item for item in artifact.relations if item.kind is RelationKind.CONTAINS]
    for endpoint in endpoints:
        route_scope = route_scope_by_subject[endpoint.subject_id]
        route_registration = next(item for item in registration if item.target_id == route_scope.id)
        candidates = []
        public_facts = tuple(
            fact
            for fact in artifact.facts
            if fact.kind is FactKind.PUBLIC_DECLARATION
            and subjects[fact.subject_id].parent_id == endpoint.subject_id
        )
        for public_fact in public_facts:
            relation = next(
                item
                for item in artifact.relations
                if item.kind is RelationKind.REFERENCES
                and item.source_id == endpoint.subject_id
                and item.target_id == public_fact.subject_id
            )
            association = EvidenceAssociation(
                f"association:public:{endpoint.id}:{public_fact.id}",
                endpoint.id,
                public_fact.id,
                route_scope.id,
                public_fact.span,
                tuple(sorted((endpoint.id, public_fact.id, relation.id))),
            )
            proof = Proof(
                f"proof:public:{endpoint.id}:{public_fact.id}",
                ProofKind.PUBLIC_POLICY,
                endpoint.id,
                (public_fact.id,),
                (association.id,),
                (relation.id,),
                tuple(sorted((association.id, endpoint.id, public_fact.id, relation.id))),
            )
            associations.append(association)
            proofs.append(proof)
        for relation in artifact.relations:
            target = subjects.get(relation.target_id)
            if target is None or target.kind not in {SubjectKind.HANDLER, SubjectKind.MIDDLEWARE}:
                continue
            route_local = relation.source_id == endpoint.subject_id or relation.source_id == route_scope.id
            receiver_ordered = (
                relation.source_id == route_registration.source_id
                and relation.order is not None
                and route_registration.order is not None
                and relation.order < route_registration.order
            )
            if route_local or receiver_ordered:
                candidates.append((target, relation))

        for middleware, relation in candidates:
            if middleware.kind is SubjectKind.MIDDLEWARE and (
                middleware.name == "passport.authenticate:jwt"
                or (middleware.name is not None and middleware.name.startswith("custom-auth:"))
            ):
                auth_fact = Fact(
                    f"fact:auth:{endpoint.id}:{middleware.id}",
                    FactKind.AUTH_ENFORCEMENT,
                    middleware.id,
                    middleware.span,
                )
                association = EvidenceAssociation(
                    f"association:auth:{endpoint.id}:{middleware.id}",
                    endpoint.id,
                    auth_fact.id,
                    route_scope.id,
                    middleware.span,
                    tuple(sorted((auth_fact.id, endpoint.id, relation.id))),
                )
                proof = Proof(
                    f"proof:auth:{endpoint.id}:{middleware.id}",
                    ProofKind.AUTH_ENFORCEMENT,
                    endpoint.id,
                    (auth_fact.id,),
                    (association.id,),
                    (relation.id,),
                    tuple(
                        sorted(
                            (
                                association.id,
                                auth_fact.id,
                                endpoint.id,
                                "provenance:express:auth_association",
                                relation.id,
                            )
                        )
                    ),
                )
                facts.append(auth_fact)
                associations.append(association)
                proofs.append(proof)
            elif _auth_looking(middleware.name):
                unresolved.append(
                    UnresolvedRecord(
                        f"unresolved:auth:{endpoint.id}:{middleware.id}",
                        "middleware auth semantics are not proven",
                        endpoint.id,
                        middleware.span,
                        (middleware.id,),
                    )
                )

    coverage = tuple(
        CoverageRecord(
            f"coverage:{endpoint.id}:{capability.value}",
            endpoint.id,
            capability,
            _coverage_status(endpoint, capability, artifact),
            f"provenance:express:{capability.value}",
            _coverage_reason(endpoint, artifact),
        )
        for endpoint in endpoints
        for capability in _REQUIRED_CAPABILITIES
    )
    graph = EvidenceGraph(
        subjects=artifact.subjects,
        facts=_ordered(facts),
        scopes=artifact.scopes,
        relations=artifact.relations,
        associations=_ordered(associations),
        proofs=_ordered(proofs),
        unresolved=_ordered(unresolved),
        diagnostics=artifact.diagnostics,
        capability_provenance=_ordered(provenance),
        coverage=_ordered(coverage),
    )
    graph.validate()
    return graph


def _auth_looking(name: str | None) -> bool:
    if name is None:
        return False
    lowered = name.lower()
    if lowered.startswith("custom-member:"):
        return lowered.endswith((".isauthenticated", ".isauthorized"))
    if lowered == "passport.authenticate:local":
        return False
    if lowered.startswith("custom-auth:"):
        return True
    if lowered.startswith("unresolved-auth:"):
        return True
    if lowered == "auth":
        return True
    return any(
        token in lowered
        for token in (
            "requireauth",
            "authguard",
            "authorize",
            "authorization",
            "isauth",
            "token",
            "sessionauth",
            "loginrequired",
            "is_authenticated",
            "is_authorized",
        )
    )


def _coverage_status(
    endpoint: Fact, capability: Capability, artifact: AdapterArtifact
) -> CoverageStatus:
    for diagnostic in artifact.diagnostics:
        if diagnostic.level.value != "error":
            continue
        if diagnostic.span is None:
            return CoverageStatus.ERROR
        if diagnostic.span.path == endpoint.span.path:
            return CoverageStatus.ERROR
    if (
        capability is not Capability.ENDPOINT_DISCOVERY
        and any(record.subject_id == endpoint.id for record in artifact.unresolved)
    ):
        return CoverageStatus.UNSUPPORTED
    return CoverageStatus.ANALYZED


def _coverage_reason(endpoint: Fact, artifact: AdapterArtifact) -> str | None:
    if any(
        diagnostic.level.value == "error"
        and (diagnostic.span is None or diagnostic.span.path == endpoint.span.path)
        for diagnostic in artifact.diagnostics
    ):
        return "adapter analysis reported an error for the endpoint source"
    return None


def _ordered(items):
    return tuple(sorted(items, key=lambda item: item.id))
