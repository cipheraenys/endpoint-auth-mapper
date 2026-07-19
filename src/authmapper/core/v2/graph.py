"""Evidence graph container and deterministic structural validation."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

from .model import (
    CapabilityProvenance,
    CoverageRecord,
    Diagnostic,
    EvidenceAssociation,
    Fact,
    FactKind,
    Proof,
    ProofKind,
    Relation,
    RelationKind,
    Scope,
    ScopeKind,
    Subject,
    UnresolvedRecord,
)


class GraphValidationError(ValueError):
    """Raised when an evidence graph violates a core invariant."""


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    subjects: tuple[Subject, ...] = ()
    facts: tuple[Fact, ...] = ()
    scopes: tuple[Scope, ...] = ()
    relations: tuple[Relation, ...] = ()
    associations: tuple[EvidenceAssociation, ...] = ()
    proofs: tuple[Proof, ...] = ()
    unresolved: tuple[UnresolvedRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    capability_provenance: tuple[CapabilityProvenance, ...] = ()
    coverage: tuple[CoverageRecord, ...] = ()

    def validate(self) -> None:
        groups = tuple(getattr(self, item.name) for item in fields(self))
        entities = tuple(entity for group in groups for entity in group)
        identifiers = [entity.id for entity in entities]
        if any(not identifier for identifier in identifiers):
            raise GraphValidationError("graph IDs must not be empty")
        if len(identifiers) != len(set(identifiers)):
            raise GraphValidationError("graph IDs must be globally unique")
        for group in groups:
            group_ids = [entity.id for entity in group]
            if group_ids != sorted(group_ids):
                raise GraphValidationError("graph entities must be ordered by ID")

        by_id = {entity.id: entity for entity in entities}
        facts_by_id = {item.id: item for item in self.facts}
        scopes_by_id = {item.id: item for item in self.scopes}
        relations_by_id = {item.id: item for item in self.relations}
        associations_by_id = {item.id: item for item in self.associations}
        subject_ids = {item.id for item in self.subjects}
        fact_ids = {item.id for item in self.facts}
        scope_ids = {item.id for item in self.scopes}
        relation_ids = {item.id for item in self.relations}
        association_ids = {item.id for item in self.associations}
        provenance_by_id = {item.id: item for item in self.capability_provenance}
        provenance_ids = set(provenance_by_id)

        for subject in self.subjects:
            self._require_optional(subject.parent_id, subject_ids, subject.id, "parent subject")
        for fact in self.facts:
            self._require(fact.subject_id, subject_ids, fact.id, "subject")
            if fact.kind is FactKind.ROUTE_IDENTITY and not fact.derived_from:
                raise GraphValidationError(f"{fact.id}: derived route identity needs provenance")
            if fact.path is not None and fact.kind not in {FactKind.ENDPOINT_DECLARATION, FactKind.ROUTE_IDENTITY}:
                raise GraphValidationError(f"{fact.id}: path is only valid on endpoint facts")
        for scope in self.scopes:
            self._require(scope.subject_id, subject_ids, scope.id, "subject")
            self._require_optional(scope.parent_id, scope_ids, scope.id, "parent scope")
        for relation in self.relations:
            self._require(relation.source_id, set(by_id), relation.id, "source")
            self._require(relation.target_id, set(by_id), relation.id, "target")
        for association in self.associations:
            self._require_endpoint(association.endpoint_id, by_id, association.id)
            self._require(association.evidence_fact_id, fact_ids, association.id, "evidence fact")
            self._require(association.scope_id, scope_ids, association.id, "scope")
            if not association.derived_from:
                raise GraphValidationError(f"{association.id}: association needs provenance")
            if facts_by_id[association.evidence_fact_id].kind is FactKind.AUTH_ENFORCEMENT:
                self._validate_enforcement_association(
                    association,
                    facts_by_id,
                    scopes_by_id,
                    relations_by_id,
                )
        for proof in self.proofs:
            self._require_endpoint(proof.endpoint_id, by_id, proof.id)
            self._require_many(proof.fact_ids, fact_ids, proof.id, "fact")
            self._require_many(proof.association_ids, association_ids, proof.id, "association")
            self._require_many(proof.relation_ids, relation_ids, proof.id, "relation")
            if not proof.derived_from:
                raise GraphValidationError(f"{proof.id}: proof needs provenance")
            selected_path = {
                proof.endpoint_id,
                *proof.fact_ids,
                *proof.association_ids,
                *proof.relation_ids,
            }
            if not proof.fact_ids or not proof.association_ids:
                raise GraphValidationError(f"{proof.id}: proof needs facts and associations")
            if proof.kind is ProofKind.AUTH_ENFORCEMENT and not proof.relation_ids:
                raise GraphValidationError(f"{proof.id}: enforcement proof needs relations")
            if not selected_path <= set(proof.derived_from):
                raise GraphValidationError(f"{proof.id}: proof derivation must include selected evidence path")
            for association_id in proof.association_ids:
                association = associations_by_id[association_id]
                if association.endpoint_id != proof.endpoint_id:
                    raise GraphValidationError(f"{proof.id}: proof association must use proof endpoint")
                if association.evidence_fact_id not in proof.fact_ids:
                    raise GraphValidationError(f"{proof.id}: proof association must use a selected fact")
                if proof.kind is ProofKind.AUTH_ENFORCEMENT:
                    if not set(proof.relation_ids) <= set(association.derived_from):
                        raise GraphValidationError(
                            f"{proof.id}: enforcement proof relations must be in association provenance"
                        )
                    self._validate_enforcement_association(
                        association,
                        facts_by_id,
                        scopes_by_id,
                        relations_by_id,
                        selected_relation_ids=proof.relation_ids,
                        relation_path_label="selected relation path",
                    )

        ambiguity_associations = {
            association.evidence_fact_id
            for association in self.associations
            if facts_by_id[association.evidence_fact_id].kind is FactKind.AUTH_AMBIGUITY
        }
        for fact in self.facts:
            if fact.kind is FactKind.AUTH_AMBIGUITY and fact.id not in ambiguity_associations:
                raise GraphValidationError(f"{fact.id}: ambiguity fact needs endpoint association")
        for unresolved in self.unresolved:
            self._require_optional(unresolved.subject_id, set(by_id), unresolved.id, "subject")
            if not unresolved.reason:
                raise GraphValidationError(f"{unresolved.id}: unresolved reason must not be empty")
        for diagnostic in self.diagnostics:
            self._require_optional(diagnostic.subject_id, set(by_id), diagnostic.id, "subject")
        for record in self.coverage:
            self._require(record.target_id, set(by_id), record.id, "target")
            self._require(record.provenance_id, provenance_ids, record.id, "capability provenance")
            if provenance_by_id[record.provenance_id].capability is not record.capability:
                raise GraphValidationError(f"{record.id}: coverage capability must match provenance")

        derivations = {
            entity.id: entity.derived_from
            for entity in entities
            if hasattr(entity, "derived_from")
        }
        for owner_id, references in derivations.items():
            self._require_many(references, set(by_id), owner_id, "derivation")
        self._reject_derivation_cycles(derivations)
        self._reject_advisory_enforcement_derivations(facts_by_id, derivations)
        self._validate_auth_ambiguity()

    def _validate_enforcement_association(
        self,
        association: EvidenceAssociation,
        facts_by_id: dict[str, Fact],
        scopes_by_id: dict[str, Scope],
        relations_by_id: dict[str, Relation],
        *,
        selected_relation_ids: tuple[str, ...] | None = None,
        relation_path_label: str = "relation path",
    ) -> None:
        endpoint = facts_by_id[association.endpoint_id]
        evidence = facts_by_id[association.evidence_fact_id]
        scope = scopes_by_id[association.scope_id]
        if selected_relation_ids is None:
            selected_relation_ids = tuple(
                item for item in association.derived_from if item in relations_by_id
            )
        required = {association.endpoint_id, association.evidence_fact_id}
        if not selected_relation_ids or not required <= set(association.derived_from):
            raise GraphValidationError(
                f"{association.id}: association derivation must include endpoint, evidence, and relation"
            )

        endpoint_ids = {endpoint.id, endpoint.subject_id}
        endpoint_ids.update(
            candidate.id for candidate in self.scopes if candidate.subject_id == endpoint.subject_id
        )
        scope_ids = {scope.id, scope.subject_id}
        direct_route_scope = (
            scope.kind is ScopeKind.ROUTE and scope.subject_id == endpoint.subject_id
        )
        if not direct_route_scope and not _relation_path_connects(
            endpoint_ids,
            scope_ids,
            selected_relation_ids,
            relations_by_id,
        ):
            raise GraphValidationError(f"{association.id}: scope must belong to endpoint or have relation path")

        endpoint_region = endpoint_ids | _scope_region(scope, scopes_by_id)
        evidence_region = {evidence.id, evidence.subject_id}
        evidence_region.update(
            candidate.id for candidate in self.scopes if candidate.subject_id == evidence.subject_id
        )
        if not _relation_path_connects(
            endpoint_region,
            evidence_region,
            selected_relation_ids,
            relations_by_id,
        ):
            raise GraphValidationError(
                f"{association.id}: {relation_path_label} must connect endpoint scope to evidence"
            )

    def _validate_auth_ambiguity(self) -> None:
        ambiguity_fact_ids = {
            fact.id for fact in self.facts if fact.kind is FactKind.AUTH_AMBIGUITY
        }
        ambiguity_associations = {
            association.id: association
            for association in self.associations
            if association.evidence_fact_id in ambiguity_fact_ids
        }
        ambiguity_unresolved = tuple(
            unresolved
            for unresolved in self.unresolved
            if ambiguity_fact_ids & set(unresolved.derived_from)
            or set(ambiguity_associations) & set(unresolved.derived_from)
        )

        for unresolved in ambiguity_unresolved:
            fact_ids = ambiguity_fact_ids & set(unresolved.derived_from)
            association_ids = set(ambiguity_associations) & set(unresolved.derived_from)
            if not association_ids:
                raise GraphValidationError(f"{unresolved.id}: ambiguity unresolved needs matching association")
            if not fact_ids:
                raise GraphValidationError(f"{unresolved.id}: ambiguity unresolved needs matching fact")
            matched_association_ids = {
                association_id
                for association_id in association_ids
                if ambiguity_associations[association_id].evidence_fact_id in fact_ids
            }
            if len(fact_ids) != 1 or len(association_ids) != 1 or len(matched_association_ids) != 1:
                raise GraphValidationError(f"{unresolved.id}: ambiguity unresolved fact must match association")
            association_id = next(iter(matched_association_ids))
            if ambiguity_associations[association_id].endpoint_id != unresolved.subject_id:
                raise GraphValidationError(
                    f"{unresolved.id}: ambiguity unresolved must reference association endpoint"
                )

        for association in ambiguity_associations.values():
            endpoint = next(fact for fact in self.facts if fact.id == association.endpoint_id)
            scope = next(scope for scope in self.scopes if scope.id == association.scope_id)
            if scope.subject_id != endpoint.subject_id:
                raise GraphValidationError(
                    f"{association.id}: ambiguity scope must belong to endpoint"
                )
            if not {association.endpoint_id, association.evidence_fact_id} <= set(association.derived_from):
                raise GraphValidationError(
                    f"{association.id}: ambiguity association derivation must include endpoint and fact"
                )
            matching = tuple(
                unresolved
                for unresolved in ambiguity_unresolved
                if association.id in unresolved.derived_from
                and association.evidence_fact_id in unresolved.derived_from
                and unresolved.subject_id == association.endpoint_id
            )
            if not matching:
                raise GraphValidationError(
                    f"{association.id}: ambiguity association needs endpoint-bound unresolved evidence"
                )

    @staticmethod
    def _require(reference: str, allowed: set[str], owner: str, label: str) -> None:
        if reference not in allowed:
            raise GraphValidationError(f"{owner}: unknown {label} ID {reference!r}")

    @classmethod
    def _require_optional(cls, reference: str | None, allowed: set[str], owner: str, label: str) -> None:
        if reference is not None:
            cls._require(reference, allowed, owner, label)

    @classmethod
    def _require_many(cls, references: tuple[str, ...], allowed: set[str], owner: str, label: str) -> None:
        if list(references) != sorted(references) or len(references) != len(set(references)):
            raise GraphValidationError(f"{owner}: {label} IDs must be unique and ordered")
        for reference in references:
            cls._require(reference, allowed, owner, label)

    @staticmethod
    def _require_endpoint(endpoint_id: str, by_id: dict[str, Any], owner: str) -> None:
        endpoint = by_id.get(endpoint_id)
        if not isinstance(endpoint, Fact) or endpoint.kind not in {
            FactKind.ENDPOINT_DECLARATION,
            FactKind.ROUTE_IDENTITY,
        }:
            raise GraphValidationError(f"{owner}: endpoint ID must reference an endpoint fact")

    @staticmethod
    def _reject_derivation_cycles(derivations: dict[str, tuple[str, ...]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(identifier: str) -> None:
            if identifier in visiting:
                raise GraphValidationError("derived evidence must be acyclic")
            if identifier in visited:
                return
            visiting.add(identifier)
            for dependency in derivations.get(identifier, ()):
                visit(dependency)
            visiting.remove(identifier)
            visited.add(identifier)

        for identifier in derivations:
            visit(identifier)

    def _reject_advisory_enforcement_derivations(
        self,
        facts_by_id: dict[str, Fact],
        derivations: dict[str, tuple[str, ...]],
    ) -> None:
        advisory_kinds = {
            FactKind.AUTH_AMBIGUITY,
            FactKind.IDENTITY_USE,
            FactKind.SESSION_PRESENCE,
            FactKind.WEAK_INDICATOR,
        }

        def includes_advisory(identifier: str) -> bool:
            for dependency in derivations.get(identifier, ()):
                fact = facts_by_id.get(dependency)
                if fact is not None and fact.kind in advisory_kinds:
                    return True
                if includes_advisory(dependency):
                    return True
            return False

        for proof in self.proofs:
            if proof.kind is not ProofKind.AUTH_ENFORCEMENT:
                continue
            selected_ids = (
                *(
                    fact_id
                    for fact_id in proof.fact_ids
                    if facts_by_id[fact_id].kind is FactKind.AUTH_ENFORCEMENT
                ),
                *proof.association_ids,
                *proof.relation_ids,
                proof.id,
            )
            if any(includes_advisory(identifier) for identifier in selected_ids):
                raise GraphValidationError(
                    f"{proof.id}: auth enforcement derivation includes advisory fact"
                )


def _scope_region(scope: Scope, scopes_by_id: dict[str, Scope]) -> set[str]:
    region = {scope.id, scope.subject_id}
    seen = {scope.id}
    parent_id = scope.parent_id
    while parent_id is not None:
        if parent_id in seen:
            break
        seen.add(parent_id)
        parent = scopes_by_id[parent_id]
        region.update((parent.id, parent.subject_id))
        parent_id = parent.parent_id
    return region


def _relation_path_connects(
    start_ids: set[str],
    target_ids: set[str],
    relation_ids: tuple[str, ...],
    relations_by_id: dict[str, Relation],
) -> bool:
    adjacent: dict[str, set[str]] = {}
    for relation_id in relation_ids:
        relation = relations_by_id[relation_id]
        step = _forward_relation_step(relation)
        if step is None:
            continue
        source_id, target_id = step
        adjacent.setdefault(source_id, set()).add(target_id)

    seen = set(start_ids)
    pending = list(start_ids)
    while pending:
        current = pending.pop()
        for neighbor in adjacent.get(current, ()):
            if neighbor in target_ids:
                return True
            if neighbor not in seen:
                seen.add(neighbor)
                pending.append(neighbor)
    return False


def _forward_relation_step(relation: Relation) -> tuple[str, str] | None:
    if relation.kind in {RelationKind.CONTAINS, RelationKind.COMPOSES, RelationKind.REFERENCES}:
        return relation.source_id, relation.target_id
    return None
