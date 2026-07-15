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
    Relation,
    Scope,
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
        for proof in self.proofs:
            self._require_endpoint(proof.endpoint_id, by_id, proof.id)
            self._require_many(proof.fact_ids, fact_ids, proof.id, "fact")
            self._require_many(proof.association_ids, association_ids, proof.id, "association")
            self._require_many(proof.relation_ids, relation_ids, proof.id, "relation")
            if not proof.derived_from:
                raise GraphValidationError(f"{proof.id}: proof needs provenance")
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
