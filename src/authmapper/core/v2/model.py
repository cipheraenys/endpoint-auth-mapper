"""Immutable evidence-domain contracts for the v2 analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SubjectKind(str, Enum):
    ROUTE_CALL = "route_call"
    OBJECT_PROPERTY = "object_property"
    HANDLER = "handler"
    CALLABLE_PARAMETER = "callable_parameter"
    TYPE_ANNOTATION = "type_annotation"
    DECORATOR = "decorator"
    MIDDLEWARE = "middleware"
    POLICY = "policy"
    PUBLIC_DECLARATION = "public_declaration"


class FactKind(str, Enum):
    ENDPOINT_DECLARATION = "endpoint_declaration"
    ROUTE_IDENTITY = "route_identity"
    AUTH_ENFORCEMENT = "auth_enforcement"
    AUTH_AMBIGUITY = "auth_ambiguity"
    PUBLIC_DECLARATION = "public_declaration"
    IDENTITY_USE = "identity_use"
    SESSION_PRESENCE = "session_presence"
    ROUTING_PREDICATE = "routing_predicate"
    WEAK_INDICATOR = "weak_indicator"


class ScopeKind(str, Enum):
    APPLICATION = "application"
    COMPONENT = "component"
    ROUTE = "route"
    HANDLER = "handler"
    CALLABLE = "callable"


class RelationKind(str, Enum):
    CONTAINS = "contains"
    COMPOSES = "composes"
    REFERENCES = "references"
    DERIVES = "derives"


class ProofKind(str, Enum):
    AUTH_ENFORCEMENT = "auth_enforcement"
    PUBLIC_POLICY = "public_policy"


class CoverageStatus(str, Enum):
    ANALYZED = "analyzed"
    EXCLUDED = "excluded"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    ERROR = "error"


class Capability(str, Enum):
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    ROUTE_COMPOSITION = "route_composition"
    SCOPE_RESOLUTION = "scope_resolution"
    AUTH_ASSOCIATION = "auth_association"


class DiagnosticLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class EndpointVerdict(str, Enum):
    GUARDED = "GUARDED"
    UNGUARDED = "UNGARDED"
    DECLARED_PUBLIC = "DECLARED_PUBLIC"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True)
class SourceSpan:
    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("source span path must not be empty")
        if min(self.start_line, self.start_column, self.end_line, self.end_column) < 1:
            raise ValueError("source span positions are one-based")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("source span end must not precede its start")


@dataclass(frozen=True, slots=True)
class Subject:
    id: str
    kind: SubjectKind
    span: SourceSpan
    name: str | None = None
    parent_id: str | None = None
    derived_from: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Fact:
    id: str
    kind: FactKind
    subject_id: str
    span: SourceSpan
    derived_from: tuple[str, ...] = ()
    method: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class Scope:
    id: str
    kind: ScopeKind
    subject_id: str
    span: SourceSpan
    parent_id: str | None = None
    derived_from: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Relation:
    id: str
    kind: RelationKind
    source_id: str
    target_id: str
    span: SourceSpan
    derived_from: tuple[str, ...] = ()
    order: int | None = None


@dataclass(frozen=True, slots=True)
class EvidenceAssociation:
    id: str
    endpoint_id: str
    evidence_fact_id: str
    scope_id: str
    span: SourceSpan
    derived_from: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Proof:
    id: str
    kind: ProofKind
    endpoint_id: str
    fact_ids: tuple[str, ...]
    association_ids: tuple[str, ...]
    relation_ids: tuple[str, ...] = ()
    derived_from: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UnresolvedRecord:
    id: str
    reason: str
    subject_id: str | None
    span: SourceSpan
    derived_from: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Diagnostic:
    id: str
    code: str
    message: str
    level: DiagnosticLevel
    span: SourceSpan | None = None
    subject_id: str | None = None
    derived_from: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapabilityProvenance:
    id: str
    capability: Capability
    adapter_id: str
    adapter_version: str
    rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    id: str
    target_id: str
    capability: Capability
    status: CoverageStatus
    provenance_id: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class EndpointResolution:
    endpoint_id: str
    verdict: EndpointVerdict
    proof_ids: tuple[str, ...] = ()
    unresolved_ids: tuple[str, ...] = ()
    coverage_ids: tuple[str, ...] = ()
