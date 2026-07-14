"""Production v2 evidence graph and resolver contracts."""

from __future__ import annotations

from .graph import EvidenceGraph, GraphValidationError
from .model import (
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    Diagnostic,
    DiagnosticLevel,
    EndpointResolution,
    EndpointVerdict,
    EvidenceAssociation,
    Fact,
    FactKind,
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
)
from .resolver import resolve_endpoints

__all__ = [
    "Capability",
    "CapabilityProvenance",
    "CoverageRecord",
    "CoverageStatus",
    "Diagnostic",
    "DiagnosticLevel",
    "EndpointResolution",
    "EndpointVerdict",
    "EvidenceAssociation",
    "EvidenceGraph",
    "Fact",
    "FactKind",
    "GraphValidationError",
    "Proof",
    "ProofKind",
    "Relation",
    "RelationKind",
    "Scope",
    "ScopeKind",
    "SourceSpan",
    "Subject",
    "SubjectKind",
    "UnresolvedRecord",
    "resolve_endpoints",
]
