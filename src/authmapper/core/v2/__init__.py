"""Production v2 evidence graph and resolver contracts."""

from __future__ import annotations

from .adapter import Adapter, AdapterArtifact, AdapterInput
from .graph import EvidenceGraph, GraphValidationError
from .manifest import ManifestError, RulepackManifest, load_manifest, parse_manifest
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
from .package import (
    ActivationEvidence,
    ApplicabilityResult,
    ApplicabilityState,
    CapabilityMaturity,
    OwnershipDecision,
    OwnershipState,
    PackageLifecycle,
)
from .resolver import resolve_endpoints
from .semantics import SemanticKind, SemanticRule

__all__ = [
    "ActivationEvidence",
    "Adapter",
    "AdapterArtifact",
    "AdapterInput",
    "ApplicabilityResult",
    "ApplicabilityState",
    "Capability",
    "CapabilityMaturity",
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
    "ManifestError",
    "OwnershipDecision",
    "OwnershipState",
    "PackageLifecycle",
    "Proof",
    "ProofKind",
    "Relation",
    "RelationKind",
    "RulepackManifest",
    "Scope",
    "ScopeKind",
    "SourceSpan",
    "SemanticKind",
    "SemanticRule",
    "Subject",
    "SubjectKind",
    "UnresolvedRecord",
    "load_manifest",
    "parse_manifest",
    "resolve_endpoints",
]
