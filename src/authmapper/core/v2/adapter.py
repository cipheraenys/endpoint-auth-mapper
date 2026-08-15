"""Framework-neutral adapter boundary for v2 evidence production."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .model import (
    CapabilityProvenance,
    CoverageRecord,
    Diagnostic,
    Fact,
    Relation,
    Scope,
    Subject,
    UnresolvedRecord,
)

if TYPE_CHECKING:
    from .graph import EvidenceGraph
    from .package import ApplicabilityResult, CapabilityMaturity


@dataclass(frozen=True, slots=True)
class AdapterInput:
    project_root: Path
    source_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class AdapterArtifact:
    """Syntactic evidence only; verdicts and severity belong to later stages."""

    subjects: tuple[Subject, ...] = ()
    facts: tuple[Fact, ...] = ()
    scopes: tuple[Scope, ...] = ()
    relations: tuple[Relation, ...] = ()
    unresolved: tuple[UnresolvedRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    capability_provenance: tuple[CapabilityProvenance, ...] = ()
    coverage: tuple[CoverageRecord, ...] = ()


class Adapter(Protocol):
    id: str
    version: str
    source_extensions: frozenset[str]
    """Lowercase file suffixes this adapter can analyze, including the leading dot."""

    capability_maturity: Mapping[str, CapabilityMaturity]
    """Declared maturity per capability id, reported verbatim in evidence output."""

    ownership_rationale: str
    """Human-readable reason attached to files this adapter claims."""

    def applicability(self, input_data: AdapterInput) -> ApplicabilityResult:
        """Decide whether this adapter owns the project, with supporting evidence."""
        ...

    def analyze(self, input_data: AdapterInput) -> AdapterArtifact:
        """Analyze source without executing target code."""
        ...

    def build_graph(self, artifact: AdapterArtifact) -> EvidenceGraph:
        """Lift syntactic evidence into the framework-neutral evidence graph."""
        ...
