"""Framework-neutral adapter boundary for v2 evidence production."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

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

    def analyze(self, input_data: AdapterInput) -> AdapterArtifact:
        """Analyze source without executing target code."""
        ...
