"""Production v2 evidence-scan application use case."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from authmapper import __version__
from authmapper.adapters import get_adapter
from authmapper.core.v2 import (
    Adapter,
    AdapterExplanation,
    AdapterInput,
    CapabilityExplanation,
    EvidenceReport,
    InvocationProvenance,
    OwnershipDecision,
    OwnershipState,
    ReportedCapability,
    resolve_endpoints,
)

_DEFAULT_EXCLUDES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "vendor",
        "venv",
    }
)
_DEFAULT_FILE_EXCLUDES = frozenset({"test", "tests", "spec", "specs"})


@dataclass(frozen=True, slots=True)
class EvidenceScanResult:
    report: EvidenceReport
    explanation: AdapterExplanation


def _collect_sources(root: Path, suffixes: frozenset[str]) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in suffixes
                and not (_DEFAULT_EXCLUDES & set(path.relative_to(root).parts))
                and path.stem not in _DEFAULT_FILE_EXCLUDES
                and not any(part in _DEFAULT_FILE_EXCLUDES for part in path.relative_to(root).parts[:-1])
            ),
            key=lambda path: path.as_posix(),
        )
    )


def run_evidence_scan(
    project_root: Path,
    command_line: tuple[str, ...],
    adapter_id: str = "express",
) -> EvidenceScanResult:
    """Run a full evidence scan with the registered adapter for ``adapter_id``."""
    return run_adapter_evidence_scan(get_adapter(adapter_id), project_root, command_line)


def run_adapter_evidence_scan(
    adapter: Adapter,
    project_root: Path,
    command_line: tuple[str, ...],
) -> EvidenceScanResult:
    """Run a full evidence scan with an already constructed adapter."""
    root = project_root.resolve()
    paths = _collect_sources(root, adapter.source_extensions)
    input_data = AdapterInput(root, paths)
    applicability = adapter.applicability(input_data)
    artifact = adapter.analyze(input_data)
    graph = adapter.build_graph(artifact)
    ownership = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        evidence_ids = tuple(item.id for item in applicability.evidence if item.span and item.span.path == relative)
        if evidence_ids:
            ownership.append(
                OwnershipDecision(
                    f"source:{relative}",
                    f"source:{relative}",
                    adapter.id,
                    OwnershipState.SELECTED,
                    evidence_ids,
                    adapter.ownership_rationale,
                )
            )
    maturity = adapter.capability_maturity
    capabilities = tuple(
        CapabilityExplanation(item, maturity[item])
        for item in sorted(maturity)
    )
    reported_capabilities = tuple(
        ReportedCapability(adapter.id, adapter.version, item, maturity[item], applicability.state)
        for item in sorted(maturity)
    )
    report = EvidenceReport(
        graph,
        resolve_endpoints(graph),
        InvocationProvenance(command_line, str(root), __version__),
        reported_capabilities,
    )
    explanation = AdapterExplanation(
        adapter.id,
        adapter.version,
        applicability,
        tuple(ownership),
        capabilities,
        tuple(sorted({rule for item in graph.capability_provenance for rule in item.rule_ids})),
        graph.diagnostics,
    )
    return EvidenceScanResult(report, explanation)


def run_express_evidence_scan(project_root: Path, command_line: tuple[str, ...]) -> EvidenceScanResult:
    """Backwards-compatible entry point pinned to the Express adapter."""
    return run_evidence_scan(project_root, command_line, adapter_id="express")
