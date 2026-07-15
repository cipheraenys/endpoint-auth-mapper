"""Production v2 evidence-scan application use case."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from authmapper import __version__
from authmapper.adapters import ExpressAdapter, build_express_graph
from authmapper.core.v2 import (
    AdapterExplanation,
    AdapterInput,
    CapabilityExplanation,
    CapabilityMaturity,
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


def run_express_evidence_scan(project_root: Path, command_line: tuple[str, ...]) -> EvidenceScanResult:
    root = project_root.resolve()
    paths = tuple(
        sorted(
            (
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in {".js", ".mjs", ".cjs"}
                and not (_DEFAULT_EXCLUDES & set(path.relative_to(root).parts))
                and path.stem not in _DEFAULT_FILE_EXCLUDES
                and not any(part in _DEFAULT_FILE_EXCLUDES for part in path.relative_to(root).parts[:-1])
            ),
            key=lambda path: path.as_posix(),
        )
    )
    adapter = ExpressAdapter()
    input_data = AdapterInput(root, paths)
    applicability = adapter.applicability(input_data)
    artifact = adapter.analyze(input_data)
    graph = build_express_graph(artifact, adapter_version=adapter.version)
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
                    "nearest package declares Express and source resolves Express binding",
                )
            )
    maturity = {
        "auth_association": CapabilityMaturity.VERIFIED,
        "endpoint_discovery": CapabilityMaturity.VERIFIED,
        "public_override": CapabilityMaturity.EXPERIMENTAL,
        "route_composition": CapabilityMaturity.VERIFIED,
        "scope_resolution": CapabilityMaturity.VERIFIED,
    }
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
