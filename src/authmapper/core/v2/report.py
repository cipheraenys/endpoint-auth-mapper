"""Versioned evidence report envelope and deterministic document conversion."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from .contracts import FACT_GRAPH_VERSION, REPORT_SCHEMA_ID, REPORT_SCHEMA_VERSION
from .fingerprint import endpoint_fingerprint, proof_fingerprint
from .graph import EvidenceGraph
from .model import EndpointResolution, Fact, FactKind
from .package import ReportedCapability


@dataclass(frozen=True, slots=True)
class InvocationProvenance:
    command_line: tuple[str, ...]
    working_directory: str
    tool_version: str
    vcs_uri: str | None = None
    vcs_revision: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceReport:
    graph: EvidenceGraph
    resolutions: tuple[EndpointResolution, ...]
    invocation: InvocationProvenance
    capabilities: tuple[ReportedCapability, ...] = ()

    def __post_init__(self) -> None:
        self.graph.validate()
        endpoints = {
            fact.id
            for fact in self.graph.facts
            if fact.kind in {FactKind.ENDPOINT_DECLARATION, FactKind.ROUTE_IDENTITY}
        }
        resolution_ids = [item.endpoint_id for item in self.resolutions]
        if resolution_ids != sorted(resolution_ids) or len(resolution_ids) != len(set(resolution_ids)):
            raise ValueError("endpoint resolutions must be unique and ordered")
        if set(resolution_ids) != endpoints:
            raise ValueError("endpoint resolutions must cover every graph endpoint exactly once")
        capability_keys = tuple(
            (item.adapter_id, item.adapter_version, item.capability) for item in self.capabilities
        )
        if capability_keys != tuple(sorted(capability_keys)) or len(capability_keys) != len(set(capability_keys)):
            raise ValueError("reported capabilities must be unique and ordered")


def report_document(report: EvidenceReport) -> dict[str, Any]:
    facts = {fact.id: fact for fact in report.graph.facts}
    proofs = {proof.id: proof for proof in report.graph.proofs}
    resolutions = []
    for resolution in report.resolutions:
        endpoint = facts[resolution.endpoint_id]
        resolution_document = _value(resolution)
        resolution_document["fingerprint"] = _value(endpoint_fingerprint(endpoint))
        resolution_document["proof_fingerprints"] = [
            _value(proof_fingerprint(endpoint, proofs[proof_id])) for proof_id in resolution.proof_ids
        ]
        resolutions.append(resolution_document)

    return {
        "$schema": REPORT_SCHEMA_ID,
        "schema_version": REPORT_SCHEMA_VERSION,
        "fact_graph_version": FACT_GRAPH_VERSION,
        "tool": {"name": "endpoint-auth-mapper", "version": report.invocation.tool_version},
        "invocation": _value(report.invocation),
        "graph": _value(report.graph),
        "endpoint_resolutions": resolutions,
    }


def _value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_value(item) for item in value]
    if isinstance(value, list):
        return [_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _value(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _value(item) for key, item in asdict(value).items()}
    return value


def endpoint_span(report: EvidenceReport, endpoint: Fact) -> dict[str, int | str]:
    span = endpoint.span
    return {
        "path": span.path,
        "start_line": span.start_line,
        "start_column": span.start_column,
        "end_line": span.end_line,
        "end_column": span.end_column,
    }
