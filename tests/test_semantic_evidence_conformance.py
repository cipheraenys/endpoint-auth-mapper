"""Framework-neutral conformance tests for semantic assurance evidence."""

from __future__ import annotations

import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from authmapper.core.v2 import (
    REPORT_SCHEMA_ID,
    REPORT_SCHEMA_VERSION,
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    EndpointVerdict,
    EvidenceAssociation,
    EvidenceGraph,
    EvidenceReport,
    Fact,
    FactKind,
    GraphValidationError,
    InvocationProvenance,
    Proof,
    ProofKind,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
    UnresolvedRecord,
    report_document,
    resolve_endpoints,
)
from authmapper.reporters.v2_json_reporter import render_evidence_json

EVIDENCE_SPAN = SourceSpan("src/generic.routes", 2, 3, 2, 24)
ENDPOINT_SPAN = SourceSpan("src/generic.routes", 8, 1, 8, 32)
REQUIRED_CAPABILITIES = (
    Capability.AUTH_ASSOCIATION,
    Capability.ENDPOINT_DISCOVERY,
    Capability.ROUTE_COMPOSITION,
    Capability.SCOPE_RESOLUTION,
)


def _ordered(items):
    return tuple(sorted(items, key=lambda item: item.id))


def _coverage(endpoint_ids: tuple[str, ...]):
    provenance = tuple(
        CapabilityProvenance(
            f"provenance:{capability.value}",
            capability,
            "adapter:synthetic",
            "1.0.0",
            (f"rule:{capability.value}",),
        )
        for capability in REQUIRED_CAPABILITIES
    )
    coverage = _ordered(
        CoverageRecord(
            f"coverage:{endpoint_id.removeprefix('fact:route:')}:{capability.value}",
            endpoint_id,
            capability,
            CoverageStatus.ANALYZED,
            f"provenance:{capability.value}",
        )
        for endpoint_id in endpoint_ids
        for capability in REQUIRED_CAPABILITIES
    )
    return provenance, coverage


def _semantic_graph() -> EvidenceGraph:
    endpoints = ("ambiguous", "guarded", "identity", "session", "weak")
    endpoint_ids = tuple(f"fact:route:{name}" for name in endpoints)
    provenance, coverage = _coverage(endpoint_ids)
    evidence_kinds = {
        "ambiguity": FactKind.AUTH_AMBIGUITY,
        "enforcement": FactKind.AUTH_ENFORCEMENT,
        "identity": FactKind.IDENTITY_USE,
        "session": FactKind.SESSION_PRESENCE,
        "weak": FactKind.WEAK_INDICATOR,
    }

    return EvidenceGraph(
        subjects=_ordered(
            [Subject(f"subject:{name}", SubjectKind.POLICY, EVIDENCE_SPAN) for name in evidence_kinds]
            + [Subject(f"subject:route:{name}", SubjectKind.ROUTE_CALL, ENDPOINT_SPAN) for name in endpoints]
        ),
        facts=_ordered(
            [
                Fact(f"fact:{name}", kind, f"subject:{name}", EVIDENCE_SPAN)
                for name, kind in evidence_kinds.items()
            ]
            + [
                Fact(
                    f"fact:route:{name}",
                    FactKind.ENDPOINT_DECLARATION,
                    f"subject:route:{name}",
                    ENDPOINT_SPAN,
                    method="GET",
                    path=f"/{name}",
                )
                for name in endpoints
            ]
        ),
        scopes=tuple(
            Scope(f"scope:route:{name}", ScopeKind.ROUTE, f"subject:route:{name}", ENDPOINT_SPAN)
            for name in endpoints
        ),
        associations=_ordered(
            (
                EvidenceAssociation(
                    f"association:{association}",
                    f"fact:route:{endpoint}",
                    f"fact:{evidence}",
                    f"scope:route:{endpoint}",
                    EVIDENCE_SPAN,
                    tuple(sorted((f"fact:{evidence}", f"fact:route:{endpoint}"))),
                )
                for association, evidence, endpoint in (
                    ("ambiguity", "ambiguity", "ambiguous"),
                    ("enforcement", "enforcement", "guarded"),
                    ("identity", "identity", "identity"),
                    ("identity:ambiguous", "identity", "ambiguous"),
                    ("session", "session", "session"),
                    ("session:ambiguous", "session", "ambiguous"),
                    ("weak", "weak", "weak"),
                    ("weak:ambiguous", "weak", "ambiguous"),
                )
            )
        ),
        proofs=(
            Proof(
                "proof:guarded",
                ProofKind.AUTH_ENFORCEMENT,
                "fact:route:guarded",
                ("fact:enforcement",),
                ("association:enforcement",),
                derived_from=("association:enforcement", "fact:enforcement"),
            ),
        ),
        unresolved=(
            UnresolvedRecord(
                "unresolved:ambiguity",
                "auth evidence cannot be proven",
                "fact:route:ambiguous",
                EVIDENCE_SPAN,
                ("association:ambiguity", "fact:ambiguity"),
            ),
        ),
        capability_provenance=provenance,
        coverage=coverage,
    )


def test_semantic_evidence_shapes_conform_through_report_schema():
    graph = _semantic_graph()
    resolutions = resolve_endpoints(graph)
    by_endpoint = {item.endpoint_id: item for item in resolutions}

    assert by_endpoint["fact:route:guarded"].verdict is EndpointVerdict.GUARDED
    assert by_endpoint["fact:route:guarded"].proof_ids == ("proof:guarded",)
    assert by_endpoint["fact:route:ambiguous"].verdict is EndpointVerdict.UNRESOLVED
    assert by_endpoint["fact:route:ambiguous"].unresolved_ids == ("unresolved:ambiguity",)
    assert {
        by_endpoint[f"fact:route:{name}"].verdict for name in ("identity", "session", "weak")
    } == {EndpointVerdict.UNGUARDED}
    assert all(len(item.coverage_ids) == len(REQUIRED_CAPABILITIES) for item in resolutions)
    assert all(item.status is CoverageStatus.ANALYZED for item in graph.coverage)

    report = EvidenceReport(
        graph,
        resolutions,
        InvocationProvenance(("authmap", "--evidence-scan", "synthetic"), "/project", "0.1.2"),
    )
    first_json = render_evidence_json(report)
    second_json = render_evidence_json(report)
    first = json.loads(first_json)
    schema = json.loads(files("authmapper.schemas").joinpath("evidence-report-2.1.schema.json").read_text())

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first)
    assert first_json == second_json
    assert first == report_document(report, schema_version=REPORT_SCHEMA_VERSION)
    assert first["$schema"] == REPORT_SCHEMA_ID
    assert first["schema_version"] == "2.1"
    ambiguity_fact = next(item for item in first["graph"]["facts"] if item["id"] == "fact:ambiguity")
    ambiguity_association = next(
        item for item in first["graph"]["associations"] if item["id"] == "association:ambiguity"
    )
    ambiguity_unresolved = first["graph"]["unresolved"][0]
    assert ambiguity_fact["kind"] == "auth_ambiguity"
    assert ambiguity_fact["span"] == {
        "path": "src/generic.routes",
        "start_line": 2,
        "start_column": 3,
        "end_line": 2,
        "end_column": 24,
    }
    assert ambiguity_association["derived_from"] == ["fact:ambiguity", "fact:route:ambiguous"]
    assert ambiguity_unresolved["subject_id"] == "fact:route:ambiguous"
    assert ambiguity_unresolved["derived_from"] == ["association:ambiguity", "fact:ambiguity"]


def test_ambiguity_derivation_cannot_mix_fact_and_endpoint_across_associations():
    graph = _semantic_graph()
    second_ambiguity = Fact(
        "fact:ambiguity:second",
        FactKind.AUTH_AMBIGUITY,
        "subject:ambiguity",
        EVIDENCE_SPAN,
    )
    second_association = EvidenceAssociation(
        "association:ambiguity:second",
        "fact:route:weak",
        "fact:ambiguity:second",
        "scope:route:weak",
        EVIDENCE_SPAN,
        ("fact:ambiguity:second", "fact:route:weak"),
    )
    unresolved = _ordered(
        (
            *graph.unresolved,
            UnresolvedRecord(
                "unresolved:ambiguity:crossed",
                "crossed ambiguity references",
                "fact:route:weak",
                EVIDENCE_SPAN,
                ("association:ambiguity", "association:ambiguity:second", "fact:ambiguity:second"),
            ),
            UnresolvedRecord(
                "unresolved:ambiguity:second",
                "auth evidence cannot be proven",
                "fact:route:weak",
                EVIDENCE_SPAN,
                ("association:ambiguity:second", "fact:ambiguity:second"),
            ),
        )
    )
    malformed = EvidenceGraph(
        subjects=graph.subjects,
        facts=_ordered((*graph.facts, second_ambiguity)),
        scopes=graph.scopes,
        associations=_ordered((*graph.associations, second_association)),
        proofs=graph.proofs,
        unresolved=unresolved,
        capability_provenance=graph.capability_provenance,
        coverage=graph.coverage,
    )

    with pytest.raises(GraphValidationError) as error:
        malformed.validate()

    assert "ambiguity unresolved" in str(error.value)
