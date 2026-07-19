"""M2-C evidence report, fingerprint, and schema contract tests."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from authmapper.core.v2 import (
    FACT_GRAPH_VERSION,
    REPORT_SCHEMA_ID,
    REPORT_SCHEMA_VERSION,
    Capability,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    Diagnostic,
    DiagnosticLevel,
    EndpointVerdict,
    EvidenceAssociation,
    EvidenceGraph,
    EvidenceReport,
    Fact,
    FactKind,
    InvocationProvenance,
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
    endpoint_fingerprint,
    proof_fingerprint,
    report_document,
    resolve_endpoints,
)
from authmapper.reporters.v2_json_reporter import render_evidence_json

REPORT_ENUM_FIELDS = (
    ("subject", "kind", SubjectKind),
    ("fact", "kind", FactKind),
    ("scope", "kind", ScopeKind),
    ("relation", "kind", RelationKind),
    ("proof", "kind", ProofKind),
    ("diagnostic", "level", DiagnosticLevel),
    ("provenance", "capability", Capability),
    ("coverage", "capability", Capability),
    ("coverage", "status", CoverageStatus),
    ("resolution", "verdict", EndpointVerdict),
)


def evidence_report() -> EvidenceReport:
    guarded_span = SourceSpan("src/app.js", 3, 1, 3, 42)
    unresolved_span = SourceSpan("src/app.js", 4, 1, 4, 30)
    subjects = (
        Subject("subject:auth", SubjectKind.MIDDLEWARE, guarded_span, "requireAuth"),
        Subject("subject:guarded", SubjectKind.ROUTE_CALL, guarded_span),
        Subject("subject:unresolved", SubjectKind.ROUTE_CALL, unresolved_span),
    )
    facts = (
        Fact("fact:auth", FactKind.AUTH_ENFORCEMENT, "subject:auth", guarded_span),
        Fact(
            "fact:guarded",
            FactKind.ENDPOINT_DECLARATION,
            "subject:guarded",
            guarded_span,
            method="GET",
            path="/account",
        ),
        Fact(
            "fact:unresolved",
            FactKind.ENDPOINT_DECLARATION,
            "subject:unresolved",
            unresolved_span,
            method="GET",
            path="/dynamic",
        ),
    )
    scopes = (
        Scope("scope:guarded", ScopeKind.ROUTE, "subject:guarded", guarded_span),
        Scope("scope:unresolved", ScopeKind.ROUTE, "subject:unresolved", unresolved_span),
    )
    association = EvidenceAssociation(
        "association:auth",
        "fact:guarded",
        "fact:auth",
        "scope:guarded",
        guarded_span,
        ("fact:auth", "fact:guarded", "relation:auth"),
    )
    relation = Relation(
        "relation:auth",
        RelationKind.REFERENCES,
        "subject:guarded",
        "subject:auth",
        guarded_span,
    )
    proof = Proof(
        "proof:guarded",
        ProofKind.AUTH_ENFORCEMENT,
        "fact:guarded",
        ("fact:auth",),
        ("association:auth",),
        ("relation:auth",),
        ("association:auth", "fact:auth", "fact:guarded", "relation:auth"),
    )
    provenance = tuple(
        sorted(
            (
                CapabilityProvenance(f"provenance:{capability.value}", capability, "adapter:synthetic", "1.0.0")
                for capability in Capability
            ),
            key=lambda item: item.id,
        )
    )
    coverage = tuple(
        sorted(
            (
                CoverageRecord(
                    f"coverage:{endpoint}:{capability.value}",
                    f"fact:{endpoint}",
                    capability,
                    CoverageStatus.ERROR
                    if endpoint == "unresolved" and capability is Capability.ROUTE_COMPOSITION
                    else CoverageStatus.ANALYZED,
                    f"provenance:{capability.value}",
                    "dynamic route composition"
                    if endpoint == "unresolved" and capability is Capability.ROUTE_COMPOSITION
                    else None,
                )
                for endpoint in ("guarded", "unresolved")
                for capability in Capability
            ),
            key=lambda item: item.id,
        )
    )
    graph = EvidenceGraph(
        subjects=subjects,
        facts=facts,
        scopes=scopes,
        relations=(relation,),
        associations=(association,),
        proofs=(proof,),
        unresolved=(
            UnresolvedRecord(
                "unresolved:route",
                "dynamic route composition",
                "fact:unresolved",
                unresolved_span,
                ("fact:unresolved",),
            ),
        ),
        diagnostics=(
            Diagnostic(
                "diagnostic:dynamic",
                "AM-DYNAMIC-ROUTE",
                "route composition is dynamic",
                DiagnosticLevel.WARNING,
                unresolved_span,
                "fact:unresolved",
                ("fact:unresolved",),
            ),
        ),
        capability_provenance=provenance,
        coverage=coverage,
    )
    return EvidenceReport(
        graph,
        resolve_endpoints(graph),
        InvocationProvenance(
            ("authmap", "--project", "."),
            "file:///workspace",
            "0.1.2",
            "https://example.test/repository.git",
            "abc123",
        ),
    )


def test_evidence_json_is_deterministic_and_schema_valid():
    report = evidence_report()
    first = render_evidence_json(report)
    second = render_evidence_json(report)
    document = json.loads(first)
    schema = json.loads(files("authmapper.schemas").joinpath("evidence-report-2.1.schema.json").read_text())

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    assert first == second
    assert document["$schema"] == REPORT_SCHEMA_ID
    assert document["schema_version"] == REPORT_SCHEMA_VERSION == "2.1"
    assert document["fact_graph_version"] == FACT_GRAPH_VERSION == "2.1"
    assert document["endpoint_resolutions"][0]["verdict"] == "GUARDED"
    assert document["endpoint_resolutions"][1]["verdict"] == "UNRESOLVED"
    assert document["graph"]["diagnostics"][0]["code"] == "AM-DYNAMIC-ROUTE"
    assert document["graph"]["coverage"][-1]["status"] == "analyzed"


def test_report_2_0_schema_remains_byte_identical():
    schema_bytes = files("authmapper.schemas").joinpath("evidence-report-2.0.schema.json").read_bytes()

    assert hashlib.sha256(schema_bytes).hexdigest() == (
        "6354b7eea6d31fb0777b762994987d38b743f03e270c5d71b2a796e67ce0316b"
    )


def test_report_document_explicitly_selects_current_2_1_contract():
    document = report_document(evidence_report(), schema_version="2.1")

    assert document["$schema"] == "https://authmap.dev/schemas/evidence-report-2.1.json"
    assert document["schema_version"] == "2.1"
    assert document["fact_graph_version"] == "2.1"


def test_report_document_defaults_to_current_2_1_contract():
    document = report_document(evidence_report())

    assert document["$schema"] == REPORT_SCHEMA_ID
    assert document["schema_version"] == REPORT_SCHEMA_VERSION == "2.1"


def test_report_document_rejects_unknown_contract_version():
    with pytest.raises(ValueError, match="unsupported report schema version"):
        report_document(evidence_report(), schema_version="2.0")


@pytest.mark.parametrize(
    ("definition", "property_name", "enum_type"),
    REPORT_ENUM_FIELDS,
)
def test_report_2_1_schema_accepts_every_public_graph_enum(definition, property_name, enum_type):
    schema = json.loads(files("authmapper.schemas").joinpath("evidence-report-2.1.schema.json").read_text())

    assert set(schema["$defs"][definition]["properties"][property_name]["enum"]) == {
        item.value for item in enum_type
    }


@pytest.mark.parametrize(
    ("definition", "property_name"),
    tuple((definition, property_name) for definition, property_name, _ in REPORT_ENUM_FIELDS),
)
def test_report_2_1_schema_rejects_unknown_public_graph_enum(definition, property_name):
    schema = json.loads(files("authmapper.schemas").joinpath("evidence-report-2.1.schema.json").read_text())
    document = report_document(evidence_report())
    locations = {
        "subject": document["graph"]["subjects"],
        "fact": document["graph"]["facts"],
        "scope": document["graph"]["scopes"],
        "relation": document["graph"]["relations"],
        "proof": document["graph"]["proofs"],
        "diagnostic": document["graph"]["diagnostics"],
        "provenance": document["graph"]["capability_provenance"],
        "coverage": document["graph"]["coverage"],
        "resolution": document["endpoint_resolutions"],
    }
    locations[definition][0][property_name] = "unknown"

    errors = tuple(Draft202012Validator(schema).iter_errors(document))

    assert any(error.validator == "enum" for error in errors)


def test_report_2_1_schema_has_completeness_tests_for_every_enum():
    schema = json.loads(files("authmapper.schemas").joinpath("evidence-report-2.1.schema.json").read_text())
    actual = {
        (definition, property_name)
        for definition, definition_schema in schema["$defs"].items()
        for property_name, property_schema in definition_schema.get("properties", {}).items()
        if "enum" in property_schema
    }
    expected = {(definition, property_name) for definition, property_name, _ in REPORT_ENUM_FIELDS}

    assert actual == expected


def test_fingerprints_are_algorithm_versioned_and_semantic():
    report = evidence_report()
    endpoint = next(fact for fact in report.graph.facts if fact.id == "fact:guarded")
    proof = report.graph.proofs[0]

    endpoint_print = endpoint_fingerprint(endpoint)
    proof_print = proof_fingerprint(endpoint, proof)
    moved = Fact(
        endpoint.id,
        endpoint.kind,
        endpoint.subject_id,
        SourceSpan("other/app.js", 30, 1, 30, 42),
        method=endpoint.method,
        path=endpoint.path,
    )

    assert endpoint_print.algorithm == "authmap.endpoint.v1"
    assert proof_print.algorithm == "authmap.proof.v1"
    assert endpoint_fingerprint(moved).value == endpoint_print.value
    assert proof_print.value != endpoint_print.value
    assert len(proof_print.value) == 64


def test_report_requires_one_resolution_per_endpoint():
    report = evidence_report()

    try:
        EvidenceReport(report.graph, report.resolutions[:1], report.invocation)
    except ValueError as exc:
        assert "every graph endpoint" in str(exc)
    else:
        raise AssertionError("incomplete report resolution was accepted")
