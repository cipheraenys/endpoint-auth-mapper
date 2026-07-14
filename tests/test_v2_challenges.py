"""M2-D conversion and cross-framework generic graph challenge tests."""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from authmapper.core.v2 import (
    EvidenceAssociation,
    EvidenceGraph,
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
from authmapper.spike.express import SpikeArtifact, extract_express_spike

SPAN = SourceSpan("challenge.fixture", 1, 1, 1, 20)


def _span(span: Any) -> SourceSpan:
    return SourceSpan(span.file, span.start_line, span.start_column, span.end_line, span.end_column)


def _convert_express(artifact: SpikeArtifact) -> EvidenceGraph:
    subjects: list[Subject] = []
    facts: list[Fact] = []
    scopes: list[Scope] = []
    relations: list[Relation] = []
    associations: list[EvidenceAssociation] = []
    unresolved: list[UnresolvedRecord] = []
    scope_subjects: dict[str, str] = {}

    subject_kind = {
        "endpoint": SubjectKind.ROUTE_CALL,
        "middleware": SubjectKind.MIDDLEWARE,
        "inline_middleware": SubjectKind.MIDDLEWARE,
        "handler_reference": SubjectKind.HANDLER,
        "mount": SubjectKind.ROUTE_CALL,
        "public_override": SubjectKind.PUBLIC_DECLARATION,
        "router": SubjectKind.HANDLER,
        "dynamic_route": SubjectKind.ROUTE_CALL,
    }
    fact_kind = {
        "endpoint": FactKind.ENDPOINT_DECLARATION,
        "middleware": FactKind.WEAK_INDICATOR,
        "inline_middleware": FactKind.WEAK_INDICATOR,
        "handler_reference": FactKind.ROUTING_PREDICATE,
        "mount": FactKind.ROUTING_PREDICATE,
        "public_override": FactKind.PUBLIC_DECLARATION,
        "router": FactKind.ROUTING_PREDICATE,
        "dynamic_route": FactKind.ROUTING_PREDICATE,
    }
    for observation in artifact.observations:
        subject_id = f"subject:{observation.id}"
        subjects.append(
            Subject(subject_id, subject_kind[observation.kind], _span(observation.span), observation.attribute("name"))
        )
        facts.append(
            Fact(
                f"fact:{observation.id}",
                fact_kind[observation.kind],
                subject_id,
                _span(observation.span),
                method=observation.attribute("method") if observation.kind == "endpoint" else None,
                path=observation.attribute("path") if observation.kind == "endpoint" else None,
            )
        )
    for scope in artifact.scopes:
        subject_id = f"subject:{scope.id}"
        scope_subjects[scope.id] = subject_id
        subjects.append(Subject(subject_id, SubjectKind.HANDLER, _span(scope.span), scope.kind))
    for scope in artifact.scopes:
        scopes.append(
            Scope(
                scope.id,
                {
                    "application": ScopeKind.APPLICATION,
                    "router": ScopeKind.COMPONENT,
                    "route": ScopeKind.ROUTE,
                    "handler": ScopeKind.HANDLER,
                }[scope.kind],
                scope_subjects[scope.id],
                _span(scope.span),
                scope.parent_id,
            )
        )
    for edge in artifact.composition_edges:
        relations.append(
            Relation(
                f"relation:{edge.id}",
                {
                    "mount": RelationKind.COMPOSES,
                    "contains": RelationKind.CONTAINS,
                    "handler_reference": RelationKind.REFERENCES,
                }[edge.kind],
                edge.from_id,
                edge.to_id,
                _span(edge.span),
                order=int(edge.attribute("order")) if edge.attribute("order") else None,
            )
        )
    observation_ids = {item.id for item in artifact.observations}
    for edge in artifact.associations:
        assert edge.span is not None
        associations.append(
            EvidenceAssociation(
                f"association:{edge.id}",
                f"fact:{edge.endpoint_id}",
                f"fact:{edge.evidence_id}",
                edge.scope_id,
                _span(edge.span),
                tuple(sorted((f"fact:{edge.endpoint_id}", f"fact:{edge.evidence_id}"))),
            )
        )
    for item in artifact.unresolved:
        mapped_subject = f"fact:{item.subject_id}" if item.subject_id in observation_ids else None
        unresolved.append(
            UnresolvedRecord(
                f"unresolved:{item.id}",
                item.reason,
                mapped_subject,
                _span(item.span),
                (mapped_subject,) if mapped_subject else (),
            )
        )
    return EvidenceGraph(
        subjects=tuple(sorted(subjects, key=lambda item: item.id)),
        facts=tuple(sorted(facts, key=lambda item: item.id)),
        scopes=tuple(sorted(scopes, key=lambda item: item.id)),
        relations=tuple(sorted(relations, key=lambda item: item.id)),
        associations=tuple(sorted(associations, key=lambda item: item.id)),
        unresolved=tuple(sorted(unresolved, key=lambda item: item.id)),
    )


def test_m1_express_artifact_maps_without_framework_named_core_fields(fixtures_dir: Path):
    root = fixtures_dir / "express_spike"
    graph = _convert_express(extract_express_spike(root / "nested_mount.js", root=root))

    graph.validate()
    endpoint = next(fact for fact in graph.facts if fact.kind is FactKind.ENDPOINT_DECLARATION)
    assert endpoint.path == "/api/v1/users"
    assert len([relation for relation in graph.relations if relation.kind is RelationKind.COMPOSES]) == 2
    field_names = {
        field.name
        for graph_field in fields(graph)
        for item in getattr(graph, graph_field.name)
        for field in fields(item)
    }
    assert not {"express", "router_name", "receiver"} & field_names


def _challenge_graph(case: dict[str, Any]) -> EvidenceGraph:
    subjects = tuple(
        Subject(item[0], SubjectKind(item[1]), SPAN, item[2])
        for item in case["subjects"]
    )
    facts = tuple(
        Fact(item[0], FactKind(item[1]), item[2], SPAN, method=item[3], path=item[4])
        for item in case["facts"]
    )
    scopes = tuple(Scope(item[0], ScopeKind(item[1]), item[2], SPAN) for item in case["scopes"])
    relations = tuple(
        Relation(item[0], RelationKind(item[1]), item[2], item[3], SPAN, order=item[4])
        for item in case["relations"]
    )
    associations: tuple[EvidenceAssociation, ...] = ()
    proofs: tuple[Proof, ...] = ()
    if "association" in case:
        item = case["association"]
        associations = (
            EvidenceAssociation(item[0], item[1], item[2], item[3], SPAN, tuple(sorted((item[1], item[2])))),
        )
    if "proof" in case:
        item = case["proof"]
        proofs = (
            Proof(
                item[0],
                ProofKind(item[1]),
                item[2],
                (item[3],),
                (item[4],),
                derived_from=tuple(sorted((item[3], item[4]))),
            ),
        )
    return EvidenceGraph(subjects, facts, scopes, relations, associations, proofs)


@pytest.mark.parametrize(
    "case_name",
    ["hono_mounted_subapp", "bun_route_map", "axum_nested_layer", "rocket_typed_guard"],
)
def test_cross_framework_challenge_maps_to_generic_graph(fixtures_dir: Path, case_name: str):
    cases = json.loads((fixtures_dir / "v2_challenges" / "framework_graphs.json").read_text(encoding="utf-8"))
    case = cases[case_name]
    graph = _challenge_graph(case)

    graph.validate()
    assert sorted(item.kind.value for item in graph.subjects) == case["expected_subject_kinds"]
    assert all(
        name not in {field.name for field in fields(item)}
        for item in graph.subjects
        for name in ("express", "hono", "bun", "axum", "rocket")
    )


def test_rocket_guard_uses_parameter_and_type_evidence_not_middleware(fixtures_dir: Path):
    cases = json.loads((fixtures_dir / "v2_challenges" / "framework_graphs.json").read_text(encoding="utf-8"))
    graph = _challenge_graph(cases["rocket_typed_guard"])

    assert SubjectKind.CALLABLE_PARAMETER in {item.kind for item in graph.subjects}
    assert SubjectKind.TYPE_ANNOTATION in {item.kind for item in graph.subjects}
    assert SubjectKind.MIDDLEWARE not in {item.kind for item in graph.subjects}
    assert graph.proofs[0].kind is ProofKind.AUTH_ENFORCEMENT
