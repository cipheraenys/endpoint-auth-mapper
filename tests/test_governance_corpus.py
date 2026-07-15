"""Independent M4 governance corpus over committed policy behavior."""

from __future__ import annotations

import itertools
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from test_v2_exceptions import _document, _policy, _report

from authmapper.app.evidence_gate import GateExitClass, classify_gate_exit, evaluate_evidence_gate
from authmapper.app.exception_audit import audit_evidence_exceptions
from authmapper.core.v2 import (
    ApplicabilityState,
    CapabilityMaturity,
    CoverageStatus,
    ExceptionAuditState,
    parse_evidence_exceptions,
)

CORPUS = json.loads(
    (Path(__file__).parent / "fixtures" / "governance-corpus.json").read_text(encoding="utf-8")
)
EXPECTED = {item["id"]: item["expected_exit_class"] for item in CORPUS["cases"]}


@pytest.mark.parametrize(
    ("case", "report_update", "policy_update", "expected"),
    [
        ("verified_unguarded", {}, {}, GateExitClass.VIOLATION),
        ("verified_unresolved", {"verdict": "unresolved"}, {}, GateExitClass.SATISFIED),
        ("verified_incomplete", {"coverage": CoverageStatus.ERROR}, {}, GateExitClass.VIOLATION),
        (
            "experimental",
            {"maturity": CapabilityMaturity.EXPERIMENTAL},
            {"minimum": "experimental"},
            GateExitClass.SATISFIED,
        ),
        ("demoted", {"maturity": CapabilityMaturity.EXPERIMENTAL}, {}, GateExitClass.SETUP_ERROR),
        ("inactive", {"applicability": ApplicabilityState.INACTIVE}, {}, GateExitClass.SETUP_ERROR),
    ],
)
def test_independent_policy_cases(case, report_update, policy_update, expected):
    from authmapper.core.v2 import EndpointVerdict, EvidenceReport, resolve_endpoints

    verdict = (
        EndpointVerdict.UNRESOLVED
        if report_update.get("verdict") == "unresolved"
        else EndpointVerdict.UNGUARDED
    )
    coverage_status = report_update.get("coverage", CoverageStatus.ANALYZED)
    report = _report()
    graph = replace(
        report.graph,
        coverage=tuple(replace(item, status=coverage_status) for item in report.graph.coverage),
        unresolved=report.graph.unresolved,
    )
    if verdict is EndpointVerdict.UNRESOLVED:
        from authmapper.core.v2 import UnresolvedRecord

        graph = replace(
            graph,
            unresolved=(
                UnresolvedRecord(
                    "unresolved:route",
                    "dynamic",
                    "fact:route",
                    graph.facts[0].span,
                    ("fact:route",),
                ),
            ),
        )
    capabilities = tuple(
        replace(
            item,
            maturity=report_update.get("maturity", item.maturity),
            applicability=report_update.get("applicability", item.applicability),
        )
        for item in report.capabilities
    )
    report = EvidenceReport(graph, resolve_endpoints(graph), report.invocation, capabilities)
    policy = _policy()
    if policy_update:
        policy = replace(
            policy,
            requirements=tuple(
                replace(item, minimum_maturity=CapabilityMaturity.EXPERIMENTAL)
                for item in policy.requirements
            ),
        )

    assert expected.value == EXPECTED[case.replace("_", "-")]
    assert evaluate_evidence_gate(report, policy).exit_class is expected, case


@pytest.mark.parametrize(
    ("mutation", "state"),
    [
        ("exact", ExceptionAuditState.CONSUMED),
        ("refactor", ExceptionAuditState.UNMATCHED),
        ("expired", ExceptionAuditState.EXPIRED),
        ("invalid", ExceptionAuditState.INVALID),
    ],
)
def test_independent_exception_cases(mutation: str, state: ExceptionAuditState):
    document = _document()
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    if mutation == "refactor":
        document["exceptions"][0]["identity"]["path"] = "/renamed"
    elif mutation == "expired":
        document["exceptions"][0]["created_on"] = "2025-01-01"
        document["exceptions"][0]["expires_on"] = "2026-07-16"
    elif mutation == "invalid":
        now = datetime(2026, 6, 30, tzinfo=timezone.utc)
    result = audit_evidence_exceptions(
        _report(), _policy(), parse_evidence_exceptions(document), now=now
    )

    assert result.audit[0].state is state


def test_duplicate_exception_identity_is_rejected():
    document = _document()
    duplicate = dict(document["exceptions"][0])
    duplicate["id"] = "exception.duplicate"
    document["exceptions"].append(duplicate)

    with pytest.raises(ValueError, match="identities must be unique"):
        parse_evidence_exceptions(document)


def test_exception_permutation_and_timezone_boundaries_are_stable():
    document = _document()
    other = dict(document["exceptions"][0])
    other["id"] = "exception.other"
    other["identity"] = dict(other["identity"])
    other["identity"]["path"] = "/other"
    other["identity"]["endpoint_fingerprint"] = "0" * 64
    entries = [document["exceptions"][0], other]
    outputs = []
    for permutation in itertools.permutations(entries):
        candidate = {**document, "exceptions": list(permutation)}
        parsed = parse_evidence_exceptions(candidate)
        outputs.append(tuple(item.id for item in parsed.exceptions))
    assert len(set(outputs)) == 1

    boundary = datetime(2026, 8, 1, tzinfo=timezone.utc)
    equivalent = boundary.astimezone(timezone(timedelta(hours=-7)))
    for now in (boundary, equivalent):
        result = audit_evidence_exceptions(
            _report(), _policy(), parse_evidence_exceptions(_document()), now=now
        )
        assert result.audit[0].state is ExceptionAuditState.EXPIRED


def test_exception_failure_classifies_as_setup_not_policy_violation():
    result = audit_evidence_exceptions(
        _report(),
        _policy(),
        parse_evidence_exceptions(_document(path="/other")),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert classify_gate_exit(result.gate) is GateExitClass.SETUP_ERROR


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adapter_id", "other"),
        ("endpoint_fingerprint", "f" * 64),
        ("policy_id", "other.policy"),
    ],
)
def test_exception_identity_never_leaks_across_governance_boundaries(field: str, value: str):
    document = _document(**{field: value})
    if field == "policy_id":
        document["exceptions"][0]["authorizing_policy_id"] = value
    result = audit_evidence_exceptions(
        _report(),
        _policy(),
        parse_evidence_exceptions(document),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert result.audit[0].state is ExceptionAuditState.UNMATCHED
    assert classify_gate_exit(result.gate) is GateExitClass.SETUP_ERROR


def test_legacy_option_conflict_is_part_of_governance_corpus(tmp_path: Path):
    from authmapper.cli import main

    with pytest.raises(SystemExit, match="2"):
        main([
            "--project",
            str(tmp_path),
            "--evidence-scan",
            "express",
            "--evidence-policy",
            "policy.json",
            "--fail-on",
            "EXPOSED",
        ])
