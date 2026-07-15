"""M4-D deterministic JSON and SARIF gate audit tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

from test_v2_exceptions import _document, _policy, _report

from authmapper.app.evidence_gate import classify_gate_exit, evaluate_evidence_gate
from authmapper.app.exception_audit import audit_evidence_exceptions
from authmapper.core.v2 import parse_evidence_exceptions
from authmapper.reporters.gate_audit import render_gate_audit_json, render_gate_audit_sarif
from authmapper.reporters.v2_sarif_reporter import render_evidence_sarif


def test_json_exposes_ordered_policy_gate_and_evidence_without_mutation():
    report = _report()
    policy = _policy()
    run = evaluate_evidence_gate(report, policy)

    first = render_gate_audit_json(report, policy, run)
    second = render_gate_audit_json(report, policy, run)
    document = json.loads(first)

    assert first == second
    assert document["policy"]["id"] == "default.assurance"
    assert [item["id"] for item in document["policy"]["requirements"]] == sorted(
        item["id"] for item in document["policy"]["requirements"]
    )
    assert document["gate"]["exit_class"] == "violation"
    assert document["gate"]["exit_code"] == 1
    assert document["gate"]["violations"][0]["kind"] == "unguarded"
    assert document["evidence_report"]["endpoint_resolutions"][0]["verdict"] == "UNGARDED"


def test_json_keeps_suppressed_finding_visible_with_consumed_audit():
    report = _report()
    policy = _policy()
    audit = audit_evidence_exceptions(
        report,
        policy,
        parse_evidence_exceptions(_document()),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    run = replace(
        evaluate_evidence_gate(report, policy),
        gate=audit.gate,
        exit_class=classify_gate_exit(audit.gate),
        exception_audit=audit.audit,
    )
    document = json.loads(render_gate_audit_json(report, policy, run))

    assert document["gate"]["violations"] == []
    assert document["gate"]["exit_class"] == "satisfied"
    assert document["gate"]["exit_code"] == 0
    assert document["exception_audit"][0]["state"] == "consumed"
    assert document["evidence_report"]["endpoint_resolutions"][0]["verdict"] == "UNGARDED"


def test_sarif_preserves_endpoint_results_and_exposes_gate_audit():
    report = _report()
    policy = _policy()
    run = evaluate_evidence_gate(report, policy)
    base = json.loads(render_evidence_sarif(report))

    rendered = render_gate_audit_sarif(base, report, policy, run)
    document = json.loads(rendered)
    results = document["runs"][0]["results"]
    properties = document["runs"][0]["properties"]["authmapGate"]

    assert any(item["ruleId"] == "AMV2-0002" for item in results)
    assert any(item["ruleId"] == "AMGATE-UNGUARDED" for item in results)
    assert any(item["id"] == "AMGATE-UNGUARDED" for item in document["runs"][0]["tool"]["driver"]["rules"])
    assert properties["policyId"] == "default.assurance"
    assert properties["exitClass"] == "violation"


def test_sarif_keeps_suppressed_endpoint_visible_and_is_deterministic():
    report = _report()
    policy = _policy()
    audit = audit_evidence_exceptions(
        report,
        policy,
        parse_evidence_exceptions(_document()),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    run = replace(
        evaluate_evidence_gate(report, policy),
        gate=audit.gate,
        exit_class=classify_gate_exit(audit.gate),
        exception_audit=audit.audit,
    )
    base = json.loads(render_evidence_sarif(report))

    first = render_gate_audit_sarif(base, report, policy, run)
    second = render_gate_audit_sarif(base, report, policy, run)
    document = json.loads(first)

    assert first == second
    assert any(item["ruleId"] == "AMV2-0002" for item in document["runs"][0]["results"])
    properties = document["runs"][0]["properties"]["authmapGate"]
    assert properties["exitClass"] == "satisfied"
    assert properties["exceptionAudit"][0]["state"] == "consumed"
    assert not any(item["ruleId"].startswith("AMGATE-") for item in document["runs"][0]["results"])
