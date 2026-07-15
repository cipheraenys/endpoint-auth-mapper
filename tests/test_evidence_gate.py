"""M4-C shared evidence gate application use-case tests."""

from __future__ import annotations

from dataclasses import replace

from test_v2_exceptions import _policy, _report

from authmapper.app.evidence_gate import GateExitClass, evaluate_evidence_gate


def test_shared_gate_maps_satisfied_violation_and_setup_exit_classes():
    violation = evaluate_evidence_gate(_report(), _policy())
    assert violation.exit_class is GateExitClass.VIOLATION
    assert violation.exit_class.code == 1

    run = evaluate_evidence_gate(_report(), replace(_policy(), fail_on_unguarded=False))
    assert run.exit_class is GateExitClass.SATISFIED
    assert run.exit_class.code == 0

    report = replace(_report(), capabilities=())
    setup = evaluate_evidence_gate(report, _policy())
    assert setup.exit_class is GateExitClass.SETUP_ERROR
    assert setup.exit_class.code == 2
