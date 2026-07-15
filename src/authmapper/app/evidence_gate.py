"""Shared application use case for evidence policy and exception gating."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from authmapper.core.v2 import (
    EvidenceGateResult,
    EvidencePolicy,
    EvidenceReport,
    GateIssueKind,
    evaluate_evidence_policy,
)


class GateExitClass(str, Enum):
    SATISFIED = "satisfied"
    VIOLATION = "violation"
    SETUP_ERROR = "setup_error"

    @property
    def code(self) -> int:
        return {
            GateExitClass.SATISFIED: 0,
            GateExitClass.VIOLATION: 1,
            GateExitClass.SETUP_ERROR: 2,
        }[self]


@dataclass(frozen=True, slots=True)
class EvidenceGateRun:
    gate: EvidenceGateResult
    exit_class: GateExitClass


_SETUP_KINDS = frozenset(
    {
        GateIssueKind.ANALYSIS_ERROR,
        GateIssueKind.CAPABILITY_REQUIREMENT,
        GateIssueKind.EXCEPTION_AUDIT,
    }
)


def evaluate_evidence_gate(
    report: EvidenceReport,
    policy: EvidencePolicy,
) -> EvidenceGateRun:
    """Apply one policy to an immutable runner report."""
    gate = evaluate_evidence_policy(policy, report)
    if any(item.kind in _SETUP_KINDS for item in gate.violations):
        exit_class = GateExitClass.SETUP_ERROR
    elif gate.violations:
        exit_class = GateExitClass.VIOLATION
    else:
        exit_class = GateExitClass.SATISFIED
    return EvidenceGateRun(gate, exit_class)
