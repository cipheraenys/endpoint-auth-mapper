"""Shared application use case for exception audit over one evidence scan."""

from __future__ import annotations

from datetime import datetime

from authmapper.core.v2 import (
    EvidenceExceptions,
    EvidencePolicy,
    EvidenceReport,
    ExceptionResult,
    apply_evidence_exceptions,
    evaluate_evidence_policy,
)


def audit_evidence_exceptions(
    report: EvidenceReport,
    policy: EvidencePolicy,
    exceptions: EvidenceExceptions,
    *,
    now: datetime,
) -> ExceptionResult:
    """Audit exact exceptions without hiding evidence or scan results."""
    gate = evaluate_evidence_policy(policy, report)
    return apply_evidence_exceptions(gate, exceptions, policy, report, now=now)
