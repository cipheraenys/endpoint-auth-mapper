"""M4-C shared exception audit application use-case tests."""

from __future__ import annotations

from datetime import datetime, timezone

from test_v2_exceptions import _document, _policy, _report

from authmapper.app.exception_audit import audit_evidence_exceptions
from authmapper.core.v2 import ExceptionAuditState, parse_evidence_exceptions


def test_shared_exception_audit_consumes_exact_violation():
    result = audit_evidence_exceptions(
        _report(),
        _policy(),
        parse_evidence_exceptions(_document()),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert result.gate.passed
    assert [item.state for item in result.audit] == [ExceptionAuditState.CONSUMED]
