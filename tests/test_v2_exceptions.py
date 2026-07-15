"""M4-B exact expiring evidence exception tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime, timezone

import pytest

from authmapper.core.v2 import (
    ApplicabilityState,
    Capability,
    CapabilityMaturity,
    CapabilityProvenance,
    CoverageRecord,
    CoverageStatus,
    EndpointVerdict,
    EvidenceExceptionError,
    EvidenceGraph,
    EvidenceReport,
    ExceptionAuditState,
    Fact,
    FactKind,
    GateIssueKind,
    InvocationProvenance,
    ReportedCapability,
    SourceSpan,
    Subject,
    SubjectKind,
    apply_evidence_exceptions,
    endpoint_fingerprint,
    evaluate_evidence_policy,
    parse_evidence_exceptions,
    parse_evidence_policy,
    replace_evidence_exception,
    resolve_endpoints,
)

SCHEMA_ID = "https://authmap.dev/schemas/evidence-exceptions-1.0.json"
SPAN = SourceSpan("app.js", 1, 1, 1, 24)
CAPABILITIES = tuple(Capability)


def _report() -> EvidenceReport:
    endpoint = Fact(
        "fact:route",
        FactKind.ENDPOINT_DECLARATION,
        "subject:route",
        SPAN,
        method="GET",
        path="/admin",
    )
    provenance = tuple(
        sorted(
            (
                CapabilityProvenance(
                    f"provenance:express:{capability.value}",
                    capability,
                    "express",
                    "0.1.0",
                )
                for capability in CAPABILITIES
            ),
            key=lambda item: item.id,
        )
    )
    coverage = tuple(
        sorted(
            (
                CoverageRecord(
                    f"coverage:{capability.value}",
                    endpoint.id,
                    capability,
                    CoverageStatus.ANALYZED,
                    f"provenance:express:{capability.value}",
                )
                for capability in CAPABILITIES
            ),
            key=lambda item: item.id,
        )
    )
    capabilities = tuple(
        ReportedCapability(
            "express",
            "0.1.0",
            capability.value,
            CapabilityMaturity.VERIFIED,
            ApplicabilityState.ACTIVE,
        )
        for capability in sorted(CAPABILITIES, key=lambda item: item.value)
    )
    graph = EvidenceGraph(
        subjects=(Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN),),
        facts=(endpoint,),
        capability_provenance=provenance,
        coverage=coverage,
    )
    return EvidenceReport(
        graph,
        resolve_endpoints(graph),
        InvocationProvenance(("authmap",), ".", "0.1.2"),
        capabilities,
    )


def _policy():
    return parse_evidence_policy(
        {
            "$schema": "https://authmap.dev/schemas/evidence-policy-1.0.json",
            "schema_version": "1.0",
            "id": "default.assurance",
            "fail_on_unguarded": True,
            "fail_on_unresolved": False,
            "fail_on_incomplete_coverage": True,
            "requirements": [
                {
                    "id": f"express.{capability.value}",
                    "adapter_id": "express",
                    "adapter_version": "0.1.0",
                    "capability": capability.value,
                    "minimum_maturity": "verified",
                }
                for capability in CAPABILITIES
            ],
        }
    )


def _document(**identity_updates: str) -> dict:
    endpoint = _report().graph.facts[0]
    identity = {
        "method": "GET",
        "path": "/admin",
        "adapter_id": "express",
        "adapter_version": "0.1.0",
        "capability": "auth_association",
        "maturity": "verified",
        "endpoint_fingerprint_algorithm": "authmap.endpoint.v1",
        "endpoint_fingerprint": endpoint_fingerprint(endpoint).value,
        "violation": "unguarded",
        "policy_id": "default.assurance",
    }
    identity.update(identity_updates)
    return {
        "$schema": SCHEMA_ID,
        "schema_version": "1.0",
        "exceptions": [
            {
                "id": "exception.admin",
                "reason": "migration window",
                "owner": "security",
                "reference": "SEC-123",
                "created_on": "2026-07-01",
                "expires_on": "2026-08-01",
                "review_on": None,
                "authorizing_policy_id": "default.assurance",
                "identity": identity,
            }
        ],
    }


def _apply(document: dict, now: datetime = datetime(2026, 7, 16, tzinfo=timezone.utc)):
    report = _report()
    policy = _policy()
    gate = evaluate_evidence_policy(policy, report)
    return apply_evidence_exceptions(
        gate,
        parse_evidence_exceptions(document),
        policy,
        report,
        now=now,
    )


def test_exact_active_exception_consumes_only_named_violation():
    report = _report()
    result = _apply(_document())

    assert result.gate.passed
    assert result.audit == (
        result.audit[0],
    )
    assert result.audit[0].state is ExceptionAuditState.CONSUMED
    assert report.resolutions[0].verdict is EndpointVerdict.UNGUARDED


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "POST"),
        ("path", "/admins"),
        ("adapter_id", "other"),
        ("adapter_version", "0.2.0"),
        ("capability", "other_capability"),
        ("maturity", "experimental"),
        ("endpoint_fingerprint", "0" * 64),
        ("violation", "unresolved"),
        ("policy_id", "other.policy"),
    ],
)
def test_identity_mismatch_is_unmatched_and_fails_closed(field: str, value: str):
    document = _document(**{field: value})
    if field == "policy_id":
        document["exceptions"][0]["authorizing_policy_id"] = value
    result = _apply(document)

    assert not result.gate.passed
    assert result.audit[0].state is ExceptionAuditState.UNMATCHED
    assert {item.subject_id for item in result.gate.violations} == {"exceptions", "fact:route"}


@pytest.mark.parametrize(
    ("now", "state"),
    [
        (datetime(2026, 8, 1, tzinfo=timezone.utc), ExceptionAuditState.EXPIRED),
        (datetime(2026, 6, 30, tzinfo=timezone.utc), ExceptionAuditState.INVALID),
    ],
)
def test_expired_or_not_yet_created_exception_fails_closed(now: datetime, state: ExceptionAuditState):
    result = _apply(_document(), now)

    assert not result.gate.passed
    assert result.audit[0].state is state


def test_review_date_is_due_at_utc_date_boundary():
    document = _document()
    document["exceptions"][0]["expires_on"] = None
    document["exceptions"][0]["review_on"] = "2026-07-16"

    result = _apply(document, datetime(2026, 7, 15, 20, tzinfo=timezone.utc))

    assert result.audit[0].state is ExceptionAuditState.CONSUMED
    result = _apply(document, datetime(2026, 7, 16, tzinfo=timezone.utc))
    assert result.audit[0].state is ExceptionAuditState.REVIEW_DUE


def test_naive_clock_is_rejected():
    with pytest.raises(EvidenceExceptionError, match="timezone-aware"):
        _apply(_document(), datetime(2026, 7, 16))


def test_schema_rejects_unknown_fields_versions_and_bad_dates():
    for mutate in (
        lambda document: document.update({"legacy_baseline": []}),
        lambda document: document.update({"schema_version": "2.0"}),
        lambda document: document["exceptions"][0].update({"created_on": "16-07-2026"}),
    ):
        document = _document()
        mutate(document)
        with pytest.raises(EvidenceExceptionError, match="invalid evidence exceptions"):
            parse_evidence_exceptions(document)


def test_duplicate_ids_or_identities_are_rejected():
    document = _document()
    duplicate = dict(document["exceptions"][0])
    duplicate["id"] = "exception.other"
    document["exceptions"].append(duplicate)

    with pytest.raises(EvidenceExceptionError, match="identities must be unique"):
        parse_evidence_exceptions(document)


def test_explicit_replacement_requires_new_id_and_known_target():
    exceptions = parse_evidence_exceptions(_document())
    replacement = replace(
        exceptions.exceptions[0],
        id="exception.admin.v2",
        reference="SEC-456",
        created_on=date(2026, 7, 16),
        expires_on=date(2026, 9, 1),
    )

    replaced = replace_evidence_exception(exceptions, "exception.admin", replacement)

    assert [item.id for item in replaced.exceptions] == ["exception.admin.v2"]
    with pytest.raises(EvidenceExceptionError, match="new stable ID"):
        replace_evidence_exception(exceptions, "exception.admin", exceptions.exceptions[0])


def test_exception_values_are_immutable():
    exception = parse_evidence_exceptions(_document()).exceptions[0]

    with pytest.raises(FrozenInstanceError):
        exception.owner = "other"  # type: ignore[misc]


def test_non_endpoint_policy_failure_cannot_be_suppressed():
    report = replace(_report(), capabilities=())
    policy = _policy()
    gate = evaluate_evidence_policy(policy, report)

    result = apply_evidence_exceptions(
        gate,
        parse_evidence_exceptions(_document()),
        policy,
        report,
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert result.audit[0].state is ExceptionAuditState.UNMATCHED
    assert any(item.kind is GateIssueKind.EXCEPTION_AUDIT for item in result.gate.violations)
