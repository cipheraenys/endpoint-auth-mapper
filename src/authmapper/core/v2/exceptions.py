"""Exact, expiring evidence exceptions with deterministic audit states."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from enum import Enum
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .contracts import (
    ENDPOINT_FINGERPRINT_ALGORITHM,
    EVIDENCE_EXCEPTION_SCHEMA_ID,
    EXCEPTION_SCHEMA_VERSION,
)
from .fingerprint import endpoint_fingerprint
from .model import Fact
from .package import ApplicabilityState, CapabilityMaturity
from .policy import (
    EvidenceGateResult,
    EvidencePolicy,
    GateDisposition,
    GateIssue,
    GateIssueKind,
)
from .report import EvidenceReport


class EvidenceExceptionError(ValueError):
    """Raised when an exception document or evaluation input is invalid."""


class ExceptionAuditState(str, Enum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVIEW_DUE = "review_due"
    UNMATCHED = "unmatched"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class ExceptionIdentity:
    method: str
    path: str
    adapter_id: str
    adapter_version: str
    capability: str
    maturity: CapabilityMaturity
    endpoint_fingerprint_algorithm: str
    endpoint_fingerprint: str
    violation: GateIssueKind
    policy_id: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Z]+", self.method) or not self.path.startswith("/"):
            raise EvidenceExceptionError("exception route identity must use normalized method and path")
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", self.adapter_id):
            raise EvidenceExceptionError(f"invalid exception adapter ID: {self.adapter_id!r}")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", self.adapter_version):
            raise EvidenceExceptionError(f"invalid exception adapter version: {self.adapter_version!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.capability):
            raise EvidenceExceptionError(f"invalid exception capability: {self.capability!r}")
        if not isinstance(self.maturity, CapabilityMaturity):
            raise EvidenceExceptionError("exception maturity must use CapabilityMaturity")
        if self.maturity is CapabilityMaturity.UNAVAILABLE:
            raise EvidenceExceptionError("unavailable cannot identify an exception capability")
        if self.endpoint_fingerprint_algorithm != ENDPOINT_FINGERPRINT_ALGORITHM:
            raise EvidenceExceptionError("unsupported endpoint fingerprint algorithm")
        if not re.fullmatch(r"[a-f0-9]{64}", self.endpoint_fingerprint):
            raise EvidenceExceptionError("invalid endpoint fingerprint")
        if not isinstance(self.violation, GateIssueKind) or self.violation not in {
            GateIssueKind.UNGUARDED,
            GateIssueKind.UNRESOLVED,
        }:
            raise EvidenceExceptionError("exception cannot suppress this violation kind")
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.policy_id):
            raise EvidenceExceptionError(f"invalid exception policy ID: {self.policy_id!r}")


@dataclass(frozen=True, slots=True)
class EvidenceException:
    id: str
    reason: str
    owner: str
    reference: str
    created_on: date
    expires_on: date | None
    review_on: date | None
    authorizing_policy_id: str
    identity: ExceptionIdentity

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.id):
            raise EvidenceExceptionError(f"invalid exception ID: {self.id!r}")
        if not all((self.reason.strip(), self.owner.strip(), self.reference.strip())):
            raise EvidenceExceptionError(f"{self.id}: reason, owner, and reference are required")
        if not all(isinstance(item, date) for item in (self.created_on,)):
            raise EvidenceExceptionError(f"{self.id}: creation date is invalid")
        if self.expires_on is None and self.review_on is None:
            raise EvidenceExceptionError(f"{self.id}: expiry or review date is required")
        for boundary in (self.expires_on, self.review_on):
            if boundary is not None and boundary < self.created_on:
                raise EvidenceExceptionError(f"{self.id}: boundary date precedes creation")
        if self.authorizing_policy_id != self.identity.policy_id:
            raise EvidenceExceptionError(f"{self.id}: authorizing policy must match identity policy")


@dataclass(frozen=True, slots=True)
class EvidenceExceptions:
    exceptions: tuple[EvidenceException, ...]
    schema_version: str = EXCEPTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EXCEPTION_SCHEMA_VERSION:
            raise EvidenceExceptionError(f"unsupported exception schema version: {self.schema_version!r}")
        if not isinstance(self.exceptions, tuple) or not all(
            isinstance(item, EvidenceException) for item in self.exceptions
        ):
            raise EvidenceExceptionError("exceptions must be an immutable tuple")
        identifiers = tuple(item.id for item in self.exceptions)
        if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
            raise EvidenceExceptionError("exception IDs must be unique and ordered")
        identities = tuple(item.identity for item in self.exceptions)
        if len(identities) != len(set(identities)):
            raise EvidenceExceptionError("exception identities must be unique")


@dataclass(frozen=True, slots=True)
class ExceptionAudit:
    exception_id: str
    state: ExceptionAuditState
    issue_subject_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ExceptionResult:
    gate: EvidenceGateResult
    audit: tuple[ExceptionAudit, ...]


def load_evidence_exceptions(path: Path) -> EvidenceExceptions:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceExceptionError(f"cannot load evidence exceptions '{path}': {exc}") from exc
    if not isinstance(document, dict):
        raise EvidenceExceptionError("exception document must be an object")
    return parse_evidence_exceptions(document)


def parse_evidence_exceptions(document: Mapping[str, Any]) -> EvidenceExceptions:
    schema = json.loads(
        files("authmapper.schemas").joinpath("evidence-exceptions-1.0.schema.json").read_text(encoding="utf-8")
    )
    if schema.get("$id") != EVIDENCE_EXCEPTION_SCHEMA_ID:
        raise EvidenceExceptionError("bundled exception schema ID is incompatible")
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(dict(document)),
        key=lambda item: list(item.path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise EvidenceExceptionError(f"invalid evidence exceptions at {location}: {error.message}")
    parsed = tuple(_parse_exception(item) for item in sorted(document["exceptions"], key=lambda item: item["id"]))
    return EvidenceExceptions(parsed, document["schema_version"])


def apply_evidence_exceptions(
    gate: EvidenceGateResult,
    exceptions: EvidenceExceptions,
    policy: EvidencePolicy,
    report: EvidenceReport,
    *,
    now: datetime,
) -> ExceptionResult:
    if gate.policy_id != policy.id:
        raise EvidenceExceptionError("gate and exception policy identities must match")
    endpoints = {
        fact.id: fact
        for fact in report.graph.facts
        if fact.method is not None and fact.path is not None
    }
    today = _utc_date(now)
    remaining = list(gate.violations)
    audit: list[ExceptionAudit] = []
    for exception in exceptions.exceptions:
        boundary_state = _boundary_state(exception, today)
        if boundary_state is not None:
            audit.append(ExceptionAudit(exception.id, boundary_state, None, f"exception is {boundary_state.value}"))
            continue
        matches = [
            issue
            for issue in remaining
            if _matches(exception, issue, gate.policy_id, policy, report, endpoints)
        ]
        if len(matches) != 1:
            audit.append(
                ExceptionAudit(
                    exception.id,
                    ExceptionAuditState.UNMATCHED if not matches else ExceptionAuditState.INVALID,
                    None,
                    "exception must match exactly one named violation",
                )
            )
            continue
        issue = matches[0]
        remaining.remove(issue)
        audit.append(
            ExceptionAudit(
                exception.id,
                ExceptionAuditState.CONSUMED,
                issue.subject_id,
                "named violation suppressed",
            )
        )

    ordered_audit = tuple(sorted(audit, key=lambda item: item.exception_id))
    failed_states = {
        ExceptionAuditState.EXPIRED,
        ExceptionAuditState.REVIEW_DUE,
        ExceptionAuditState.UNMATCHED,
        ExceptionAuditState.INVALID,
    }
    if any(item.state in failed_states for item in ordered_audit):
        remaining.append(
            GateIssue(
                GateIssueKind.EXCEPTION_AUDIT,
                GateDisposition.VIOLATION,
                "exceptions",
                None,
                "exception audit failed closed",
            )
        )
    ordered_violations = tuple(sorted(remaining, key=_issue_key))
    return ExceptionResult(replace(gate, violations=ordered_violations), ordered_audit)


def replace_evidence_exception(
    exceptions: EvidenceExceptions,
    replaced_id: str,
    replacement: EvidenceException,
) -> EvidenceExceptions:
    """Explicitly replace one exception; never infer identity migration."""
    if replacement.id == replaced_id:
        raise EvidenceExceptionError("replacement must use a new stable ID")
    if replaced_id not in {item.id for item in exceptions.exceptions}:
        raise EvidenceExceptionError(f"unknown replaced exception ID: {replaced_id!r}")
    values = tuple(item for item in exceptions.exceptions if item.id != replaced_id) + (replacement,)
    return EvidenceExceptions(tuple(sorted(values, key=lambda item: item.id)), exceptions.schema_version)


def _parse_exception(document: Mapping[str, Any]) -> EvidenceException:
    identity = document["identity"]
    return EvidenceException(
        document["id"],
        document["reason"],
        document["owner"],
        document["reference"],
        date.fromisoformat(document["created_on"]),
        date.fromisoformat(document["expires_on"]) if document["expires_on"] else None,
        date.fromisoformat(document["review_on"]) if document["review_on"] else None,
        document["authorizing_policy_id"],
        ExceptionIdentity(
            identity["method"],
            identity["path"],
            identity["adapter_id"],
            identity["adapter_version"],
            identity["capability"],
            CapabilityMaturity(identity["maturity"]),
            identity["endpoint_fingerprint_algorithm"],
            identity["endpoint_fingerprint"],
            GateIssueKind(identity["violation"]),
            identity["policy_id"],
        ),
    )


def _utc_date(value: datetime) -> date:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceExceptionError("exception evaluation clock must be timezone-aware")
    return value.astimezone(timezone.utc).date()


def _boundary_state(exception: EvidenceException, today: date) -> ExceptionAuditState | None:
    if today < exception.created_on:
        return ExceptionAuditState.INVALID
    if exception.expires_on is not None and today >= exception.expires_on:
        return ExceptionAuditState.EXPIRED
    if exception.review_on is not None and today >= exception.review_on:
        return ExceptionAuditState.REVIEW_DUE
    return None


def _matches(
    exception: EvidenceException,
    issue: GateIssue,
    policy_id: str,
    policy: EvidencePolicy,
    report: EvidenceReport,
    endpoints: Mapping[str, Fact],
) -> bool:
    identity = exception.identity
    endpoint = endpoints.get(issue.subject_id)
    if endpoint is None or issue.kind not in {GateIssueKind.UNGUARDED, GateIssueKind.UNRESOLVED}:
        return False
    fingerprint = endpoint_fingerprint(endpoint)
    requirement_matches = any(
        requirement.adapter_id == identity.adapter_id
        and requirement.adapter_version == identity.adapter_version
        and requirement.capability == identity.capability
        and requirement.minimum_maturity is identity.maturity
        for requirement in policy.requirements
    )
    provenance = {item.id: item for item in report.graph.capability_provenance}
    coverage_matches = any(
        record.target_id == endpoint.id
        and record.capability.value == identity.capability
        and provenance[record.provenance_id].adapter_id == identity.adapter_id
        and provenance[record.provenance_id].adapter_version == identity.adapter_version
        for record in report.graph.coverage
    )
    capability_matches = any(
        item.adapter_id == identity.adapter_id
        and item.adapter_version == identity.adapter_version
        and item.capability == identity.capability
        and item.maturity is identity.maturity
        and item.applicability is ApplicabilityState.ACTIVE
        for item in report.capabilities
    )
    return (
        identity.policy_id == policy_id
        and identity.violation is issue.kind
        and identity.method == endpoint.method
        and identity.path == endpoint.path
        and identity.endpoint_fingerprint_algorithm == ENDPOINT_FINGERPRINT_ALGORITHM
        and identity.endpoint_fingerprint == fingerprint.value
        and requirement_matches
        and coverage_matches
        and capability_matches
    )


def _issue_key(issue: GateIssue) -> tuple[str, str, str, str]:
    return issue.kind.value, issue.subject_id, issue.requirement_id or "", issue.reason
