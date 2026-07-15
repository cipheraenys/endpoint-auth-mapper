"""Strict versioned evidence policy and deterministic gate evaluation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .contracts import EVIDENCE_POLICY_SCHEMA_ID, EVIDENCE_POLICY_SCHEMA_VERSION
from .model import Capability, CoverageStatus, DiagnosticLevel, EndpointVerdict
from .package import ApplicabilityState, CapabilityMaturity, ReportedCapability
from .report import EvidenceReport
from .resolver import resolve_endpoints


class EvidencePolicyError(ValueError):
    """Raised when an evidence policy is invalid or incompatible."""


class GateDisposition(str, Enum):
    VIOLATION = "violation"
    ADVISORY = "advisory"


class GateIssueKind(str, Enum):
    ANALYSIS_ERROR = "analysis_error"
    UNGUARDED = "unguarded"
    UNRESOLVED = "unresolved"
    PUBLIC_DECLARATION = "public_declaration"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    CAPABILITY_REQUIREMENT = "capability_requirement"


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    id: str
    adapter_id: str
    adapter_version: str
    capability: str
    minimum_maturity: CapabilityMaturity

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.id):
            raise EvidencePolicyError(f"invalid evidence policy requirement ID: {self.id!r}")
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", self.adapter_id):
            raise EvidencePolicyError(f"invalid required adapter ID: {self.adapter_id!r}")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", self.adapter_version):
            raise EvidencePolicyError(f"invalid required adapter version: {self.adapter_version!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.capability):
            raise EvidencePolicyError(f"invalid required capability: {self.capability!r}")
        if not isinstance(self.minimum_maturity, CapabilityMaturity):
            raise EvidencePolicyError("required capability maturity must use CapabilityMaturity")
        if self.minimum_maturity is CapabilityMaturity.UNAVAILABLE:
            raise EvidencePolicyError("unavailable cannot be a required capability maturity")


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    id: str
    fail_on_unguarded: bool
    fail_on_unresolved: bool
    fail_on_incomplete_coverage: bool
    requirements: tuple[CapabilityRequirement, ...]
    schema_version: str = EVIDENCE_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EVIDENCE_POLICY_SCHEMA_VERSION:
            raise EvidencePolicyError(f"unsupported evidence policy version: {self.schema_version!r}")
        if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", self.id):
            raise EvidencePolicyError(f"invalid evidence policy ID: {self.id!r}")
        for name in ("fail_on_unguarded", "fail_on_unresolved", "fail_on_incomplete_coverage"):
            if not isinstance(getattr(self, name), bool):
                raise EvidencePolicyError(f"{name} must be boolean")
        if not isinstance(self.requirements, tuple) or not self.requirements:
            raise EvidencePolicyError("evidence policy requirements must be a non-empty tuple")
        if not all(isinstance(item, CapabilityRequirement) for item in self.requirements):
            raise EvidencePolicyError("invalid evidence policy capability requirement")
        rule_ids = tuple(item.id for item in self.requirements)
        if len(rule_ids) != len(set(rule_ids)):
            raise EvidencePolicyError("evidence policy requirement IDs must be unique")
        targets = tuple(
            (item.adapter_id, item.adapter_version, item.capability) for item in self.requirements
        )
        if len(targets) != len(set(targets)):
            raise EvidencePolicyError("evidence policy capability requirements must be unique")
        if self.requirements != tuple(sorted(self.requirements, key=lambda item: item.id)):
            raise EvidencePolicyError("evidence policy requirements must be ordered by ID")


@dataclass(frozen=True, slots=True)
class GateIssue:
    kind: GateIssueKind
    disposition: GateDisposition
    subject_id: str
    requirement_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class EvidenceGateResult:
    policy_id: str
    policy_schema_version: str
    violations: tuple[GateIssue, ...]
    advisories: tuple[GateIssue, ...]

    @property
    def passed(self) -> bool:
        return not self.violations


def load_evidence_policy(path: Path) -> EvidencePolicy:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidencePolicyError(f"cannot load evidence policy '{path}': {exc}") from exc
    if not isinstance(document, dict):
        raise EvidencePolicyError("evidence policy document must be an object")
    return parse_evidence_policy(document)


def parse_evidence_policy(document: Mapping[str, Any]) -> EvidencePolicy:
    schema = json.loads(
        files("authmapper.schemas").joinpath("evidence-policy-1.0.schema.json").read_text(encoding="utf-8")
    )
    if schema.get("$id") != EVIDENCE_POLICY_SCHEMA_ID:
        raise EvidencePolicyError("bundled evidence policy schema ID is incompatible")
    errors = sorted(Draft202012Validator(schema).iter_errors(dict(document)), key=lambda item: list(item.path))
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise EvidencePolicyError(f"invalid evidence policy at {location}: {error.message}")

    requirements = tuple(
        CapabilityRequirement(
            item["id"],
            item["adapter_id"],
            item["adapter_version"],
            item["capability"],
            CapabilityMaturity(item["minimum_maturity"]),
        )
        for item in sorted(document["requirements"], key=lambda item: item["id"])
    )
    return EvidencePolicy(
        id=document["id"],
        fail_on_unguarded=document["fail_on_unguarded"],
        fail_on_unresolved=document["fail_on_unresolved"],
        fail_on_incomplete_coverage=document["fail_on_incomplete_coverage"],
        requirements=requirements,
        schema_version=document["schema_version"],
    )


def evaluate_evidence_policy(
    policy: EvidencePolicy,
    report: EvidenceReport,
) -> EvidenceGateResult:
    """Evaluate one validated v2 result without mutating evidence or policy."""
    if not isinstance(report, EvidenceReport):
        raise EvidencePolicyError("evidence policy requires a v2 EvidenceReport input")
    report.graph.validate()
    if report.resolutions != resolve_endpoints(report.graph):
        raise EvidencePolicyError("evidence report resolutions do not match the validated evidence graph")
    capability_by_key = _validated_capabilities(report.capabilities)
    report_capabilities: set[tuple[str, str, str]] = set()
    for item in report.graph.capability_provenance:
        report_capabilities.add((item.adapter_id, item.adapter_version, item.capability.value))
    maturity_by_requirement: dict[str, CapabilityMaturity] = {}
    issues = [
        GateIssue(
            GateIssueKind.ANALYSIS_ERROR,
            GateDisposition.VIOLATION,
            diagnostic.id,
            None,
            f"analysis error {diagnostic.code}: {diagnostic.message}",
        )
        for diagnostic in report.graph.diagnostics
        if diagnostic.level is DiagnosticLevel.ERROR
    ]

    for requirement in policy.requirements:
        failure = _requirement_failure(
            requirement,
            report.capabilities,
            capability_by_key,
            report_capabilities,
        )
        if failure is not None:
            issues.append(
                GateIssue(
                    GateIssueKind.CAPABILITY_REQUIREMENT,
                    GateDisposition.VIOLATION,
                    requirement.adapter_id,
                    requirement.id,
                    failure,
                )
            )
            continue
        maturity_by_requirement[requirement.id] = capability_by_key[
            (requirement.adapter_id, requirement.adapter_version, requirement.capability)
        ].maturity

    selected_capabilities = {
        (requirement.adapter_id, requirement.adapter_version, requirement.capability)
        for requirement in policy.requirements
        if maturity_by_requirement.get(requirement.id) is CapabilityMaturity.VERIFIED
    }
    verified_endpoints = _verified_assurance_endpoints(report, selected_capabilities)
    for resolution in report.resolutions:
        maturity_is_verified = resolution.endpoint_id in verified_endpoints
        if (
            resolution.verdict is EndpointVerdict.GUARDED
            and maturity_is_verified
            and not _has_selected_auth_proof(report, resolution.proof_ids, selected_capabilities)
        ):
            issues.append(
                GateIssue(
                    GateIssueKind.CAPABILITY_REQUIREMENT,
                    GateDisposition.VIOLATION,
                    resolution.endpoint_id,
                    None,
                    "guard proof lacks selected verified auth capability provenance",
                )
            )
        elif resolution.verdict is EndpointVerdict.UNGUARDED:
            issues.append(
                GateIssue(
                    GateIssueKind.UNGUARDED,
                    GateDisposition.VIOLATION
                    if policy.fail_on_unguarded and maturity_is_verified
                    else GateDisposition.ADVISORY,
                    resolution.endpoint_id,
                    None,
                    "verified capability resolved endpoint as UNGUARDED"
                    if maturity_is_verified
                    else "non-verified capability result is advisory",
                )
            )
        elif resolution.verdict is EndpointVerdict.UNRESOLVED:
            issues.append(
                GateIssue(
                    GateIssueKind.UNRESOLVED,
                    GateDisposition.VIOLATION
                    if policy.fail_on_unresolved and maturity_is_verified
                    else GateDisposition.ADVISORY,
                    resolution.endpoint_id,
                    None,
                    "verified capability could not resolve endpoint protection"
                    if maturity_is_verified
                    else "non-verified capability result is advisory",
                )
            )
        elif resolution.verdict is EndpointVerdict.DECLARED_PUBLIC:
            issues.append(
                GateIssue(
                    GateIssueKind.PUBLIC_DECLARATION,
                    GateDisposition.ADVISORY,
                    resolution.endpoint_id,
                    None,
                    "public declaration is advisory without verified proof provenance",
                )
            )
            if maturity_is_verified and policy.fail_on_unguarded:
                issues.append(
                    GateIssue(
                        GateIssueKind.UNGUARDED,
                        GateDisposition.VIOLATION,
                        resolution.endpoint_id,
                        None,
                        "public declaration without verified proof provenance cannot bypass verified gate",
                    )
                )

    provenance = {item.id: item for item in report.graph.capability_provenance}
    required_targets = {
        (item.adapter_id, item.adapter_version, item.capability): item
        for item in policy.requirements
        if maturity_by_requirement.get(item.id) is CapabilityMaturity.VERIFIED
        and item.capability in {capability.value for capability in Capability}
    }
    owned_targets = {
        (record.target_id, source.adapter_id, source.adapter_version)
        for record in report.graph.coverage
        for source in (provenance[record.provenance_id],)
    }
    seen_coverage: set[tuple[str, str]] = set()
    for record in report.graph.coverage:
        source = provenance[record.provenance_id]
        matched_requirement = required_targets.get(
            (source.adapter_id, source.adapter_version, record.capability.value)
        )
        if matched_requirement is None:
            continue
        seen_coverage.add((record.target_id, matched_requirement.id))
        if record.status is not CoverageStatus.ANALYZED:
            issues.append(
                GateIssue(
                    GateIssueKind.INCOMPLETE_COVERAGE,
                    GateDisposition.VIOLATION
                    if policy.fail_on_incomplete_coverage
                    else GateDisposition.ADVISORY,
                    record.id,
                    matched_requirement.id,
                    f"required verified coverage is {record.status.value}",
                )
            )

    for resolution in report.resolutions:
        for requirement in required_targets.values():
            if (
                resolution.endpoint_id,
                requirement.adapter_id,
                requirement.adapter_version,
            ) not in owned_targets:
                continue
            if (resolution.endpoint_id, requirement.id) not in seen_coverage:
                issues.append(
                    GateIssue(
                        GateIssueKind.INCOMPLETE_COVERAGE,
                        GateDisposition.VIOLATION
                        if policy.fail_on_incomplete_coverage
                        else GateDisposition.ADVISORY,
                        resolution.endpoint_id,
                        requirement.id,
                        "required verified coverage record is missing",
                    )
                )

    ordered = sorted(
        issues,
        key=lambda item: (item.kind.value, item.subject_id, item.requirement_id or "", item.reason),
    )
    return EvidenceGateResult(
        policy.id,
        policy.schema_version,
        tuple(item for item in ordered if item.disposition is GateDisposition.VIOLATION),
        tuple(item for item in ordered if item.disposition is GateDisposition.ADVISORY),
    )


def _validated_capabilities(
    capabilities: tuple[ReportedCapability, ...],
) -> dict[tuple[str, str, str], ReportedCapability]:
    keys = tuple((item.adapter_id, item.adapter_version, item.capability) for item in capabilities)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise EvidencePolicyError("reported capabilities must be unique and ordered")
    return {key: item for key, item in zip(keys, capabilities, strict=True)}


def _requirement_failure(
    requirement: CapabilityRequirement,
    capabilities: tuple[ReportedCapability, ...],
    capability_by_key: dict[tuple[str, str, str], ReportedCapability],
    report_capabilities: set[tuple[str, str, str]],
) -> str | None:
    adapter_capabilities = tuple(item for item in capabilities if item.adapter_id == requirement.adapter_id)
    if not adapter_capabilities:
        return "required adapter is missing"
    version_capabilities = tuple(
        item for item in adapter_capabilities if item.adapter_version == requirement.adapter_version
    )
    if not version_capabilities:
        return "required adapter version is incompatible"
    reported = capability_by_key.get(
        (requirement.adapter_id, requirement.adapter_version, requirement.capability)
    )
    if reported is None:
        return "required capability is missing"
    if reported.applicability is not ApplicabilityState.ACTIVE:
        return f"required adapter is {reported.applicability.value}"
    rank = {
        CapabilityMaturity.UNAVAILABLE: 0,
        CapabilityMaturity.EXPERIMENTAL: 1,
        CapabilityMaturity.VERIFIED: 2,
    }
    if rank[reported.maturity] < rank[requirement.minimum_maturity]:
        return f"required capability is {reported.maturity.value}, below {requirement.minimum_maturity.value}"
    if requirement.capability in {capability.value for capability in Capability} and (
        requirement.adapter_id,
        requirement.adapter_version,
        requirement.capability,
    ) not in report_capabilities:
        return "required capability provenance is missing from evidence report"
    return None


def _verified_assurance_endpoints(
    report: EvidenceReport,
    selected_capabilities: set[tuple[str, str, str]],
) -> set[str]:
    required = {capability.value for capability in Capability}
    selected_by_adapter: dict[tuple[str, str], set[str]] = {}
    for adapter_id, adapter_version, capability in selected_capabilities:
        selected_by_adapter.setdefault((adapter_id, adapter_version), set()).add(capability)
    verified_adapters = {
        adapter
        for adapter, capabilities in selected_by_adapter.items()
        if capabilities >= required
    }
    provenance = {item.id: item for item in report.graph.capability_provenance}
    reported_by_endpoint: dict[tuple[str, str, str], set[str]] = {}
    for coverage in report.graph.coverage:
        source = provenance[coverage.provenance_id]
        adapter = (source.adapter_id, source.adapter_version)
        if adapter not in verified_adapters:
            continue
        reported_by_endpoint.setdefault((coverage.target_id, *adapter), set()).add(coverage.capability.value)
    return {
        endpoint_id
        for (endpoint_id, _adapter_id, _adapter_version), capabilities in reported_by_endpoint.items()
        if capabilities >= required
    }


def _has_selected_auth_proof(
    report: EvidenceReport,
    proof_ids: tuple[str, ...],
    selected_capabilities: set[tuple[str, str, str]],
) -> bool:
    proofs = {item.id: item for item in report.graph.proofs}
    provenance = {item.id: item for item in report.graph.capability_provenance}
    for proof_id in proof_ids:
        proof = proofs[proof_id]
        for reference in proof.derived_from:
            source = provenance.get(reference)
            if source is not None and (
                source.adapter_id,
                source.adapter_version,
                source.capability.value,
            ) in selected_capabilities and source.capability is Capability.AUTH_ASSOCIATION:
                return True
    return False
