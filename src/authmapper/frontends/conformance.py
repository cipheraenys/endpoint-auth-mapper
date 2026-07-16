"""Framework-neutral applicability and declaration ownership conformance."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from authmapper.core.v2 import (
    ApplicabilityResult,
    ApplicabilityState,
    OwnershipDecision,
    OwnershipState,
)


class ClaimRole(str, Enum):
    """Whether a candidate can own a declaration or supplies metadata only."""

    OWNER = "owner"
    METADATA = "metadata"


@dataclass(frozen=True, slots=True)
class OwnershipClaim:
    """One adapter candidate for a declaration collision group."""

    subject_id: str
    collision_group: str
    applicability: ApplicabilityResult
    evidence_ids: tuple[str, ...]
    role: ClaimRole = ClaimRole.OWNER


def resolve_ownership(claims: tuple[OwnershipClaim, ...]) -> tuple[OwnershipDecision, ...]:
    """Resolve deterministic ownership without framework-specific policy."""
    normalized = _normalized_claims(claims)
    decisions: list[OwnershipDecision] = []
    groups: dict[tuple[str, str], list[OwnershipClaim]] = {}
    for claim in normalized:
        groups.setdefault((claim.subject_id, claim.collision_group), []).append(claim)

    for group_claims in groups.values():
        owners = [claim for claim in group_claims if claim.role is ClaimRole.OWNER]
        contenders = [
            claim
            for claim in owners
            if claim.applicability.state in {ApplicabilityState.ACTIVE, ApplicabilityState.AMBIGUOUS}
        ]
        active_adapters = {claim.applicability.adapter_id for claim in contenders}
        ambiguous = len(active_adapters) > 1 or any(
            claim.applicability.state is ApplicabilityState.AMBIGUOUS for claim in contenders
        )
        selected_adapter = (
            next(iter(active_adapters))
            if len(active_adapters) == 1 and not ambiguous
            else None
        )

        for claim in group_claims:
            adapter_id = claim.applicability.adapter_id
            if claim.role is ClaimRole.METADATA:
                state = OwnershipState.REJECTED
                reason = "metadata does not own declarations"
            elif claim.applicability.state is ApplicabilityState.INACTIVE:
                state = OwnershipState.REJECTED
                reason = "adapter applicability is inactive"
            elif ambiguous:
                state = OwnershipState.AMBIGUOUS
                reason = "competing ownership provenance is ambiguous"
            elif adapter_id == selected_adapter:
                state = OwnershipState.SELECTED
                reason = "active applicability provenance uniquely owns declaration"
            else:
                state = OwnershipState.REJECTED
                reason = "another active adapter uniquely owns declaration"
            decisions.append(
                OwnershipDecision(
                    claim.subject_id,
                    claim.collision_group,
                    adapter_id,
                    state,
                    claim.evidence_ids,
                    reason,
                )
            )
    result = tuple(sorted(decisions, key=_decision_key))
    _validate_decisions(result)
    return result


def _normalized_claims(claims: tuple[OwnershipClaim, ...]) -> tuple[OwnershipClaim, ...]:
    merged: dict[tuple[str, str, str], OwnershipClaim] = {}
    for claim in claims:
        if not isinstance(claim.role, ClaimRole):
            raise ValueError("ownership claim role must use ClaimRole")
        subject_id = _normalize_identity(claim.subject_id)
        collision_group = _normalize_identity(claim.collision_group)
        if not subject_id or not collision_group:
            raise ValueError("ownership subject and collision group must not be empty")
        available = {item.id for item in claim.applicability.evidence}
        if not set(claim.evidence_ids) <= available:
            raise ValueError("ownership claim references unknown activation evidence")
        evidence_ids = tuple(sorted(set(claim.evidence_ids)))
        if (
            claim.role is ClaimRole.OWNER
            and claim.applicability.state is not ApplicabilityState.INACTIVE
            and not evidence_ids
        ):
            raise ValueError("active ownership claim requires activation evidence")
        key = (subject_id, collision_group, claim.applicability.adapter_id)
        previous = merged.get(key)
        if previous is not None:
            if previous.role is not claim.role:
                raise ValueError("duplicate ownership claims disagree on role")
            if previous.applicability.state is not claim.applicability.state:
                raise ValueError("duplicate ownership claims disagree on applicability")
            evidence_ids = tuple(sorted(set((*previous.evidence_ids, *evidence_ids))))
            evidence = {
                item.id: item
                for item in (*previous.applicability.evidence, *claim.applicability.evidence)
            }
            applicability = ApplicabilityResult(
                claim.applicability.adapter_id,
                claim.applicability.state,
                tuple(evidence[key] for key in sorted(evidence)),
                tuple(sorted(set((*previous.applicability.reasons, *claim.applicability.reasons)))),
            )
        else:
            applicability = claim.applicability
        merged[key] = OwnershipClaim(
            subject_id,
            collision_group,
            applicability,
            evidence_ids,
            claim.role,
        )
    return tuple(sorted(merged.values(), key=_claim_key))


def _validate_decisions(decisions: tuple[OwnershipDecision, ...]) -> None:
    selected: dict[tuple[str, str], int] = {}
    states: dict[tuple[str, str], set[OwnershipState]] = {}
    for decision in decisions:
        key = (decision.subject_id, decision.collision_group)
        states.setdefault(key, set()).add(decision.state)
        if decision.state is OwnershipState.SELECTED:
            selected[key] = selected.get(key, 0) + 1
    if any(count > 1 for count in selected.values()):
        raise ValueError("a declaration collision group cannot have multiple selected owners")
    if any(
        OwnershipState.SELECTED in values and OwnershipState.AMBIGUOUS in values
        for values in states.values()
    ):
        raise ValueError("ambiguous ownership cannot include a selected owner")


def _normalize_identity(value: str) -> str:
    normalized = value.replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized.replace("/./", "/").removeprefix("./").rstrip("/")


def _claim_key(claim: OwnershipClaim) -> tuple[str, str, str, str]:
    return (
        claim.subject_id,
        claim.collision_group,
        claim.applicability.adapter_id,
        claim.role.value,
    )


def _decision_key(decision: OwnershipDecision) -> tuple[str, str, str, str]:
    return (
        decision.subject_id,
        decision.collision_group,
        decision.adapter_id,
        decision.state.value,
    )
