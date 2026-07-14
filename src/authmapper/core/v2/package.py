"""Package maturity, applicability, collision, and ownership contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .model import SourceSpan


class PackageLifecycle(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class CapabilityMaturity(str, Enum):
    UNAVAILABLE = "unavailable"
    EXPERIMENTAL = "experimental"
    VERIFIED = "verified"


class ApplicabilityState(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    AMBIGUOUS = "ambiguous"


class OwnershipState(str, Enum):
    SELECTED = "selected"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class ActivationEvidence:
    id: str
    kind: str
    value: str
    span: SourceSpan | None = None


@dataclass(frozen=True, slots=True)
class ApplicabilityResult:
    adapter_id: str
    state: ApplicabilityState
    evidence: tuple[ActivationEvidence, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnershipDecision:
    subject_id: str
    collision_group: str
    adapter_id: str
    state: OwnershipState
    evidence_ids: tuple[str, ...]
    reason: str
