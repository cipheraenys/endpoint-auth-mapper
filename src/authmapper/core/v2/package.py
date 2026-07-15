"""Package maturity, applicability, collision, and ownership contracts."""

from __future__ import annotations

import re
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
class ReportedCapability:
    adapter_id: str
    adapter_version: str
    capability: str
    maturity: CapabilityMaturity
    applicability: ApplicabilityState

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", self.adapter_id):
            raise ValueError(f"invalid reported adapter ID: {self.adapter_id!r}")
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", self.adapter_version):
            raise ValueError(f"invalid reported adapter version: {self.adapter_version!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.capability):
            raise ValueError(f"invalid reported capability: {self.capability!r}")
        if not isinstance(self.maturity, CapabilityMaturity):
            raise ValueError("reported maturity must use CapabilityMaturity")
        if not isinstance(self.applicability, ApplicabilityState):
            raise ValueError("reported applicability must use ApplicabilityState")


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
