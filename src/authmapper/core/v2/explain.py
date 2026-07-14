"""Stable internal view model for adapter activation explainability."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from .model import Diagnostic
from .package import ApplicabilityResult, CapabilityMaturity, OwnershipDecision

EXPLAIN_ADAPTER_VIEW_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class CapabilityExplanation:
    capability: str
    maturity: CapabilityMaturity


@dataclass(frozen=True, slots=True)
class AdapterExplanation:
    adapter_id: str
    adapter_version: str
    applicability: ApplicabilityResult
    ownership_decisions: tuple[OwnershipDecision, ...]
    capabilities: tuple[CapabilityExplanation, ...]
    applied_rule_ids: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]

    def __post_init__(self) -> None:
        if self.adapter_id != self.applicability.adapter_id:
            raise ValueError("explanation adapter must match applicability adapter")
        for values, label in (
            (tuple(item.subject_id for item in self.ownership_decisions), "ownership decisions"),
            (tuple(item.capability for item in self.capabilities), "capabilities"),
            (self.applied_rule_ids, "applied rule IDs"),
            (tuple(item.id for item in self.diagnostics), "diagnostics"),
        ):
            if values != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique and ordered")


def explain_adapter_document(explanation: AdapterExplanation) -> dict[str, Any]:
    """Return deterministic data suitable for a future ``explain-adapter`` CLI."""
    return {
        "view_version": EXPLAIN_ADAPTER_VIEW_VERSION,
        **_normalize(asdict(explanation)),
    }


def render_adapter_explanation(explanation: AdapterExplanation) -> str:
    return json.dumps(explain_adapter_document(explanation), indent=2, sort_keys=True)


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value
