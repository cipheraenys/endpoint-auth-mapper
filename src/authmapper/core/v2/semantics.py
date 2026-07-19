"""Declarative semantic recognition contracts applied after extraction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .model import SubjectKind


class SemanticKind(str, Enum):
    AUTH_ENFORCEMENT = "auth_enforcement"
    AUTH_AMBIGUITY = "auth_ambiguity"
    PUBLIC_OVERRIDE = "public_override"
    IDENTITY_USE = "identity_use"
    SESSION_PRESENCE = "session_presence"
    ROUTING_PREDICATE = "routing_predicate"
    WEAK_INDICATOR = "weak_indicator"


@dataclass(frozen=True, slots=True)
class SemanticRule:
    id: str
    kind: SemanticKind
    subject_kinds: tuple[SubjectKind, ...]
    symbol: str
    required_scope: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.symbol or not self.subject_kinds:
            raise ValueError("semantic rule ID, symbol, and subject kinds are required")
        if tuple(sorted(set(self.subject_kinds), key=lambda item: item.value)) != self.subject_kinds:
            raise ValueError("semantic rule subject kinds must be unique and ordered")
