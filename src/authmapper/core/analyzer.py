"""Analyzer interface and implementations."""

from __future__ import annotations

from typing import Protocol

from .model import Finding
from .rulepack import RulePack
from .walker import SourceFile


class Analyzer(Protocol):
    def analyze(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        ...
