"""Analysis engine.

The engine is the orchestrator that ties discovery, rule packs, and
classification together into a :class:`ScanResult`. It contains the mechanical
"how" of matching, while the policy "what does this mean" lives in
:mod:`classifier`. This separation keeps the engine boring and the policy
auditable.

Guarantees upheld here:
    * read-only  — only text is inspected; nothing is imported or executed.
    * resilient  — a failure on one file is captured as a ScanError, not raised.
    * ReDoS-safe — all matching goes through :class:`SafeMatcher`.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .model import ScanResult, ScanError, Finding
from .rulepack import RulePack
from .safety import SafeMatcher
from .walker import FileWalker, SourceFile
from .analyzer import Analyzer
from .regex_analyzer import RegexAnalyzer
from .ast_analyzer import ASTAnalyzer

@dataclass(frozen=True)
class EngineConfig:
    """Tunable knobs for a run."""

    regex_timeout_seconds: float = 1.0
    max_file_bytes: int = 2 * 1024 * 1024


class Engine:
    """The analysis engine."""

    def __init__(self, rulepacks: Sequence[RulePack], config: EngineConfig | None = None) -> None:
        self._rulepacks = tuple(rulepacks)
        self._config = config or EngineConfig()
        self._matcher = SafeMatcher(self._config.regex_timeout_seconds)
        self._regex_analyzer = RegexAnalyzer(self._matcher)
        self._ast_analyzer = ASTAnalyzer()

    # -- public API ----------------------------------------------------------

    def scan(self, root: Path, *, extra_excludes: Sequence[str] = ()) -> ScanResult:
        """Analyze ``root`` and return an aggregate :class:`ScanResult`."""
        started = time.perf_counter()
        include_globs = self._all_globs()
        walker = FileWalker(
            root,
            include_globs=include_globs,
            extra_excludes=extra_excludes,
            max_file_bytes=self._config.max_file_bytes,
        )

        findings: list[Finding] = []
        errors: list[ScanError] = []
        scanned = 0

        for source in walker.walk():
            scanned += 1

            for pack in self._rulepacks:
                if pack.matches_file(source.relpath):
                    try:
                        file_findings = self._analyze_file(source, pack)
                        findings.extend(file_findings)
                    except Exception as exc:
                        errors.append(ScanError(file=source.relpath, message=f"({pack.name}): {exc}"))

        duration = time.perf_counter() - started
        return ScanResult(
            findings=tuple(findings),
            errors=tuple(errors),
            files_scanned=scanned,
            files_skipped=walker.skipped,
            rulepacks_used=len(self._rulepacks),
            duration_seconds=duration,
        )

    # -- internals -----------------------------------------------------------

    def _all_globs(self) -> list[str]:
        globs: list[str] = []
        for pack in self._rulepacks:
            globs.extend(pack.file_globs)
        return globs

    def _analyze_file(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        if self._ast_analyzer.is_available() and pack.ast_endpoints:
            try:
                ast_findings = self._ast_analyzer.analyze(source, pack)
                if ast_findings:
                    return ast_findings
            except Exception as e:
                # Fallback to regex
                pass
        return self._regex_analyzer.analyze(source, pack)
