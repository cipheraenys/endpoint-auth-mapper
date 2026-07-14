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

from .ast_analyzer import ASTAnalyzer
from .model import CoverageStatus, Finding, ScanError, ScanResult, SourceCoverage
from .regex_analyzer import RegexAnalyzer
from .rulepack import RulePack
from .safety import SafeMatcher
from .walker import FileWalker, SourceFile


@dataclass(frozen=True)
class EngineConfig:
    """Tunable knobs for a run."""

    regex_timeout_seconds: float = 1.0
    max_file_bytes: int = 2 * 1024 * 1024
    use_ast: bool = False
    public_paths: tuple[str, ...] = ()


class Engine:
    """The analysis engine."""

    def __init__(self, rulepacks: Sequence[RulePack], config: EngineConfig | None = None) -> None:
        self._rulepacks = tuple(rulepacks)
        self._config = config or EngineConfig()
        self._matcher = SafeMatcher(self._config.regex_timeout_seconds)
        self._regex_analyzer = RegexAnalyzer(self._matcher, self._config.public_paths)
        self._ast_analyzer = ASTAnalyzer(self._config.public_paths)

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
        coverage: list[SourceCoverage] = []

        try:
            for source in walker.walk():
                matched_packs: list[str] = []
                had_error = False

                for pack in self._rulepacks:
                    if pack.matches_file(source.relpath):
                        matched_packs.append(pack.name)
                        try:
                            file_findings = self._analyze_file(source, pack)
                            findings.extend(file_findings)
                        except Exception as exc:
                            had_error = True
                            errors.append(ScanError(file=source.relpath, message=f"({pack.name}): {exc}"))
                coverage.append(
                    SourceCoverage(
                        file=source.relpath,
                        status=CoverageStatus.ERROR if had_error else CoverageStatus.ANALYZED,
                        reason="analysis failed; see scan errors" if had_error else "",
                        rulepacks=tuple(matched_packs),
                    )
                )
        finally:
            # Deterministic cleanup of the worker process regardless of outcome.
            self._matcher.close()

        duration = time.perf_counter() - started
        coverage.extend(walker.coverage)
        coverage.sort(key=lambda record: record.file)
        scanned = sum(record.status is CoverageStatus.ANALYZED for record in coverage)
        skipped = sum(record.status is not CoverageStatus.ANALYZED for record in coverage)
        return ScanResult(
            findings=tuple(findings),
            errors=tuple(errors),
            files_scanned=scanned,
            files_skipped=skipped,
            rulepacks_used=tuple(p.name for p in self._rulepacks),
            duration_seconds=duration,
            coverage=tuple(coverage),
        )

    # -- internals -----------------------------------------------------------

    def _all_globs(self) -> list[str]:
        globs: list[str] = []
        for pack in self._rulepacks:
            globs.extend(pack.file_globs)
        return globs

    def _analyze_file(self, source: SourceFile, pack: RulePack) -> list[Finding]:
        if self._config.use_ast and self._ast_analyzer.is_available() and pack.ast_endpoints:
            try:
                ast_findings = self._ast_analyzer.analyze(source, pack)
                if ast_findings:
                    return ast_findings
            except Exception:
                pass  # Fallback to regex
        return self._regex_analyzer.analyze(source, pack)
