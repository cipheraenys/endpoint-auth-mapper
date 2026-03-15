"""Run orchestration and gating.

The runner is the application-level use case: it loads rule packs, executes the
engine, applies confidence/baseline filtering, optionally writes a confidential
report, and computes the process exit code. Both the CLI and the TUI call into
this single entry point so behaviour never diverges between them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.engine import Engine, EngineConfig
from ..core.model import AuthState, Finding, ScanResult, Severity
from ..core.rulepack import RulePackError, load_rulepacks
from ..core.safety import ensure_within
from ..reporters import REPORTERS
from .baseline import is_baselined, load_baseline
from .config import RunConfig

# Process exit codes (documented contract for CI).
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class RunOutcome:
    """Everything a caller needs after a run."""

    result: ScanResult
    rendered: str
    report_path: Path | None
    exit_code: int
    gating_findings: tuple[Finding, ...]


class Runner:
    """Coordinates a single analysis run end to end."""

    def __init__(self, config: RunConfig) -> None:
        self._config = config

    def run(self) -> RunOutcome:
        rulepacks = self._load_rulepacks()
        engine = Engine(
            rulepacks,
            EngineConfig(
                regex_timeout_seconds=self._config.regex_timeout_seconds,
                max_file_bytes=self._config.max_file_bytes,
            ),
        )
        result = engine.scan(self._config.project_root, extra_excludes=self._config.excludes)

        rendered = self._render(result)
        report_path = self._maybe_write_report(rendered)
        gating = self._gating_findings(result)
        exit_code = self._exit_code(result, gating)

        return RunOutcome(
            result=result,
            rendered=rendered,
            report_path=report_path,
            exit_code=exit_code,
            gating_findings=gating,
        )

    # -- steps ---------------------------------------------------------------

    def _load_rulepacks(self):
        try:
            return load_rulepacks(self._config.extra_rulepack_dirs)
        except RulePackError as exc:
            raise RunnerError(f"rule-pack error: {exc}") from exc

    def _render(self, result: ScanResult) -> str:
        reporter = REPORTERS.get(self._config.output_format)
        if reporter is None:
            raise RunnerError(f"unknown output format: {self._config.output_format}")
        return reporter(result)

    def _maybe_write_report(self, rendered: str) -> Path | None:
        if not self._config.write_report:
            return None
        report_dir = self._config.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        ext = {"table": "txt", "json": "json", "sarif": "sarif"}[self._config.output_format]
        target = ensure_within(report_dir, Path(f"{self._config.output_stem}.{ext}"))
        target.write_text(rendered, encoding="utf-8")
        return target

    # -- gating logic --------------------------------------------------------

    def _gating_findings(self, result: ScanResult) -> tuple[Finding, ...]:
        """Return findings that should count toward failing the run."""
        fail_state = self._config.fail_state()
        fail_sev = self._config.fail_severity()
        if fail_state is None and fail_sev is None:
            return ()

        accepted = (
            load_baseline(self._config.baseline_path)
            if self._config.baseline_path
            else set()
        )
        min_rank = _CONFIDENCE_RANK[self._config.min_confidence]

        gating: list[Finding] = []
        for f in result.sorted_findings():
            if f.suppressed:
                continue
            if _CONFIDENCE_RANK[str(f.confidence)] < min_rank:
                continue
            if accepted and is_baselined(f, accepted):
                continue
            if self._trips_gate(f, fail_state, fail_sev):
                gating.append(f)
        return tuple(gating)

    @staticmethod
    def _trips_gate(
        finding: Finding,
        fail_state: str | None,
        fail_sev: Severity | None,
    ) -> bool:
        if fail_state is not None:
            # State-based gate: an UNKNOWN gate also catches the stricter EXPOSED.
            unknown_states = (AuthState.UNKNOWN, AuthState.EXPOSED)
            if fail_state == "UNKNOWN" and finding.auth_state in unknown_states:
                return True
            return bool(fail_state == "EXPOSED" and finding.auth_state is AuthState.EXPOSED)
        if fail_sev is not None:
            return finding.severity.rank >= fail_sev.rank
        return False

    def _exit_code(self, result: ScanResult, gating: tuple[Finding, ...]) -> int:
        if result.errors and not result.findings:
            # Nothing analyzed and errors present -> signal tool trouble.
            return EXIT_ERROR
        return EXIT_FINDINGS if gating else EXIT_OK


class RunnerError(Exception):
    """Raised for unrecoverable run configuration/setup problems."""
