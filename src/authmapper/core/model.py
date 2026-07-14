"""Domain model for the analyzer.

These immutable value objects are the shared language spoken by every layer of
the tool (engine, classifier, reporters, TUI). Keeping them dependency-free and
serializable means any reporter can render them and any test can assert on them
without touching the analysis internals.

Nothing here performs I/O or holds mutable global state.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any


class AuthState(enum.Enum):
    """Authentication posture of an endpoint.

    The three-state (plus PUBLIC) model is the heart of the fail-safe design:
    when the engine cannot *confidently* prove an endpoint is guarded, it must
    resolve to ``UNKNOWN`` rather than ``PROTECTED``. Silence is never treated
    as safety.
    """

    PROTECTED = "PROTECTED"  # An auth guard was positively identified.
    EXPOSED = "EXPOSED"      # Confidently an endpoint, and no guard was found.
    UNKNOWN = "UNKNOWN"      # Could not resolve routing/guards with confidence.
    PUBLIC = "PUBLIC"        # Intentionally public (exempt path / annotation).

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Confidence(enum.Enum):
    """How sure the engine is about a finding.

    Confidence gates severity escalation: a low-confidence endpoint with no
    guard is reported as ``UNKNOWN`` (needs review), never ``EXPOSED``.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Severity(enum.Enum):
    """Risk severity derived from ``AuthState`` and ``Confidence``."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class CoverageStatus(enum.Enum):
    """Processing outcome for one eligible source file."""

    ANALYZED = "ANALYZED"
    EXCLUDED = "EXCLUDED"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True)
class Evidence:
    """A single piece of supporting proof for a finding.

    Evidence intentionally records *locations and signal names*, not sensitive
    values, so that reports remain safe to read without leaking secrets.
    """

    file: str            # Project-relative POSIX path.
    line: int            # 1-based line number.
    signal: str          # Rule/signal id that matched (e.g. "inline-middleware").
    snippet: str = ""    # Short, redacted excerpt for human context.

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "signal": self.signal,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class Endpoint:
    """An HTTP entry point discovered in source.

    ``method`` and ``route`` may be best-effort ("ANY", "*") when a rule pack
    models a whole file as an endpoint (e.g. classic PHP) rather than a routed
    handler (e.g. Express).
    """

    file: str
    line: int
    method: str = "ANY"
    route: str = "*"
    language: str = "unknown"
    framework: str = "unknown"

    @property
    def identity(self) -> tuple[str, str, str, int]:
        """Stable sort/dedup key: route, then file, then line."""
        return (self.route, self.file, self.method, self.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "method": self.method,
            "route": self.route,
            "language": self.language,
            "framework": self.framework,
        }


@dataclass(frozen=True)
class Finding:
    """The unit of analyzer output: an endpoint plus its classified posture."""

    endpoint: Endpoint
    auth_state: AuthState
    confidence: Confidence
    severity: Severity
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    rationale: str = ""
    fix_hint: str = ""
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def sort_key(self) -> tuple[int, tuple[str, str, str, int]]:
        """Order by severity (desc) then endpoint identity (asc) for determinism."""
        return (-self.severity.rank, self.endpoint.identity)

    def with_suppression(self, reason: str) -> Finding:
        return replace(self, suppressed=True, suppression_reason=reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint.to_dict(),
            "auth_state": str(self.auth_state),
            "confidence": str(self.confidence),
            "severity": str(self.severity),
            "evidence": [e.to_dict() for e in self.evidence],
            "rationale": self.rationale,
            "fix_hint": self.fix_hint,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


@dataclass(frozen=True)
class ScanError:
    """A non-fatal problem encountered while scanning a single file.

    The walker/engine isolate per-file failures so one unreadable or malformed
    file never aborts the whole run.
    """

    file: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "message": self.message}


@dataclass(frozen=True)
class SourceCoverage:
    """Coverage status and diagnostic for one eligible source file."""

    file: str
    status: CoverageStatus
    reason: str = ""
    rulepacks: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "status": str(self.status),
            "reason": self.reason,
            "rulepacks": list(self.rulepacks),
        }


@dataclass(frozen=True)
class ScanResult:
    """Aggregate output of a full analysis run."""

    findings: tuple[Finding, ...]
    errors: tuple[ScanError, ...]
    files_scanned: int
    files_skipped: int
    rulepacks_used: tuple[str, ...]
    duration_seconds: float
    coverage: tuple[SourceCoverage, ...] = field(default_factory=tuple)

    def sorted_findings(self, include_suppressed: bool = False) -> list[Finding]:
        items = [f for f in self.findings if include_suppressed or not f.suppressed]
        return sorted(items, key=lambda f: f.sort_key)

    def counts_by_state(self) -> dict[str, int]:
        counts = {s.value: 0 for s in AuthState}
        for f in self.findings:
            if not f.suppressed:
                counts[f.auth_state.value] += 1
        return counts

    def max_severity(self) -> Severity:
        active = [f for f in self.findings if not f.suppressed]
        if not active:
            return Severity.INFO
        return max((f.severity for f in active), key=lambda s: s.rank)

    def coverage_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CoverageStatus}
        for record in self.coverage:
            counts[record.status.value] += 1
        return counts

    def incomplete_coverage(self) -> tuple[SourceCoverage, ...]:
        incomplete = {
            CoverageStatus.UNSUPPORTED,
            CoverageStatus.SKIPPED,
            CoverageStatus.ERROR,
        }
        return tuple(record for record in self.coverage if record.status in incomplete)

    def coverage_errors(self) -> tuple[SourceCoverage, ...]:
        return tuple(record for record in self.coverage if record.status is CoverageStatus.ERROR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.sorted_findings(include_suppressed=True)],
            "errors": [e.to_dict() for e in self.errors],
            "coverage": [record.to_dict() for record in self.coverage],
            "summary": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "rulepacks_used": list(self.rulepacks_used),
                "duration_seconds": round(self.duration_seconds, 4),
                "counts_by_state": self.counts_by_state(),
                "counts_by_coverage": self.coverage_counts(),
                "max_severity": str(self.max_severity()),
            },
        }
