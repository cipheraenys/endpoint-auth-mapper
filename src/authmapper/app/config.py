"""Run configuration.

A single immutable :class:`RunConfig` captures everything a run needs. It can be
assembled from CLI arguments and optionally merged with a project-level
``.authmap.json`` file, so teams can commit shared defaults while still allowing
command-line overrides.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..core.model import Severity

CONFIG_FILENAME = ".authmap.json"

#: Report severities eligible to trip ``--fail-on``.
_FAIL_LEVELS = {s.value: s for s in Severity}

#: Auth states eligible to trip ``--fail-on`` (convenience aliases).
_FAIL_STATES = {"EXPOSED", "UNKNOWN"}


@dataclass(frozen=True)
class RunConfig:
    """Fully-resolved settings for one analysis run."""

    project_root: Path
    report_dir: Path
    output_stem: str = "authmap"
    output_format: str = "table"
    fail_on: str | None = None          # "EXPOSED" | "UNKNOWN" | a Severity name | None
    min_confidence: str = "medium"          # low | medium | high
    excludes: tuple[str, ...] = field(default_factory=tuple)
    extra_rulepack_dirs: tuple[Path, ...] = field(default_factory=tuple)
    baseline_path: Path | None = None
    regex_timeout_seconds: float = 1.0
    max_file_bytes: int = 2 * 1024 * 1024
    write_report: bool = False
    quiet: bool = False

    def merged_with_file(self) -> RunConfig:
        """Overlay a project ``.authmap.json`` beneath explicit CLI values.

        CLI values take precedence; the file only supplies values the user did
        not override. To keep this simple and predictable, file values are only
        applied to a curated subset of fields.
        """
        cfg_path = self.project_root / CONFIG_FILENAME
        if not cfg_path.exists():
            return self
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self

        updates: dict[str, object] = {}
        if "excludes" in data and not self.excludes:
            updates["excludes"] = tuple(data["excludes"])
        if "min_confidence" in data and self.min_confidence == "medium":
            updates["min_confidence"] = str(data["min_confidence"])
        if "fail_on" in data and self.fail_on is None:
            updates["fail_on"] = str(data["fail_on"])
        return replace(self, **updates) if updates else self

    def fail_severity(self) -> Severity | None:
        """Return the Severity threshold implied by ``fail_on``, if severity-based."""
        if self.fail_on is None:
            return None
        return _FAIL_LEVELS.get(self.fail_on.upper())

    def fail_state(self) -> str | None:
        """Return the auth-state name implied by ``fail_on``, if state-based."""
        if self.fail_on is None:
            return None
        name = self.fail_on.upper()
        return name if name in _FAIL_STATES else None
