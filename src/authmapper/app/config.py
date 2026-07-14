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


class ConfigError(Exception):
    """Raised when a project configuration file is present but invalid.

    A *missing* ``.authmap.json`` is acceptable (the file is optional).
    A *present but malformed* file is a usage error that must not silently
    produce a false-green security gate.
    """


#: Report severities eligible to trip ``--fail-on``.
_FAIL_LEVELS = {s.value: s for s in Severity}

#: Auth states eligible to trip ``--fail-on`` (convenience aliases).
_FAIL_STATES = {"EXPOSED", "UNKNOWN"}


@dataclass(frozen=True)
class RunConfig:
    """Immutable configuration for a single analysis run."""

    project_root: Path = field(default_factory=Path)
    report_dir: Path = field(default_factory=Path)
    output_stem: str = "authmap"
    output_format: str = "table"           # table | json | sarif
    min_confidence: str = "medium"         # low | medium | high
    fail_on: str | None = None             # "EXPOSED" | "UNKNOWN" | a Severity name | None
    baseline_path: Path | None = None
    extra_rulepack_dirs: tuple[Path, ...] = ()
    excludes: tuple[str, ...] = ()
    regex_timeout_seconds: float = 1.0
    max_file_bytes: int = 1 * 1024 * 1024
    write_report: bool = False
    quiet: bool = False
    experimental_ast: bool = False

    def merged_with_file(self) -> RunConfig:
        """Return a new config with values from the project ``.authmap.json`` applied.

        Only fields still at their dataclass defaults are overridden; explicit
        CLI arguments always take precedence.

        Raises :class:`ConfigError` if the file exists but cannot be read or
        contains invalid content.  A missing file is silently ignored because
        ``.authmap.json`` is optional.
        """
        cfg_path = self.project_root / ".authmap.json"
        if not cfg_path.exists():
            return self
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"invalid project config '{cfg_path}': {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(
                f"invalid project config '{cfg_path}': expected a JSON object, "
                f"got {type(data).__name__}"
            )

        updates: dict = {}
        if "excludes" in data and not self.excludes:
            updates["excludes"] = tuple(str(x) for x in data["excludes"])
        if "min_confidence" in data and self.min_confidence == "medium":
            updates["min_confidence"] = str(data["min_confidence"])
        if "fail_on" in data and self.fail_on is None:
            updates["fail_on"] = str(data["fail_on"])
        return replace(self, **updates)

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
