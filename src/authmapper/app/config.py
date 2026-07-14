"""Run configuration.

A single immutable :class:`RunConfig` captures everything a run needs. It can be
assembled from CLI arguments and optionally merged with a project-level
``.authmap.json`` file, so teams can commit shared defaults while still allowing
command-line overrides.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

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
_OUTPUT_FORMATS = {"table", "json", "sarif"}
_CONFIDENCE_LEVELS = {"low", "medium", "high"}
_CONFIG_VERSION = "1.0"
_CONFIG_FIELDS = {
    "schema_version",
    "excludes",
    "experimental_ast",
    "fail_on",
    "min_confidence",
    "public_paths",
    "strict_coverage",
}


def _expect_string(value: Any, field_name: str, cfg_path: Path) -> str:
    if not isinstance(value, str):
        raise ConfigError(
            f"invalid project config '{cfg_path}': '{field_name}' must be a string"
        )
    return value


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
    public_paths: tuple[str, ...] = ()
    regex_timeout_seconds: float = 1.0
    max_file_bytes: int = 1 * 1024 * 1024
    write_report: bool = False
    quiet: bool = False
    experimental_ast: bool = False
    strict_coverage: bool = False
    cli_overrides: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        if self.output_format not in _OUTPUT_FORMATS:
            raise ConfigError(f"invalid output format: {self.output_format!r}")
        if self.min_confidence not in _CONFIDENCE_LEVELS:
            raise ConfigError(f"invalid minimum confidence: {self.min_confidence!r}")
        if self.fail_on is not None and self.fail_on not in _FAIL_STATES | set(_FAIL_LEVELS):
            raise ConfigError(f"invalid fail-on value: {self.fail_on!r}")
        if not math.isfinite(self.regex_timeout_seconds) or self.regex_timeout_seconds <= 0:
            raise ConfigError("regex timeout must be a finite number greater than zero")
        if isinstance(self.max_file_bytes, bool) or self.max_file_bytes <= 0:
            raise ConfigError("maximum file size must be greater than zero")
        if not self.output_stem or Path(self.output_stem).name != self.output_stem:
            raise ConfigError("output stem must be a non-empty file name")
        if any(not item or Path(item).name != item for item in self.excludes):
            raise ConfigError("excludes must contain non-empty directory names")
        if any(not path.startswith("/") for path in self.public_paths):
            raise ConfigError("public paths must start with '/'")

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

        unknown = sorted(set(data) - _CONFIG_FIELDS)
        if unknown:
            raise ConfigError(
                f"invalid project config '{cfg_path}': unknown field(s): {', '.join(unknown)}"
            )

        version = _expect_string(data.get("schema_version"), "schema_version", cfg_path)
        if version != _CONFIG_VERSION:
            raise ConfigError(
                f"invalid project config '{cfg_path}': unsupported schema_version {version!r}; "
                f"expected {_CONFIG_VERSION!r}"
            )

        excludes = data.get("excludes", [])
        if not isinstance(excludes, list) or any(
            not isinstance(item, str) or not item or Path(item).name != item
            for item in excludes
        ):
            raise ConfigError(
                f"invalid project config '{cfg_path}': 'excludes' must be a list of "
                "non-empty directory names"
            )

        experimental_ast = data.get("experimental_ast", False)
        if not isinstance(experimental_ast, bool):
            raise ConfigError(
                f"invalid project config '{cfg_path}': 'experimental_ast' must be a boolean"
            )

        public_paths = data.get("public_paths", [])
        if not isinstance(public_paths, list) or any(
            not isinstance(path, str) or not path.startswith("/") for path in public_paths
        ):
            raise ConfigError(
                f"invalid project config '{cfg_path}': 'public_paths' must be a list "
                "of paths starting with '/'"
            )

        strict_coverage = data.get("strict_coverage", False)
        if not isinstance(strict_coverage, bool):
            raise ConfigError(
                f"invalid project config '{cfg_path}': 'strict_coverage' must be a boolean"
            )

        min_confidence = _expect_string(
            data.get("min_confidence", "medium"), "min_confidence", cfg_path
        )
        if min_confidence not in _CONFIDENCE_LEVELS:
            raise ConfigError(
                f"invalid project config '{cfg_path}': invalid min_confidence "
                f"{min_confidence!r}"
            )

        fail_on_raw = data.get("fail_on")
        fail_on = None
        if "fail_on" in data:
            fail_on = _expect_string(fail_on_raw, "fail_on", cfg_path)
            if fail_on not in _FAIL_STATES | set(_FAIL_LEVELS):
                raise ConfigError(
                    f"invalid project config '{cfg_path}': invalid fail_on {fail_on!r}"
                )

        return replace(
            self,
            excludes=(
                tuple(excludes)
                if "excludes" in data and "excludes" not in self.cli_overrides
                else self.excludes
            ),
            experimental_ast=(
                experimental_ast
                if "experimental_ast" in data
                and "experimental_ast" not in self.cli_overrides
                else self.experimental_ast
            ),
            public_paths=(tuple(dict.fromkeys(public_paths)) if "public_paths" in data else self.public_paths),
            strict_coverage=(
                strict_coverage
                if "strict_coverage" in data and "strict_coverage" not in self.cli_overrides
                else self.strict_coverage
            ),
            min_confidence=(
                min_confidence
                if "min_confidence" in data and "min_confidence" not in self.cli_overrides
                else self.min_confidence
            ),
            fail_on=(
                fail_on
                if "fail_on" in data and "fail_on" not in self.cli_overrides
                else self.fail_on
            ),
        )

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
