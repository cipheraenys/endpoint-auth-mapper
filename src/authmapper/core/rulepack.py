"""Rule-pack loading and validation.

A rule pack is declarative data (JSON) describing how to analyze one
language/framework. This module loads packs from the bundled directory and/or a
user-supplied directory, validates their shape, and compiles their regexes once
(under the ReDoS-safe compiler).

The engine consumes :class:`RulePack` objects and never sees raw JSON, so the
on-disk format can evolve behind this boundary.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .safety import compile_pattern

#: Endpoint discovery strategies a pack may declare.
ENDPOINT_MODEL_ROUTE = "route"  # Match routed handlers via regex (Express, Flask...).
ENDPOINT_MODEL_FILE = "file"    # Treat each matching file as one endpoint (classic PHP).

#: Scope in which an auth signal counts as guarding an endpoint.
SCOPE_SAME_LINE = "same_line"
SCOPE_FILE = "file"
_VALID_SCOPES = {SCOPE_SAME_LINE, SCOPE_FILE}


class RulePackError(Exception):
    """Raised when a rule pack is structurally invalid."""


@dataclass(frozen=True)
class EndpointPattern:
    """Compiled endpoint-discovery pattern (route model only)."""

    rule_id: str
    pattern: Any                 # re.Pattern[str]
    method_group: int | None
    path_group: int | None
    default_method: str


@dataclass(frozen=True)
class AuthSignal:
    """Compiled auth-guard signal."""

    rule_id: str
    pattern: Any                 # re.Pattern[str]
    scope: str


@dataclass(frozen=True)
class ASTEndpointPattern:
    """AST endpoint-discovery pattern."""

    rule_id: str
    query: str


@dataclass(frozen=True)
class ASTAuthSignal:
    """AST auth-guard signal."""

    rule_id: str
    query: str
    scope: str


@dataclass(frozen=True)
class RulePack:
    """A validated, compiled analysis pack for one language/framework."""

    name: str
    language: str
    framework: str
    file_globs: tuple[str, ...]
    endpoint_model: str
    endpoint_patterns: tuple[EndpointPattern, ...]
    auth_signals: tuple[AuthSignal, ...]
    exempt_paths: tuple[str, ...]
    file_endpoint_method: str
    ast_language: str | None = None
    ast_endpoints: tuple[ASTEndpointPattern, ...] = ()
    ast_auth_signals: tuple[ASTAuthSignal, ...] = ()

    def matches_file(self, relpath: str) -> bool:
        from .walker import glob_match

        return any(glob_match(relpath, glob) for glob in self.file_globs)


# --- loading ----------------------------------------------------------------


def _require(mapping: dict[str, Any], key: str, pack_name: str) -> Any:
    if key not in mapping:
        raise RulePackError(f"[{pack_name}] missing required field: '{key}'")
    return mapping[key]


def _parse_endpoint_pattern(raw: dict[str, Any], pack_name: str) -> EndpointPattern:
    rule_id = str(_require(raw, "id", pack_name))
    source = str(_require(raw, "regex", pack_name))
    capture = raw.get("capture", {}) or {}
    return EndpointPattern(
        rule_id=rule_id,
        pattern=compile_pattern(source, ignore_case=bool(raw.get("ignore_case", True))),
        method_group=capture.get("method"),
        path_group=capture.get("path"),
        default_method=str(raw.get("default_method", "ANY")),
    )


def _parse_auth_signal(raw: dict[str, Any], pack_name: str) -> AuthSignal:
    rule_id = str(_require(raw, "id", pack_name))
    source = str(_require(raw, "regex", pack_name))
    scope = str(raw.get("scope", SCOPE_FILE))
    if scope not in _VALID_SCOPES:
        raise RulePackError(f"[{pack_name}] invalid scope '{scope}' on signal '{rule_id}'")
    return AuthSignal(
        rule_id=rule_id,
        pattern=compile_pattern(source, ignore_case=bool(raw.get("ignore_case", True))),
        scope=scope,
    )


def _parse_ast_endpoint(raw: dict[str, Any], pack_name: str) -> ASTEndpointPattern:
    rule_id = str(_require(raw, "id", pack_name))
    query = str(_require(raw, "query", pack_name))
    return ASTEndpointPattern(rule_id=rule_id, query=query)


def _parse_ast_auth_signal(raw: dict[str, Any], pack_name: str) -> ASTAuthSignal:
    rule_id = str(_require(raw, "id", pack_name))
    query = str(_require(raw, "query", pack_name))
    scope = str(raw.get("scope", SCOPE_FILE))
    if scope not in _VALID_SCOPES:
        raise RulePackError(f"[{pack_name}] invalid scope '{scope}' on AST signal '{rule_id}'")
    return ASTAuthSignal(rule_id=rule_id, query=query, scope=scope)


def load_rulepack(data: dict[str, Any], *, source_name: str) -> RulePack:
    """Validate and compile a single rule pack from parsed JSON."""
    name = str(data.get("name") or source_name)
    language = str(_require(data, "language", name))
    framework = str(data.get("framework", "generic"))
    endpoint_model = str(data.get("endpoint_model", ENDPOINT_MODEL_ROUTE))
    if endpoint_model not in (ENDPOINT_MODEL_ROUTE, ENDPOINT_MODEL_FILE):
        raise RulePackError(f"[{name}] invalid endpoint_model: '{endpoint_model}'")

    file_globs = tuple(_require(data, "file_globs", name))
    if not file_globs:
        raise RulePackError(f"[{name}] 'file_globs' must not be empty")

    endpoint_patterns = tuple(
        _parse_endpoint_pattern(raw, name) for raw in data.get("endpoint_patterns", [])
    )
    if endpoint_model == ENDPOINT_MODEL_ROUTE and not endpoint_patterns:
        raise RulePackError(f"[{name}] route model requires at least one endpoint_pattern")

    auth_signals = tuple(_parse_auth_signal(raw, name) for raw in data.get("auth_signals", []))
    if not auth_signals:
        raise RulePackError(f"[{name}] at least one auth_signal is required")

    ast_language = data.get("ast_language")
    ast_language = str(ast_language) if ast_language else None
    
    ast_endpoints = tuple(
        _parse_ast_endpoint(raw, name) for raw in data.get("ast_endpoints", [])
    )
    ast_auth_signals = tuple(
        _parse_ast_auth_signal(raw, name) for raw in data.get("ast_auth_signals", [])
    )

    return RulePack(
        name=name,
        language=language,
        framework=framework,
        file_globs=file_globs,
        endpoint_model=endpoint_model,
        endpoint_patterns=endpoint_patterns,
        auth_signals=auth_signals,
        exempt_paths=tuple(data.get("exempt_paths", [])),
        file_endpoint_method=str(data.get("file_endpoint_method", "ANY")),
        ast_language=ast_language,
        ast_endpoints=ast_endpoints,
        ast_auth_signals=ast_auth_signals,
    )


def _load_dir(directory: Path) -> list[RulePack]:
    packs: list[RulePack] = []
    for json_path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RulePackError(f"could not read rule pack {json_path.name}: {exc}") from exc
        packs.append(load_rulepack(data, source_name=json_path.stem))
    return packs


def bundled_rulepack_dir() -> Path:
    """Return the directory holding rule packs shipped with the package."""
    return Path(__file__).resolve().parent.parent / "rulepacks"


def load_rulepacks(extra_dirs: Iterable[Path] = ()) -> list[RulePack]:
    """Load bundled packs plus any user-supplied directories.

    User packs are loaded after bundled ones so a project can extend coverage
    without modifying the installed package.
    """
    packs = _load_dir(bundled_rulepack_dir())
    for directory in extra_dirs:
        if directory and directory.is_dir():
            packs.extend(_load_dir(directory))
    if not packs:
        raise RulePackError("no rule packs found")
    return packs
