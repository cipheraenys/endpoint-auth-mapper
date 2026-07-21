"""Framework-neutral Rust syntax and Cargo provenance frontend."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tree_sitter_rust
from tree_sitter import Language, Node, Parser

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 relies on the tomli backport
    import tomli as tomllib

from authmapper.core.v2 import AdapterInput, CoverageStatus, Diagnostic, DiagnosticLevel, SourceSpan

SUPPORTED_SUFFIXES = (".rs",)
MAX_SOURCE_FILES = 10_000
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_MODULE_SUMMARIES = 10_000

DIAGNOSTIC_PARSE_ERROR = "frontend.rust.parse_error"
DIAGNOSTIC_MANIFEST_PARSE_ERROR = "frontend.rust.manifest_parse_error"
DIAGNOSTIC_MANIFEST_INHERITANCE = "frontend.rust.manifest_inheritance"
DIAGNOSTIC_IO_ERROR = "frontend.rust.io_error"
DIAGNOSTIC_UNSUPPORTED_SOURCE = "frontend.rust.unsupported_source"
DIAGNOSTIC_UNSUPPORTED_MACRO = "frontend.rust.unsupported_macro"
DIAGNOSTIC_UNSUPPORTED_CFG = "frontend.rust.unsupported_cfg"
DIAGNOSTIC_UNRESOLVED_USE = "frontend.rust.unresolved_use"
DIAGNOSTIC_UNRESOLVED_MODULE = "frontend.rust.unresolved_module"
DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY = "frontend.rust.package_boundary_ambiguity"
DIAGNOSTIC_RESOURCE_LIMIT = "frontend.rust.resource_limit"


@dataclass(frozen=True, slots=True)
class CargoDependency:
    """Dependency alias from a statically parsed Cargo manifest."""

    alias: str
    package_name: str
    kind: str
    inherited: bool
    path: str | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class CargoPackage:
    """Owning Cargo package and workspace identity."""

    manifest_path: Path
    relative_manifest_path: str
    name: str
    workspace_manifest_path: Path | None
    dependencies: tuple[CargoDependency, ...]


@dataclass(frozen=True, slots=True)
class RustSource:
    """One successfully parsed user-authored Rust source unit."""

    path: Path
    relative_path: str
    source: bytes
    root: Node
    package: CargoPackage | None


@dataclass(frozen=True, slots=True)
class RustUse:
    """Resolved or unresolved `use` binding provenance."""

    local_name: str
    imported_name: str
    path: str
    origin: str | None
    public: bool
    glob: bool
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class RustModule:
    """Rust module declaration and statically resolved source target."""

    name: str
    target: Path | None
    inline: bool
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class RustSyntax:
    """Generic syntax hook for later adapter classification."""

    kind: str
    text: str
    span: SourceSpan
    name: str | None = None


@dataclass(frozen=True, slots=True)
class RustModuleSummary:
    """Bounded generic summary for one Rust source module."""

    path: str
    uses: tuple[RustUse, ...] = ()
    modules: tuple[RustModule, ...] = ()
    syntax: tuple[RustSyntax, ...] = ()


@dataclass(frozen=True, slots=True)
class RustFailureCoverage:
    """Source-level failure coverage before adapter ownership exists."""

    id: str
    target_path: str
    status: CoverageStatus
    diagnostic_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class RustAnalysis:
    """Deterministic Rust/Cargo frontend output without framework semantics."""

    sources: tuple[RustSource, ...] = ()
    packages: tuple[CargoPackage, ...] = ()
    summaries: tuple[RustModuleSummary, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    coverage: tuple[RustFailureCoverage, ...] = ()


class RustFrontend:
    """Parse Rust and Cargo files without invoking Cargo or target code."""

    def analyze(self, input_data: AdapterInput) -> RustAnalysis:
        parser = Parser(Language(tree_sitter_rust.language()))
        project_root = input_data.project_root.resolve()
        paths = tuple(sorted(input_data.source_paths, key=lambda item: item.as_posix()))
        if len(paths) > MAX_SOURCE_FILES:
            diagnostic = Diagnostic(
                "diagnostic:frontend:rust:resource:files",
                DIAGNOSTIC_RESOURCE_LIMIT,
                f"source count exceeds limit of {MAX_SOURCE_FILES}",
                DiagnosticLevel.ERROR,
            )
            return RustAnalysis(
                diagnostics=(diagnostic,),
                coverage=(_failure_coverage(diagnostic, "<project>", CoverageStatus.ERROR),),
            )

        total_bytes = 0
        sources: list[RustSource] = []
        packages: dict[Path, CargoPackage] = {}
        diagnostics: list[Diagnostic] = []
        coverage: list[RustFailureCoverage] = []
        for path in paths:
            resolved = path.resolve()
            relative = _relative(resolved, project_root)
            if resolved.suffix.lower() not in SUPPORTED_SUFFIXES:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:unsupported:{relative}",
                    DIAGNOSTIC_UNSUPPORTED_SOURCE,
                    f"unsupported Rust source type: {relative}",
                    DiagnosticLevel.WARNING,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.UNSUPPORTED))
                continue
            try:
                source = resolved.read_bytes()
            except OSError as error:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:io:{relative}",
                    DIAGNOSTIC_IO_ERROR,
                    f"cannot read Rust source {relative}: {error}",
                    DiagnosticLevel.ERROR,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                continue
            if len(source) > MAX_SOURCE_BYTES:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:resource:source:{relative}",
                    DIAGNOSTIC_RESOURCE_LIMIT,
                    f"source budget exceeded while reading {relative}",
                    DiagnosticLevel.ERROR,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                continue
            total_bytes += len(source)
            if total_bytes > MAX_TOTAL_BYTES:
                diagnostic = Diagnostic(
                    "diagnostic:frontend:rust:resource:total",
                    DIAGNOSTIC_RESOURCE_LIMIT,
                    f"total source bytes exceed limit of {MAX_TOTAL_BYTES}",
                    DiagnosticLevel.ERROR,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                break
            tree = parser.parse(source)
            if tree.root_node.has_error:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:parse:{relative}",
                    DIAGNOSTIC_PARSE_ERROR,
                    f"Rust parse error: {relative}",
                    DiagnosticLevel.ERROR,
                    span(relative, tree.root_node),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                continue
            package, package_diagnostics = _owning_package(resolved, project_root)
            for diagnostic in package_diagnostics:
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
            if package is not None:
                packages[package.manifest_path] = package
            sources.append(RustSource(resolved, relative, source, tree.root_node, package))

        summaries: list[RustModuleSummary] = []
        for item in sources:
            if len(summaries) >= MAX_MODULE_SUMMARIES:
                diagnostic = Diagnostic(
                    "diagnostic:frontend:rust:resource:summaries",
                    DIAGNOSTIC_RESOURCE_LIMIT,
                    f"module summary limit exceeded: {MAX_MODULE_SUMMARIES}",
                    DiagnosticLevel.ERROR,
                    _file_span(item.relative_path),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
                break
            uses = _uses(item)
            modules, module_diagnostics = _modules(item, project_root)
            syntax, syntax_diagnostics = _syntax(item)
            summaries.append(RustModuleSummary(item.relative_path, uses, modules, syntax))
            for use in uses:
                if use.origin is not None:
                    continue
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:use:{item.relative_path}:{use.span.start_line}:"
                    f"{use.span.start_column}",
                    DIAGNOSTIC_UNRESOLVED_USE,
                    f"unresolved use provenance {use.path!r}",
                    DiagnosticLevel.WARNING,
                    use.span,
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.UNSUPPORTED))
            for diagnostic in (*module_diagnostics, *syntax_diagnostics):
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.UNSUPPORTED))

        return RustAnalysis(
            tuple(sources),
            _ordered(packages.values()),
            _ordered(summaries),
            _ordered(diagnostics),
            _ordered(coverage),
        )


def _owning_package(source_path: Path, project_root: Path) -> tuple[CargoPackage | None, tuple[Diagnostic, ...]]:
    manifest = _nearest_manifest(source_path.parent, project_root)
    relative_source = _relative(source_path, project_root)
    if manifest is None:
        diagnostic = Diagnostic(
            f"diagnostic:frontend:rust:package:{relative_source}",
            DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY,
            f"no owning Cargo package for {relative_source}",
            DiagnosticLevel.ERROR,
            _file_span(relative_source),
        )
        return None, (diagnostic,)
    try:
        data = _load_toml(manifest)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        diagnostic = Diagnostic(
            f"diagnostic:frontend:rust:manifest:{_relative(manifest, project_root)}",
            DIAGNOSTIC_MANIFEST_PARSE_ERROR,
            f"invalid Cargo manifest {_relative(manifest, project_root)}: {error}",
            DiagnosticLevel.ERROR,
            _file_span(_relative(manifest, project_root)),
        )
        return None, (diagnostic,)
    package_data = data.get("package")
    if not isinstance(package_data, dict) or not isinstance(package_data.get("name"), str):
        diagnostic = Diagnostic(
            f"diagnostic:frontend:rust:package:{relative_source}",
            DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY,
            f"Cargo manifest does not declare an owning package: {_relative(manifest, project_root)}",
            DiagnosticLevel.ERROR,
            _file_span(relative_source),
        )
        return None, (diagnostic,)
    workspace_manifest = _workspace_manifest(manifest.parent, project_root)
    workspace_data = _load_toml(workspace_manifest) if workspace_manifest is not None else {}
    dependencies, dependency_diagnostics = _dependencies(
        manifest, data, workspace_manifest, workspace_data, project_root
    )
    return (
        CargoPackage(
            manifest,
            _relative(manifest, project_root),
            package_data["name"],
            workspace_manifest,
            dependencies,
        ),
        dependency_diagnostics,
    )


def _dependencies(
    manifest: Path,
    data: dict[str, Any],
    workspace_manifest: Path | None,
    workspace_data: dict[str, Any],
    project_root: Path,
) -> tuple[tuple[CargoDependency, ...], tuple[Diagnostic, ...]]:
    result: list[CargoDependency] = []
    diagnostics: list[Diagnostic] = []
    workspace = workspace_data.get("workspace", {}) if isinstance(workspace_data.get("workspace", {}), dict) else {}
    workspace_dependencies = workspace.get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}
    for kind, table in _dependency_tables(data):
        for alias, value in table.items():
            inherited = isinstance(value, dict) and value.get("workspace") is True
            resolved_value = workspace_dependencies.get(alias) if inherited else value
            if inherited and resolved_value is None:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:rust:manifest-inheritance:{_relative(manifest, project_root)}:{alias}",
                    DIAGNOSTIC_MANIFEST_INHERITANCE,
                    f"workspace dependency {alias!r} is not declared",
                    DiagnosticLevel.ERROR,
                    _manifest_key_span(manifest, alias, project_root),
                )
                diagnostics.append(diagnostic)
                continue
            package_name = alias
            dependency_path: str | None = None
            if isinstance(resolved_value, dict):
                if isinstance(resolved_value.get("package"), str):
                    package_name = resolved_value["package"]
                if isinstance(resolved_value.get("path"), str):
                    dependency_path = resolved_value["path"]
            result.append(
                CargoDependency(
                    alias,
                    package_name,
                    kind,
                    inherited,
                    dependency_path,
                    _manifest_key_span(manifest, alias, project_root),
                )
            )
    return _ordered(result), _ordered(diagnostics)


def _dependency_tables(data: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            yield key, value
    target = data.get("target")
    if not isinstance(target, dict):
        return
    for target_name, target_data in target.items():
        if not isinstance(target_data, dict):
            continue
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            value = target_data.get(key)
            if isinstance(value, dict):
                yield f"target:{target_name}:{key}", value


def _uses(item: RustSource) -> tuple[RustUse, ...]:
    aliases = (
        {dependency.alias.replace("-", "_"): dependency.package_name for dependency in item.package.dependencies}
        if item.package
        else {}
    )
    result: list[RustUse] = []
    for node in walk(item.root):
        if node.type != "use_declaration":
            continue
        rendered = text(node, item.source).strip()
        public = rendered.startswith("pub ") or rendered.startswith("pub(")
        expression = rendered
        if rendered.startswith("pub("):
            expression = rendered[rendered.index(")") + 1 :].lstrip()
        else:
            expression = expression.removeprefix("pub ")
        expression = expression.removeprefix("use ").removesuffix(";").strip()
        for path, imported, local, glob in _expand_use(expression):
            first = path.split("::", 1)[0]
            origin: str | None
            if first in {"crate", "self", "super"}:
                origin = "local"
            elif first in {"alloc", "core", "std"}:
                origin = "builtin"
            else:
                origin = aliases.get(first)
            result.append(RustUse(local, imported, path, origin, public, glob, span(item.relative_path, node)))
    return _ordered(result)


def _expand_use(expression: str, prefix: tuple[str, ...] = ()) -> tuple[tuple[str, str, str, bool], ...]:
    open_index = _top_level_open_brace(expression)
    if open_index is not None:
        close_index = expression.rfind("}")
        base = tuple(part for part in expression[:open_index].removesuffix("::").split("::") if part)
        inner = expression[open_index + 1 : close_index]
        return tuple(
            expanded
            for part in _split_top_level(inner)
            for expanded in _expand_use(part.strip(), (*prefix, *base))
        )
    original, separator, alias = expression.partition(" as ")
    parts = (*prefix, *(part for part in original.split("::") if part))
    if not parts:
        return ()
    imported = parts[-1]
    glob = imported == "*"
    local = alias.strip() if separator else (parts[-2] if imported == "self" and len(parts) > 1 else imported)
    return (("::".join(parts), imported, local, glob),)


def _modules(item: RustSource, project_root: Path) -> tuple[tuple[RustModule, ...], tuple[Diagnostic, ...]]:
    modules: list[RustModule] = []
    diagnostics: list[Diagnostic] = []
    for node in walk(item.root):
        if node.type != "mod_item":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = text(name_node, item.source)
        body = node.child_by_field_name("body")
        if body is not None:
            modules.append(RustModule(name, None, True, span(item.relative_path, node)))
            continue
        previous = node.prev_named_sibling
        if (
            previous is not None
            and previous.type == "attribute_item"
            and text(previous, item.source).startswith("#[path")
        ):
            modules.append(RustModule(name, None, False, span(item.relative_path, node)))
            diagnostics.append(
                Diagnostic(
                    f"diagnostic:frontend:rust:module:{item.relative_path}:{node.start_point.row + 1}:"
                    f"{node.start_point.column + 1}",
                    DIAGNOSTIC_UNRESOLVED_MODULE,
                    f"custom module path for {name!r} is not resolved",
                    DiagnosticLevel.WARNING,
                    span(item.relative_path, node),
                )
            )
            continue
        lexical_path = _lexical_module_path(node, item.source)
        target, ambiguous = _resolve_module(item.path, name, project_root, lexical_path)
        modules.append(RustModule(name, target, False, span(item.relative_path, node)))
        if target is None or ambiguous:
            reason = "ambiguous" if ambiguous else "unresolved"
            diagnostics.append(
                Diagnostic(
                    f"diagnostic:frontend:rust:module:{item.relative_path}:{node.start_point.row + 1}:"
                    f"{node.start_point.column + 1}",
                    DIAGNOSTIC_UNRESOLVED_MODULE,
                    f"{reason} module source for {name!r}",
                    DiagnosticLevel.WARNING,
                    span(item.relative_path, node),
                )
            )
    return _ordered(modules), _ordered(diagnostics)


def _syntax(item: RustSource) -> tuple[tuple[RustSyntax, ...], tuple[Diagnostic, ...]]:
    syntax: list[RustSyntax] = []
    diagnostics: list[Diagnostic] = []
    for node in walk(item.root):
        kind = {
            "function_item": "function",
            "parameters": "parameters",
            "parameter": "parameter",
            "attribute_item": "attribute",
            "macro_invocation": "macro",
            "call_expression": "call",
            "field_expression": "method_call" if node.parent and node.parent.type == "call_expression" else "property",
            "generic_type": "type",
            "reference_type": "type",
            "scoped_type_identifier": "type",
            "type_identifier": "type",
        }.get(node.type)
        if kind is not None:
            name = node.child_by_field_name("name") or node.child_by_field_name("field")
            syntax.append(
                RustSyntax(
                    kind,
                    text(node, item.source),
                    span(item.relative_path, node),
                    text(name, item.source) if name is not None else None,
                )
            )
        if node.type == "macro_invocation":
            diagnostics.append(
                Diagnostic(
                    f"diagnostic:frontend:rust:macro:{item.relative_path}:{node.start_point.row + 1}:"
                    f"{node.start_point.column + 1}",
                    DIAGNOSTIC_UNSUPPORTED_MACRO,
                    "macro expansion is not executed",
                    DiagnosticLevel.WARNING,
                    span(item.relative_path, node),
                )
            )
        elif node.type == "attribute_item" and text(node, item.source).lstrip().startswith("#[cfg"):
            diagnostics.append(
                Diagnostic(
                    f"diagnostic:frontend:rust:cfg:{item.relative_path}:{node.start_point.row + 1}:"
                    f"{node.start_point.column + 1}",
                    DIAGNOSTIC_UNSUPPORTED_CFG,
                    "conditional compilation is not evaluated",
                    DiagnosticLevel.WARNING,
                    span(item.relative_path, node),
                )
            )
    return _ordered(syntax), _ordered(diagnostics)


def _nearest_manifest(start: Path, project_root: Path) -> Path | None:
    current = start.resolve()
    root = project_root.resolve()
    while current == root or root in current.parents:
        candidate = current / "Cargo.toml"
        if candidate.is_file():
            return candidate
        if current == root:
            break
        current = current.parent
    return None


def _workspace_manifest(start: Path, project_root: Path) -> Path | None:
    current = start.resolve()
    root = project_root.resolve()
    selected: Path | None = None
    while current == root or root in current.parents:
        candidate = current / "Cargo.toml"
        if candidate.is_file():
            try:
                if isinstance(_load_toml(candidate).get("workspace"), dict):
                    selected = candidate
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                pass
        if current == root:
            break
        current = current.parent
    return selected


def _resolve_module(
    source_path: Path,
    name: str,
    project_root: Path,
    lexical_path: tuple[str, ...] = (),
) -> tuple[Path | None, bool]:
    module_dir = (
        source_path.parent
        if source_path.name in {"lib.rs", "main.rs", "mod.rs"}
        else source_path.parent / source_path.stem
    )
    module_dir = module_dir.joinpath(*lexical_path)
    candidates = (module_dir / f"{name}.rs", module_dir / name / "mod.rs")
    root = project_root.resolve()
    matches = tuple(path.resolve() for path in candidates if path.is_file() and root in path.resolve().parents)
    return (matches[0] if len(matches) == 1 else None), len(matches) > 1


def _lexical_module_path(node: Node, source: bytes) -> tuple[str, ...]:
    result: list[str] = []
    current = node.parent
    while current is not None:
        if current.type == "mod_item" and current.child_by_field_name("body") is not None:
            name = current.child_by_field_name("name")
            if name is not None:
                result.append(text(name, source))
        current = current.parent
    return tuple(reversed(result))


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    if not isinstance(value, dict):
        raise tomllib.TOMLDecodeError("manifest root must be a table", "", 0)
    return value


def _manifest_key_span(manifest: Path, key: str, project_root: Path) -> SourceSpan:
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return _file_span(_relative(manifest, project_root))
    for index, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(f"{key} ") or stripped.startswith(f"{key}="):
            column = len(line) - len(stripped) + 1
            return SourceSpan(_relative(manifest, project_root), index, column, index, len(line) + 1)
    return _file_span(_relative(manifest, project_root))


def _top_level_open_brace(value: str) -> int | None:
    for index, character in enumerate(value):
        if character == "{":
            return index
    return None


def _split_top_level(value: str) -> tuple[str, ...]:
    result: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(value):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(value[start:index])
            start = index + 1
    result.append(value[start:])
    return tuple(result)


def walk(node: Node) -> Iterable[Node]:
    yield node
    for child in node.children:
        yield from walk(child)


def text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def span(path: str, node: Node) -> SourceSpan:
    return SourceSpan(
        path,
        node.start_point.row + 1,
        node.start_point.column + 1,
        node.end_point.row + 1,
        node.end_point.column + 1,
    )


def _failure_coverage(
    diagnostic: Diagnostic,
    target_path: str,
    status: CoverageStatus,
) -> RustFailureCoverage:
    return RustFailureCoverage(
        f"coverage:{diagnostic.id.removeprefix('diagnostic:')}",
        target_path,
        status,
        diagnostic.id,
        diagnostic.message,
    )


def _file_span(path: str) -> SourceSpan:
    return SourceSpan(path, 1, 1, 1, 1)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _ordered(items):
    return tuple(sorted(items, key=lambda item: item.id if hasattr(item, "id") else repr(item)))
