"""Framework-neutral JavaScript syntax and provenance frontend."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tree_sitter_javascript
from tree_sitter import Language, Node, Parser

from authmapper.core.v2 import AdapterInput, CoverageStatus, Diagnostic, DiagnosticLevel, SourceSpan

SUPPORTED_SUFFIXES = (".js", ".mjs", ".cjs")
DISCOVERY_SUFFIXES = (".ts", ".tsx")
MAX_SOURCE_FILES = 10_000
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_MODULE_SUMMARIES = 10_000

DIAGNOSTIC_PARSE_ERROR = "frontend.javascript.parse_error"
DIAGNOSTIC_UNSUPPORTED_SOURCE = "frontend.javascript.unsupported_source"
DIAGNOSTIC_UNSUPPORTED_SYNTAX = "frontend.javascript.unsupported_syntax"
DIAGNOSTIC_UNRESOLVED_IMPORT = "frontend.javascript.unresolved_import"
DIAGNOSTIC_UNRESOLVED_EXPORT = "frontend.javascript.unresolved_export"
DIAGNOSTIC_AMBIGUOUS_BINDING = "frontend.javascript.ambiguous_binding"
DIAGNOSTIC_RESOURCE_LIMIT = "frontend.javascript.resource_limit"
DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY = "frontend.javascript.package_boundary_ambiguity"
DIAGNOSTIC_PACKAGE_INVALID = "frontend.javascript.package_invalid"


@dataclass(frozen=True, slots=True)
class PackageBoundary:
    """Nearest package provenance for one source."""

    path: Path | None
    data: dict[str, Any] | None
    error: str | None


@dataclass(frozen=True, slots=True)
class JavaScriptSource:
    """One successfully parsed JavaScript source unit."""

    path: Path
    relative_path: str
    source: bytes
    root: Node
    package: PackageBoundary

    @property
    def package_path(self) -> Path | None:
        return self.package.path

    @property
    def package_data(self) -> dict[str, Any] | None:
        return self.package.data

    @property
    def package_error(self) -> str | None:
        return self.package.error


@dataclass(frozen=True, slots=True)
class JavaScriptImport:
    """Source-backed ESM/CJS import binding."""

    local_name: str
    module_name: str
    imported_name: str
    target: Path | None
    span: SourceSpan
    kind: str


@dataclass(frozen=True, slots=True)
class JavaScriptExport:
    """Source-backed direct export or re-export binding."""

    exported_name: str
    local_name: str | None
    module_name: str | None
    target: Path | None
    span: SourceSpan
    kind: str


@dataclass(frozen=True, slots=True)
class JavaScriptSyntax:
    """Generic syntax hook for later adapter classification."""

    kind: str
    text: str
    span: SourceSpan
    name: str | None = None


@dataclass(frozen=True, slots=True)
class JavaScriptModuleSummary:
    """Bounded local symbol summary for one parsed module."""

    path: str
    imports: tuple[JavaScriptImport, ...] = ()
    exports: tuple[JavaScriptExport, ...] = ()
    syntax: tuple[JavaScriptSyntax, ...] = ()


@dataclass(frozen=True, slots=True)
class JavaScriptFailureCoverage:
    """Source-level frontend coverage before adapter graph ownership exists."""

    id: str
    target_path: str
    status: CoverageStatus
    diagnostic_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class JavaScriptAnalysis:
    """Frontend provenance for parsed and failed source units."""

    sources: tuple[JavaScriptSource, ...] = ()
    summaries: tuple[JavaScriptModuleSummary, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    coverage: tuple[JavaScriptFailureCoverage, ...] = ()


@dataclass(frozen=True, slots=True)
class JavaScriptFrontendResult:
    """Deterministic parse output; contains no framework semantics."""

    sources: tuple[JavaScriptSource, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    coverage: tuple[JavaScriptFailureCoverage, ...] = ()


class JavaScriptFrontend:
    """Parse JavaScript and resolve local provenance without execution."""

    def parse(self, input_data: AdapterInput) -> JavaScriptFrontendResult:
        parser = Parser(Language(tree_sitter_javascript.language()))
        root = input_data.project_root.resolve()
        paths = tuple(sorted(input_data.source_paths, key=lambda item: item.as_posix()))
        if len(paths) > MAX_SOURCE_FILES:
            diagnostic = Diagnostic(
                "diagnostic:frontend:javascript:resource:files",
                DIAGNOSTIC_RESOURCE_LIMIT,
                f"source count exceeds limit of {MAX_SOURCE_FILES}",
                DiagnosticLevel.ERROR,
            )
            failure = _failure_coverage(diagnostic, "<project>", CoverageStatus.ERROR)
            return JavaScriptFrontendResult(diagnostics=(diagnostic,), coverage=(failure,))

        total_bytes = 0
        sources: list[JavaScriptSource] = []
        diagnostics: list[Diagnostic] = []
        coverage: list[JavaScriptFailureCoverage] = []
        for path in paths:
            resolved = path.resolve()
            relative = _relative(resolved, root)
            if resolved.suffix.lower() not in SUPPORTED_SUFFIXES:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:unsupported:{relative}",
                    DIAGNOSTIC_UNSUPPORTED_SOURCE,
                    f"unsupported JavaScript source type: {relative}",
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
                    f"diagnostic:frontend:javascript:read:{relative}",
                    DIAGNOSTIC_RESOURCE_LIMIT,
                    f"cannot read JavaScript source {relative}: {error}",
                    DiagnosticLevel.ERROR,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                continue
            if len(source) > MAX_SOURCE_BYTES:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:resource:source:{relative}",
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
                    "diagnostic:frontend:javascript:resource:total",
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
                    f"diagnostic:frontend:javascript:parse:{relative}",
                    DIAGNOSTIC_PARSE_ERROR,
                    f"JavaScript parse error: {relative}",
                    DiagnosticLevel.ERROR,
                    span(relative, tree.root_node),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
                continue
            package = _package_boundary(resolved.parent, root)
            if package.error is not None:
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:package:{relative}",
                    DIAGNOSTIC_PACKAGE_INVALID,
                    f"invalid owning package {package.path.name if package.path else 'package.json'}: {package.error}",
                    DiagnosticLevel.ERROR,
                    _file_span(relative),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, relative, CoverageStatus.ERROR))
            sources.append(JavaScriptSource(resolved, relative, source, tree.root_node, package))
        return JavaScriptFrontendResult(tuple(sources), _ordered(diagnostics), _ordered(coverage))

    def analyze(self, input_data: AdapterInput) -> JavaScriptAnalysis:
        """Build bounded generic module summaries and provenance diagnostics."""
        parsed = self.parse(input_data)
        diagnostics = list(parsed.diagnostics)
        coverage = list(parsed.coverage)
        summaries: list[JavaScriptModuleSummary] = []
        for item in parsed.sources:
            if len(summaries) >= MAX_MODULE_SUMMARIES:
                diagnostic = Diagnostic(
                    "diagnostic:frontend:javascript:resource:summaries",
                    DIAGNOSTIC_RESOURCE_LIMIT,
                    f"module summary limit exceeded: {MAX_MODULE_SUMMARIES}",
                    DiagnosticLevel.ERROR,
                    _file_span(item.relative_path),
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
                break
            imports = self.imports(item, input_data.project_root)
            exports = self.exports(item, input_data.project_root)
            summaries.append(JavaScriptModuleSummary(item.relative_path, imports, exports, self.syntax(item)))
            for binding in imports:
                if not binding.module_name.startswith(".") or binding.target is not None:
                    continue
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:import:{item.relative_path}:{binding.span.start_line}:"
                    f"{binding.span.start_column}",
                    DIAGNOSTIC_UNRESOLVED_IMPORT,
                    f"unresolved local import {binding.module_name!r}",
                    DiagnosticLevel.WARNING,
                    binding.span,
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
            for export_binding in exports:
                if (
                    export_binding.module_name is None
                    or not export_binding.module_name.startswith(".")
                    or export_binding.target is not None
                ):
                    continue
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:export:{item.relative_path}:{export_binding.span.start_line}:"
                    f"{export_binding.span.start_column}",
                    DIAGNOSTIC_UNRESOLVED_EXPORT,
                    f"unresolved local re-export {export_binding.module_name!r}",
                    DiagnosticLevel.WARNING,
                    export_binding.span,
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
            for local_name, bindings in _bindings_by_name(imports).items():
                origins = {(binding.module_name, binding.imported_name) for binding in bindings}
                if len(origins) <= 1:
                    continue
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:binding:{item.relative_path}:{local_name}",
                    DIAGNOSTIC_AMBIGUOUS_BINDING,
                    f"ambiguous binding {local_name!r}",
                    DiagnosticLevel.ERROR,
                    bindings[0].span,
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
            for binding in imports:
                if binding.target is None or item.package_path is None:
                    continue
                target_package = nearest_package(binding.target.parent, input_data.project_root)
                if target_package is None or target_package == item.package_path:
                    continue
                diagnostic = Diagnostic(
                    f"diagnostic:frontend:javascript:package-boundary:{item.relative_path}:"
                    f"{binding.span.start_line}:{binding.span.start_column}",
                    DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY,
                    f"local import {binding.module_name!r} crosses package boundary",
                    DiagnosticLevel.ERROR,
                    binding.span,
                )
                diagnostics.append(diagnostic)
                coverage.append(_failure_coverage(diagnostic, item.relative_path, CoverageStatus.ERROR))
        return JavaScriptAnalysis(
            parsed.sources,
            _ordered(summaries),
            _ordered(diagnostics),
            _ordered(coverage),
        )

    def imports(self, item: JavaScriptSource, project_root: Path) -> tuple[JavaScriptImport, ...]:
        """Return source-backed ESM/CJS bindings without framework semantics."""
        imports: list[JavaScriptImport] = []
        for node in walk(item.root):
            if node.type == "import_statement":
                module = node.child_by_field_name("source")
                clause = next((child for child in node.named_children if child.type == "import_clause"), None)
                if module is None or clause is None:
                    continue
                module_name = literal_string(module, item.source)
                if module_name is None:
                    continue
                target = resolve_local_module(item.path, module_name, project_root)
                imports.extend(
                    JavaScriptImport(local, module_name, imported, target, span(item.relative_path, node), kind)
                    for local, imported, kind, node in _import_bindings(clause, item.source)
                )
            elif node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                module_name = required_module(value, item.source) if value is not None else None
                if name is None or module_name is None:
                    continue
                target = resolve_local_module(item.path, module_name, project_root)
                if name.type == "identifier":
                    imports.append(
                        JavaScriptImport(
                            text(name, item.source), module_name, "*", target, span(item.relative_path, name), "cjs"
                        )
                    )
                elif name.type == "object_pattern":
                    for child in name.named_children:
                        binding = _object_pattern_binding(child, item.source)
                        if binding is not None:
                            imported, local = binding
                            imports.append(
                                JavaScriptImport(
                                    local, module_name, imported, target, span(item.relative_path, child), "cjs_named"
                                )
                            )
        return _ordered(imports)

    def exports(self, item: JavaScriptSource, project_root: Path) -> tuple[JavaScriptExport, ...]:
        """Return direct exports and ESM/CJS re-export provenance."""
        exports: list[JavaScriptExport] = []
        for node in walk(item.root):
            if node.type == "export_statement":
                module = node.child_by_field_name("source")
                module_name = literal_string(module, item.source)
                target = resolve_local_module(item.path, module_name, project_root) if module_name else None
                declaration = node.child_by_field_name("declaration")
                if declaration is not None:
                    name = declaration.child_by_field_name("name")
                    local_name = text(name, item.source) if name is not None else None
                    exports.append(
                        JavaScriptExport("default", local_name, None, None, span(item.relative_path, node), "default")
                    )
                export_clause = next((child for child in node.named_children if child.type == "export_clause"), None)
                if export_clause is not None:
                    for specifier in export_clause.named_children:
                        name = specifier.child_by_field_name("name")
                        alias = specifier.child_by_field_name("alias")
                        if name is None:
                            continue
                        local_name = text(name, item.source)
                        exported_name = text(alias, item.source) if alias is not None else local_name
                        exports.append(
                            JavaScriptExport(
                                exported_name,
                                local_name,
                                module_name,
                                target,
                                span(item.relative_path, specifier),
                                "reexport" if module_name else "named",
                            )
                        )
                elif module_name is not None:
                    exports.append(
                        JavaScriptExport("*", None, module_name, target, span(item.relative_path, node), "reexport_all")
                    )
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None or text(left, item.source) != "module.exports":
                    continue
                local_name = text(right, item.source) if right.type == "identifier" else None
                required = required_module(right, item.source)
                target = resolve_local_module(item.path, required, project_root) if required else None
                exports.append(
                    JavaScriptExport(
                        "default",
                        local_name,
                        required,
                        target,
                        span(item.relative_path, node),
                        "cjs_reexport" if required else "cjs",
                    )
                )
        return _ordered(exports)

    def syntax(self, item: JavaScriptSource) -> tuple[JavaScriptSyntax, ...]:
        """Return generic syntax hooks needed by framework adapters."""
        syntax: list[JavaScriptSyntax] = []
        for node in walk(item.root):
            kind = _syntax_kind(node)
            if kind is None:
                continue
            name = node.child_by_field_name("name") or node.child_by_field_name("property")
            syntax.append(
                JavaScriptSyntax(
                    kind,
                    text(node, item.source),
                    span(item.relative_path, node),
                    text(name, item.source) if name is not None else None,
                )
            )
        return _ordered(syntax)

    def local_modules(self, item: JavaScriptSource, project_root: Path) -> tuple[JavaScriptImport, ...]:
        """Return local import bindings for adapter composition."""
        return tuple(binding for binding in self.imports(item, project_root) if binding.module_name.startswith("."))


def nearest_package(start: Path, project_root: Path) -> Path | None:
    """Find nearest manifest without crossing explicit project root."""
    current = start.resolve()
    root = project_root.resolve()
    while current == root or root in current.parents:
        candidate = current / "package.json"
        if candidate.is_file():
            return candidate
        if current == root:
            break
        current = current.parent
    return None


def resolve_local_module(source_path: Path, module_name: str, project_root: Path) -> Path | None:
    """Resolve local modules with explicit suffix precedence and confinement."""
    if not module_name.startswith("."):
        return None
    base = (source_path.parent / module_name).resolve()
    candidates = (
        base,
        *(Path(f"{base}{suffix}") for suffix in SUPPORTED_SUFFIXES),
        *(base / f"index{suffix}" for suffix in SUPPORTED_SUFFIXES),
    )
    root = project_root.resolve()
    return next((path for path in candidates if path.is_file() and (path == root or root in path.parents)), None)


def required_module(node: Node, source: bytes) -> str | None:
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or arguments is None or text(function, source) != "require":
        return None
    args = arguments.named_children
    return literal_string(args[0], source) if len(args) == 1 else None


def module_bindings(
    root: Node,
    source: bytes,
    module_name: str,
    *,
    allowed_imported: frozenset[str] = frozenset({"*", "default"}),
) -> tuple[tuple[str, Node], ...]:
    """Return only aliases whose imported symbol provenance is allowed."""
    bindings: list[tuple[str, Node]] = []
    for node in walk(root):
        if node.type == "import_statement":
            module = node.child_by_field_name("source")
            clause = next((child for child in node.named_children if child.type == "import_clause"), None)
            if module is None or clause is None or literal_string(module, source) != module_name:
                continue
            bindings.extend(
                (local, binding_node)
                for local, imported, _kind, binding_node in _import_bindings(clause, source)
                if imported in allowed_imported
            )
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                name is not None
                and name.type == "identifier"
                and value is not None
                and required_module(value, source) == module_name
            ):
                bindings.append((text(name, source), name))
    return tuple(bindings)


def default_export(root: Node, source: bytes) -> str | None:
    """Return direct default-exported symbol; re-exports remain unresolved."""
    for node in walk(root):
        if node.type == "export_statement":
            module = node.child_by_field_name("source")
            if module is not None:
                continue
            rendered = text(node, source).strip()
            if not rendered.startswith("export default "):
                continue
            identifiers = [child for child in node.named_children if child.type == "identifier"]
            if identifiers:
                return text(identifiers[-1], source)
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if (
                left is not None
                and right is not None
                and right.type == "identifier"
                and text(left, source) == "module.exports"
            ):
                return text(right, source)
    return None


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


def literal_string(node: Node | None, source: bytes) -> str | None:
    if node is None or node.type != "string":
        return None
    return text(node, source)[1:-1]


def _package_boundary(start: Path, project_root: Path) -> PackageBoundary:
    path = nearest_package(start, project_root)
    if path is None:
        return PackageBoundary(None, None, None)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return PackageBoundary(path, None, str(error))
    if not isinstance(data, dict):
        return PackageBoundary(path, None, "package root must be an object")
    return PackageBoundary(path, data, None)


def _import_bindings(clause: Node, source: bytes) -> tuple[tuple[str, str, str, Node], ...]:
    bindings: list[tuple[str, str, str, Node]] = []
    for node in clause.named_children:
        if node.type == "identifier":
            bindings.append((text(node, source), "default", "esm_default", node))
        elif node.type == "namespace_import":
            identifier = next((child for child in node.named_children if child.type == "identifier"), None)
            if identifier is not None:
                bindings.append((text(identifier, source), "*", "esm_namespace", identifier))
        elif node.type == "named_imports":
            for specifier in node.named_children:
                name = specifier.child_by_field_name("name")
                alias = specifier.child_by_field_name("alias")
                if name is None:
                    continue
                imported = text(name, source)
                local_node = alias if alias is not None else name
                bindings.append((text(local_node, source), imported, "esm_named", local_node))
    return tuple(bindings)


def _object_pattern_binding(node: Node, source: bytes) -> tuple[str, str] | None:
    if node.type == "shorthand_property_identifier_pattern":
        name = text(node, source)
        return name, name
    if node.type != "pair_pattern":
        return None
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None or value is None:
        return None
    return text(key, source), text(value, source)


def _syntax_kind(node: Node) -> str | None:
    return {
        "call_expression": "call",
        "member_expression": "property",
        "function_declaration": "handler",
        "arrow_function": "handler",
        "formal_parameters": "parameters",
        "required_parameter": "parameter",
        "identifier": "parameter" if node.parent and node.parent.type == "formal_parameters" else None,
        "decorator": "decorator",
        "comment": "policy_declaration",
    }.get(node.type)


def _bindings_by_name(imports: tuple[JavaScriptImport, ...]) -> dict[str, tuple[JavaScriptImport, ...]]:
    grouped: dict[str, list[JavaScriptImport]] = {}
    for binding in imports:
        grouped.setdefault(binding.local_name, []).append(binding)
    return {name: tuple(items) for name, items in grouped.items()}


def _failure_coverage(
    diagnostic: Diagnostic,
    target_path: str,
    status: CoverageStatus,
) -> JavaScriptFailureCoverage:
    suffix = diagnostic.id.removeprefix("diagnostic:")
    return JavaScriptFailureCoverage(
        f"coverage:{suffix}", target_path, status, diagnostic.id, diagnostic.message
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
