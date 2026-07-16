"""M5-A shared JavaScript frontend: parsing, provenance, diagnostics, coverage."""

from __future__ import annotations

import json
from pathlib import Path

from authmapper.core.v2 import AdapterInput, CoverageStatus, DiagnosticLevel
from authmapper.frontends.javascript import (
    DIAGNOSTIC_AMBIGUOUS_BINDING,
    DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY,
    DIAGNOSTIC_PACKAGE_INVALID,
    DIAGNOSTIC_PARSE_ERROR,
    DIAGNOSTIC_RESOURCE_LIMIT,
    DIAGNOSTIC_UNRESOLVED_EXPORT,
    DIAGNOSTIC_UNRESOLVED_IMPORT,
    DIAGNOSTIC_UNSUPPORTED_SOURCE,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILES,
    JavaScriptFrontend,
    JavaScriptSource,
    nearest_package,
    resolve_local_module,
)


def _input(root: Path, *paths: Path) -> AdapterInput:
    return AdapterInput(root, paths)


def _parse(root: Path, *paths: Path):
    return JavaScriptFrontend().parse(_input(root, *paths))


def test_parses_supported_suffixes_and_preserves_source(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
    js = tmp_path / "a.js"
    mjs = tmp_path / "b.mjs"
    cjs = tmp_path / "c.cjs"
    js.write_text('import x from "express";\n', encoding="utf-8")
    mjs.write_text('const y = require("express");\n', encoding="utf-8")
    cjs.write_text('console.log(1);\n', encoding="utf-8")

    result = _parse(tmp_path, js, mjs, cjs)

    assert [item.relative_path for item in result.sources] == ["a.js", "b.mjs", "c.cjs"]
    assert result.diagnostics == ()
    assert all(isinstance(item, JavaScriptSource) for item in result.sources)
    assert result.sources[0].source.decode("utf-8").splitlines() == ['import x from "express";']


def test_unsupported_suffix_emits_diagnostic_and_skips_source(tmp_path: Path):
    ts = tmp_path / "app.ts"
    ts.write_text('import x from "express";\n', encoding="utf-8")

    result = _parse(tmp_path, ts)

    assert result.sources == ()
    assert [d.code for d in result.diagnostics] == [DIAGNOSTIC_UNSUPPORTED_SOURCE]
    assert result.diagnostics[0].level is DiagnosticLevel.WARNING
    assert [(item.target_path, item.status) for item in result.coverage] == [
        ("app.ts", CoverageStatus.UNSUPPORTED)
    ]


def test_parse_error_emits_diagnostic_and_skips_source(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    broken = tmp_path / "broken.js"
    broken.write_text('const x = (;\n', encoding="utf-8")

    result = _parse(tmp_path, broken)

    assert result.sources == ()
    assert [d.code for d in result.diagnostics] == [DIAGNOSTIC_PARSE_ERROR]
    assert result.diagnostics[0].level is DiagnosticLevel.ERROR
    assert result.coverage[0].diagnostic_id == result.diagnostics[0].id
    assert result.coverage[0].status is CoverageStatus.ERROR


def test_oversized_source_emits_resource_diagnostic(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    big = tmp_path / "big.js"
    big.write_bytes(b" " * (MAX_SOURCE_BYTES + 1))

    result = _parse(tmp_path, big)

    assert result.sources == ()
    assert [d.code for d in result.diagnostics] == [DIAGNOSTIC_RESOURCE_LIMIT]
    assert result.coverage[0].status is CoverageStatus.ERROR


def test_file_count_limit_emits_resource_diagnostic(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    files = tuple(tmp_path / f"f{i}.js" for i in range(3))
    for path in files:
        path.write_text(";\n", encoding="utf-8")
    too_many = files + tuple(tmp_path / f"g{i}.js" for i in range(MAX_SOURCE_FILES))

    result = _parse(tmp_path, *too_many)

    assert result.sources == ()
    assert [d.code for d in result.diagnostics] == [DIAGNOSTIC_RESOURCE_LIMIT]
    assert result.coverage[0].target_path == "<project>"


def test_package_boundary_records_nearest_manifest_and_invalid_manifest_diagnostic(tmp_path: Path):
    (tmp_path / "package.json").write_text("not json", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text("console.log(1);\n", encoding="utf-8")

    result = _parse(tmp_path, src)

    assert len(result.sources) == 1
    package = result.sources[0].package
    assert package.path == tmp_path / "package.json"
    assert package.data is None
    assert package.error is not None
    assert [d.code for d in result.diagnostics] == [DIAGNOSTIC_PACKAGE_INVALID]
    assert result.coverage[0].target_path == "app.js"


def test_non_object_package_manifest_is_invalid(tmp_path: Path):
    (tmp_path / "package.json").write_text("[]", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text("console.log(1);\n", encoding="utf-8")

    result = _parse(tmp_path, src)

    assert result.sources[0].package.error == "package root must be an object"
    assert [item.code for item in result.diagnostics] == [DIAGNOSTIC_PACKAGE_INVALID]
    assert result.coverage[0].status is CoverageStatus.ERROR


def test_package_boundary_finds_nearest_nested_manifest(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "root"}), encoding="utf-8")
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "package.json").write_text(json.dumps({"name": "nested"}), encoding="utf-8")
    src = nested / "app.js"
    src.write_text("console.log(1);\n", encoding="utf-8")

    result = _parse(tmp_path, src)

    assert result.sources[0].package.data == {"name": "nested"}


def test_cross_package_local_import_is_explicitly_ambiguous(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"root"}', encoding="utf-8")
    sibling = tmp_path / "packages" / "sibling"
    sibling.mkdir(parents=True)
    (sibling / "package.json").write_text('{"name":"sibling"}', encoding="utf-8")
    (sibling / "value.js").write_text("module.exports = 1;\n", encoding="utf-8")
    app = tmp_path / "packages" / "app"
    app.mkdir()
    (app / "package.json").write_text('{"name":"app"}', encoding="utf-8")
    source = app / "index.js"
    source.write_text('const value = require("../sibling/value");\n', encoding="utf-8")

    analysis = JavaScriptFrontend().analyze(_input(tmp_path, source))

    assert [item.code for item in analysis.diagnostics] == [DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY]
    assert analysis.coverage[0].status is CoverageStatus.ERROR


def test_resolve_local_module_suffix_precedence_is_deterministic(tmp_path: Path):
    base = tmp_path / "mod"
    base.write_text("module.exports = 1;\n", encoding="utf-8")
    (tmp_path / "mod.js").write_text("module.exports = 2;\n", encoding="utf-8")

    resolved = resolve_local_module(tmp_path / "app.js", "./mod", tmp_path)

    assert resolved == base.resolve()


def test_resolve_local_module_index_fallback(tmp_path: Path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

    resolved = resolve_local_module(tmp_path / "app.js", "./pkg", tmp_path)

    assert resolved == (pkg / "index.js").resolve()


def test_resolve_local_module_rejects_external_packages(tmp_path: Path):
    resolved = resolve_local_module(tmp_path / "app.js", "express", tmp_path)
    assert resolved is None


def test_resolve_local_module_confined_to_project_root(tmp_path: Path):
    outside = tmp_path.parent / "escape.js"
    resolved = resolve_local_module(tmp_path / "app.js", "../escape", tmp_path)
    assert resolved is None
    _ = outside  # avoid unused warnings even if file does not exist


def test_nearest_package_does_not_cross_project_root(tmp_path: Path):
    src_dir = tmp_path / "deep" / "dir"
    src_dir.mkdir(parents=True)

    resolved = nearest_package(src_dir, tmp_path)

    assert resolved is None


def test_imports_resolve_cjs_and_esm_local_bindings(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "cjs.js").write_text("module.exports = {};\n", encoding="utf-8")
    (tmp_path / "esm.js").write_text("export const x = 1;\n", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text(
        'const cjs = require("./cjs");\n'
        'import { esm } from "./esm";\n'
        'const external = require("express");\n',
        encoding="utf-8",
    )

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    imports = frontend.imports(result.sources[0], tmp_path)

    local_names = {item.local_name for item in imports}
    assert {"cjs", "esm"}.issubset(local_names)
    assert all(item.target is not None for item in imports if item.module_name.startswith("."))
    external = next(item for item in imports if item.module_name == "express")
    assert external.target is None


def test_imports_preserve_unresolved_local_module_target(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text('const missing = require("./missing");\n', encoding="utf-8")

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    imports = frontend.imports(result.sources[0], tmp_path)

    assert len(imports) == 1
    assert imports[0].module_name == "./missing"
    assert imports[0].target is None

    analysis = frontend.analyze(_input(tmp_path, src))
    assert [item.code for item in analysis.diagnostics] == [DIAGNOSTIC_UNRESOLVED_IMPORT]
    assert analysis.coverage[0].diagnostic_id == analysis.diagnostics[0].id


def test_reexports_preserve_alias_and_module_provenance(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "router.js").write_text("export const router = {};\n", encoding="utf-8")
    src = tmp_path / "index.js"
    src.write_text('export { router as api } from "./router";\n', encoding="utf-8")

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    exports = frontend.exports(result.sources[0], tmp_path)

    assert [(item.exported_name, item.local_name, item.module_name, item.kind) for item in exports] == [
        ("api", "router", "./router", "reexport")
    ]
    assert exports[0].target == (tmp_path / "router.js").resolve()


def test_named_export_declarations_are_not_reported_as_default(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "index.js"
    src.write_text(
        "export const handler = () => {};\n"
        "export function outer() { function nested() {} }\n"
        "export default 42;\n",
        encoding="utf-8",
    )

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    exports = frontend.exports(result.sources[0], tmp_path)

    assert [(item.exported_name, item.local_name, item.kind) for item in exports] == [
        ("default", None, "default"),
        ("handler", "handler", "named"),
        ("outer", "outer", "named"),
    ]


def test_default_export_with_comments_preserves_identifier(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    source = tmp_path / "app.js"
    source.write_text("const app = {};\nexport /* comment */ default app;\n", encoding="utf-8")

    frontend = JavaScriptFrontend()
    parsed = frontend.parse(_input(tmp_path, source))
    exports = frontend.exports(parsed.sources[0], tmp_path)

    assert [(item.exported_name, item.local_name, item.kind) for item in exports] == [
        ("default", "app", "default")
    ]


def test_destructured_export_does_not_fabricate_symbol_name(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    source = tmp_path / "app.js"
    source.write_text("export const {first, source: alias} = value;\n", encoding="utf-8")

    frontend = JavaScriptFrontend()
    parsed = frontend.parse(_input(tmp_path, source))
    exports = frontend.exports(parsed.sources[0], tmp_path)

    assert exports == ()


def test_unresolved_reexport_emits_diagnostic_and_coverage(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "index.js"
    src.write_text('export { router } from "./missing";\n', encoding="utf-8")

    analysis = JavaScriptFrontend().analyze(_input(tmp_path, src))

    assert [item.code for item in analysis.diagnostics] == [DIAGNOSTIC_UNRESOLVED_EXPORT]
    assert analysis.coverage[0].status is CoverageStatus.ERROR


def test_conflicting_local_aliases_are_explicitly_ambiguous(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text('import x from "one";\nimport { y as x } from "two";\n', encoding="utf-8")

    analysis = JavaScriptFrontend().analyze(_input(tmp_path, src))

    assert [item.code for item in analysis.diagnostics] == [DIAGNOSTIC_AMBIGUOUS_BINDING]
    assert analysis.coverage[0].target_path == "app.js"


def test_generic_syntax_hooks_include_calls_properties_handlers_and_parameters(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text("function handler(req) { return service.run(req); }\n", encoding="utf-8")

    analysis = JavaScriptFrontend().analyze(_input(tmp_path, src))

    kinds = {item.kind for item in analysis.summaries[0].syntax}
    assert {"call", "property", "handler", "parameters", "parameter"} <= kinds


def test_local_modules_returns_only_local_bindings(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "local.js").write_text("module.exports = {};\n", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text(
        'const local = require("./local");\nconst external = require("express");\n',
        encoding="utf-8",
    )

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    modules = frontend.local_modules(result.sources[0], tmp_path)

    assert [item.local_name for item in modules] == ["local"]
    assert modules[0].target is not None


def test_source_span_is_one_based(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text('import x from "./missing";\n', encoding="utf-8")

    frontend = JavaScriptFrontend()
    result = frontend.parse(_input(tmp_path, src))
    imports = frontend.imports(result.sources[0], tmp_path)

    span = imports[0].span
    assert span.start_line == 1
    assert span.start_column >= 1


def test_frontend_emits_no_verdict_or_severity():
    """Frontend diagnostics never carry verdict or severity semantics."""
    from dataclasses import fields

    from authmapper.frontends.javascript import (
        JavaScriptAnalysis,
        JavaScriptExport,
        JavaScriptFailureCoverage,
        JavaScriptFrontendResult,
        JavaScriptImport,
        JavaScriptModuleSummary,
        JavaScriptSyntax,
    )

    contracts = (
        JavaScriptAnalysis,
        JavaScriptExport,
        JavaScriptFailureCoverage,
        JavaScriptFrontendResult,
        JavaScriptImport,
        JavaScriptModuleSummary,
        JavaScriptSource,
        JavaScriptSyntax,
    )
    for contract in contracts:
        names = {field.name for field in fields(contract)}
        assert not ({"adapter_id", "auth", "proof", "severity", "verdict"} & names)


def test_results_are_deterministic_across_invocations(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    a = tmp_path / "a.js"
    b = tmp_path / "b.js"
    a.write_text("console.log(1);\n", encoding="utf-8")
    b.write_text("console.log(2);\n", encoding="utf-8")

    first = _parse(tmp_path, b, a)
    second = _parse(tmp_path, a, b)

    assert [s.relative_path for s in first.sources] == [s.relative_path for s in second.sources]
    assert first.diagnostics == second.diagnostics


def test_module_bindings_returns_external_alias(tmp_path: Path):
    from authmapper.frontends.javascript import module_bindings

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text(
        'const passport = require("passport");\n'
        'import jwt from "passport";\n',
        encoding="utf-8",
    )

    result = _parse(tmp_path, src)
    bindings = module_bindings(result.sources[0].root, result.sources[0].source, "passport")

    names = {name for name, _ in bindings}
    assert names == {"passport", "jwt"}


def test_module_bindings_excludes_named_export_alias(tmp_path: Path):
    from authmapper.frontends.javascript import module_bindings

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    src = tmp_path / "app.js"
    src.write_text('import { Strategy as passport } from "passport";\n', encoding="utf-8")

    result = _parse(tmp_path, src)
    bindings = module_bindings(result.sources[0].root, result.sources[0].source, "passport")

    assert bindings == ()


def test_diagnostic_codes_are_stable_strings():
    """All diagnostic codes are namespaced stable identifiers, not adapter-specific."""
    codes = {
        DIAGNOSTIC_PARSE_ERROR,
        DIAGNOSTIC_UNSUPPORTED_SOURCE,
        DIAGNOSTIC_RESOURCE_LIMIT,
        DIAGNOSTIC_PACKAGE_INVALID,
    }
    for code in codes:
        assert code.startswith("frontend.javascript.")
        assert "." not in code[len("frontend.javascript.") :]
