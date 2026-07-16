"""M5-B shared Rust frontend provenance, failure, and safety tests."""

from __future__ import annotations

import subprocess
from dataclasses import fields
from pathlib import Path

from authmapper.core.v2 import AdapterInput, CoverageStatus
from authmapper.frontends.rust import (
    DIAGNOSTIC_MANIFEST_INHERITANCE,
    DIAGNOSTIC_MANIFEST_PARSE_ERROR,
    DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY,
    DIAGNOSTIC_PARSE_ERROR,
    DIAGNOSTIC_RESOURCE_LIMIT,
    DIAGNOSTIC_UNRESOLVED_MODULE,
    DIAGNOSTIC_UNRESOLVED_USE,
    DIAGNOSTIC_UNSUPPORTED_CFG,
    DIAGNOSTIC_UNSUPPORTED_MACRO,
    DIAGNOSTIC_UNSUPPORTED_SOURCE,
    MAX_SOURCE_BYTES,
    RustAnalysis,
    RustFailureCoverage,
    RustFrontend,
    RustModule,
    RustModuleSummary,
    RustSource,
    RustSyntax,
    RustUse,
)


def _write_package(root: Path, manifest: str = '[package]\nname = "service"\nversion = "0.1.0"\n') -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
    source = root / "src"
    source.mkdir()
    return source


def _analyze(root: Path, *paths: Path) -> RustAnalysis:
    return RustFrontend().analyze(AdapterInput(root, paths))


def test_parser_pin_is_abi_compatible():
    import importlib.metadata

    assert importlib.metadata.version("tree-sitter") == "0.25.2"
    assert importlib.metadata.version("tree-sitter-rust") == "0.24.2"
    assert importlib.metadata.version("tomli") == "2.4.1"


def test_parses_rust_and_preserves_user_source_span(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("fn handler(user: User) { service.call(user); }\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert result.diagnostics == ()
    assert result.sources[0].relative_path == "src/lib.rs"
    assert result.packages[0].name == "service"
    function = next(item for item in result.summaries[0].syntax if item.kind == "function")
    assert (function.span.path, function.span.start_line, function.span.start_column) == ("src/lib.rs", 1, 1)
    assert {item.kind for item in result.summaries[0].syntax} >= {
        "call",
        "function",
        "method_call",
        "parameter",
        "parameters",
        "type",
    }


def test_resolves_dependency_alias_and_nested_use_tree(tmp_path: Path):
    source_dir = _write_package(
        tmp_path,
        '[package]\nname = "service"\nversion = "0.1.0"\n'
        '[dependencies]\nweb = { package = "axum", version = "1" }\n',
    )
    source = source_dir / "lib.rs"
    source.write_text("use web::{Router, routing::get as route};\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    dependency = result.packages[0].dependencies[0]
    assert (dependency.alias, dependency.package_name, dependency.kind) == ("web", "axum", "dependencies")
    assert {(item.local_name, item.imported_name, item.origin) for item in result.summaries[0].uses} == {
        ("Router", "Router", "axum"),
        ("route", "get", "axum"),
    }


def test_cargo_hyphenated_alias_resolves_rust_identifier(tmp_path: Path):
    source_dir = _write_package(
        tmp_path,
        '[package]\nname = "service"\nversion = "0.1.0"\n'
        '[dependencies]\ntower-http = "1"\n',
    )
    source = source_dir / "lib.rs"
    source.write_text("use tower_http::trace::TraceLayer;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert result.diagnostics == ()
    assert result.summaries[0].uses[0].origin == "tower-http"


def test_resolves_workspace_inherited_dependency_alias(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["service"]\n[workspace.dependencies]\nweb = { package = "axum", version = "1" }\n',
        encoding="utf-8",
    )
    service = tmp_path / "service"
    source_dir = _write_package(
        service,
        '[package]\nname = "service"\nversion = "0.1.0"\n[dependencies]\nweb = { workspace = true }\n',
    )
    source = source_dir / "lib.rs"
    source.write_text("use web::Router;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    dependency = result.packages[0].dependencies[0]
    assert (dependency.alias, dependency.package_name, dependency.inherited) == ("web", "axum", True)
    assert result.summaries[0].uses[0].origin == "axum"


def test_missing_workspace_dependency_fails_closed(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["service"]\n', encoding="utf-8")
    service = tmp_path / "service"
    source_dir = _write_package(
        service,
        '[package]\nname = "service"\nversion = "0.1.0"\n[dependencies]\nweb = { workspace = true }\n',
    )
    source = source_dir / "lib.rs"
    source.write_text("use web::Router;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert {item.code for item in result.diagnostics} == {
        DIAGNOSTIC_MANIFEST_INHERITANCE,
        DIAGNOSTIC_UNRESOLVED_USE,
    }
    assert result.packages[0].dependencies == ()


def test_public_use_keeps_reexport_provenance(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("pub use crate::auth::Guard as AuthGuard;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    use = result.summaries[0].uses[0]
    assert (use.local_name, use.imported_name, use.path, use.origin, use.public) == (
        "AuthGuard",
        "Guard",
        "crate::auth::Guard",
        "local",
        True,
    )


def test_restricted_public_use_keeps_reexport_provenance(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("pub(crate) use crate::auth::Guard;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    use = result.summaries[0].uses[0]
    assert (use.path, use.origin, use.public) == ("crate::auth::Guard", "local", True)


def test_resolves_external_module_file_and_inline_module(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    module = source_dir / "api.rs"
    module.write_text("pub fn handler() {}\n", encoding="utf-8")
    source.write_text("mod api;\nmod inline { pub fn handler() {} }\n", encoding="utf-8")

    result = _analyze(tmp_path, source, module)

    modules = next(item.modules for item in result.summaries if item.path == "src/lib.rs")
    assert [(item.name, item.inline) for item in modules] == [("api", False), ("inline", True)]
    assert modules[0].target == module.resolve()


def test_missing_and_ambiguous_modules_are_explicit(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("mod missing;\nmod duplicate;\n", encoding="utf-8")
    (source_dir / "duplicate.rs").write_text("", encoding="utf-8")
    duplicate = source_dir / "duplicate"
    duplicate.mkdir()
    (duplicate / "mod.rs").write_text("", encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert [item.code for item in result.diagnostics] == [
        DIAGNOSTIC_UNRESOLVED_MODULE,
        DIAGNOSTIC_UNRESOLVED_MODULE,
    ]
    assert all(item.status is CoverageStatus.UNSUPPORTED for item in result.coverage)


def test_nested_and_custom_path_modules_do_not_fabricate_targets(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text('mod outer { mod child; }\n#[path = "actual.rs"] mod custom;\n', encoding="utf-8")
    outer = source_dir / "outer"
    outer.mkdir()
    child = outer / "child.rs"
    child.write_text("", encoding="utf-8")
    (source_dir / "custom.rs").write_text("", encoding="utf-8")
    (source_dir / "actual.rs").write_text("", encoding="utf-8")

    result = _analyze(tmp_path, source)

    modules = result.summaries[0].modules
    nested = next(item for item in modules if item.name == "child")
    custom = next(item for item in modules if item.name == "custom")
    assert nested.target == child.resolve()
    assert custom.target is None
    assert [item.code for item in result.diagnostics] == [DIAGNOSTIC_UNRESOLVED_MODULE]


def test_macro_and_cfg_are_visible_without_expansion(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text('#[cfg(feature = "admin")]\nfn handler() { route!("/admin"); }\n', encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert {item.code for item in result.diagnostics} == {
        DIAGNOSTIC_UNSUPPORTED_CFG,
        DIAGNOSTIC_UNSUPPORTED_MACRO,
    }
    assert all(item.status is CoverageStatus.UNSUPPORTED for item in result.coverage)


def test_field_access_is_property_not_method_call(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("fn handler(user: User) { let _ = user.name; user.login(); }\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    fields_by_text = {(item.text, item.kind) for item in result.summaries[0].syntax if "." in item.text}
    assert ("user.name", "property") in fields_by_text
    assert ("user.login", "method_call") in fields_by_text


def test_unresolved_external_use_is_visible(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("use undeclared::Guard;\n", encoding="utf-8")

    result = _analyze(tmp_path, source)

    assert [item.code for item in result.diagnostics] == [DIAGNOSTIC_UNRESOLVED_USE]
    assert result.coverage[0].status is CoverageStatus.UNSUPPORTED


def test_invalid_manifest_and_missing_package_fail_closed(tmp_path: Path):
    source_dir = _write_package(tmp_path, "[")
    source = source_dir / "lib.rs"
    source.write_text("fn main() {}\n", encoding="utf-8")

    invalid = _analyze(tmp_path, source)
    assert [item.code for item in invalid.diagnostics] == [DIAGNOSTIC_MANIFEST_PARSE_ERROR]
    assert invalid.coverage[0].status is CoverageStatus.ERROR

    standalone = tmp_path / "standalone"
    standalone.mkdir()
    orphan = standalone / "lib.rs"
    orphan.write_text("fn main() {}\n", encoding="utf-8")
    missing = _analyze(standalone, orphan)
    assert [item.code for item in missing.diagnostics] == [DIAGNOSTIC_PACKAGE_BOUNDARY_AMBIGUITY]


def test_parse_unsupported_and_resource_failures_have_coverage(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    broken = source_dir / "broken.rs"
    broken.write_text("fn broken( {\n", encoding="utf-8")
    unsupported = source_dir / "notes.txt"
    unsupported.write_text("not rust\n", encoding="utf-8")
    large = source_dir / "large.rs"
    large.write_bytes(b" " * (MAX_SOURCE_BYTES + 1))

    result = _analyze(tmp_path, broken, unsupported, large)

    assert {item.code for item in result.diagnostics} == {
        DIAGNOSTIC_PARSE_ERROR,
        DIAGNOSTIC_RESOURCE_LIMIT,
        DIAGNOSTIC_UNSUPPORTED_SOURCE,
    }
    assert len(result.coverage) == len(result.diagnostics)
    assert {item.status for item in result.coverage} == {CoverageStatus.ERROR, CoverageStatus.UNSUPPORTED}


def test_frontend_never_invokes_cargo_or_subprocess(tmp_path: Path, monkeypatch):
    source_dir = _write_package(tmp_path)
    source = source_dir / "lib.rs"
    source.write_text("fn main() {}\n", encoding="utf-8")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Rust frontend executed a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = _analyze(tmp_path, source)

    assert result.diagnostics == ()


def test_frontend_contracts_have_no_semantic_or_verdict_fields():
    contracts = (
        RustAnalysis,
        RustFailureCoverage,
        RustModule,
        RustModuleSummary,
        RustSource,
        RustSyntax,
        RustUse,
    )
    forbidden = {"adapter_id", "auth", "proof", "severity", "verdict"}
    for contract in contracts:
        assert not (forbidden & {field.name for field in fields(contract)})


def test_results_are_deterministic_across_input_order(tmp_path: Path):
    source_dir = _write_package(tmp_path)
    first = source_dir / "a.rs"
    second = source_dir / "b.rs"
    first.write_text("fn a() {}\n", encoding="utf-8")
    second.write_text("fn b() {}\n", encoding="utf-8")

    left = _analyze(tmp_path, second, first)
    right = _analyze(tmp_path, first, second)

    assert [item.relative_path for item in left.sources] == [item.relative_path for item in right.sources]
    assert left.summaries == right.summaries
