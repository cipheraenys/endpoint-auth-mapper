"""M5-E reproducible metrics for independent frontend-only projects."""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from authmapper.core.v2 import AdapterInput
from authmapper.frontends.javascript import JavaScriptFrontend
from authmapper.frontends.rust import MAX_SOURCE_BYTES as RUST_MAX_SOURCE_BYTES
from authmapper.frontends.rust import RustFrontend

MIN_PRECISION = 0.98
MIN_RECALL = 0.95
_SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".rs"}


@pytest.fixture
def corpus(fixtures_dir: Path) -> tuple[Path, dict[str, Any]]:
    root = fixtures_dir / "frontend_evaluation"
    return root, json.loads((root / "labels.json").read_text(encoding="utf-8"))


def test_javascript_frontend_independent_precision_and_recall(corpus: tuple[Path, dict[str, Any]]):
    root, manifest = corpus
    observed: dict[str, set[tuple[object, ...]]] = {}
    expected: dict[str, set[tuple[object, ...]]] = {}
    for project in manifest["javascript"]["projects"]:
        project_root = root / "javascript" / project["name"]
        analysis = JavaScriptFrontend().analyze(AdapterInput(project_root, _source_paths(project_root, project)))
        _merge(expected, project["labels"], project["name"])
        _merge(
            observed,
            {
                "imports": (
                    (
                        summary.path,
                        item.local_name,
                        item.module_name,
                        item.imported_name,
                        item.kind,
                        _relative(item.target, project_root),
                    )
                    for summary in analysis.summaries
                    for item in summary.imports
                ),
                "exports": (
                    (
                        summary.path,
                        item.exported_name,
                        item.local_name,
                        item.module_name,
                        item.kind,
                        _relative(item.target, project_root),
                    )
                    for summary in analysis.summaries
                    for item in summary.exports
                ),
                "syntax": (
                    (summary.path, item.kind, item.span.start_line, item.span.start_column)
                    for summary in analysis.summaries
                    for item in summary.syntax
                ),
                "diagnostics": (
                    (item.span.path if item.span else "", item.code, item.span.start_line if item.span else 1)
                    for item in analysis.diagnostics
                ),
            },
            project["name"],
        )

    _assert_metrics(expected, observed)


def test_rust_frontend_independent_precision_and_recall(corpus: tuple[Path, dict[str, Any]]):
    root, manifest = corpus
    observed: dict[str, set[tuple[object, ...]]] = {}
    expected: dict[str, set[tuple[object, ...]]] = {}
    for project in manifest["rust"]["projects"]:
        project_root = root / "rust" / project["name"]
        analysis = RustFrontend().analyze(AdapterInput(project_root, _source_paths(project_root, project)))
        _merge(expected, project["labels"], project["name"])
        _merge(
            observed,
            {
                "dependencies": (
                    (
                        package.relative_manifest_path,
                        item.alias,
                        item.package_name,
                        item.kind,
                        item.inherited,
                    )
                    for package in analysis.packages
                    for item in package.dependencies
                ),
                "uses": (
                    (
                        summary.path,
                        item.local_name,
                        item.imported_name,
                        item.path,
                        item.origin,
                        item.public,
                        item.glob,
                    )
                    for summary in analysis.summaries
                    for item in summary.uses
                ),
                "modules": (
                    (summary.path, item.name, item.inline, _relative(item.target, project_root))
                    for summary in analysis.summaries
                    for item in summary.modules
                ),
                "syntax": (
                    (summary.path, item.kind, item.span.start_line, item.span.start_column)
                    for summary in analysis.summaries
                    for item in summary.syntax
                ),
                "diagnostics": (
                    (item.span.path if item.span else "", item.code, item.span.start_line if item.span else 1)
                    for item in analysis.diagnostics
                ),
            },
            project["name"],
        )

    _assert_metrics(expected, observed)


def test_corpus_is_frontend_only_and_separate_from_unit_fixtures(corpus: tuple[Path, dict[str, Any]]):
    root, manifest = corpus
    assert root.name == "frontend_evaluation"
    serialized = json.dumps(manifest).lower()
    assert not {"auth", "verdict", "guarded", "severity"} & set(serialized.replace('"', " ").split())
    projects = tuple(
        (language, project)
        for language in ("javascript", "rust")
        for project in manifest[language]["projects"]
    )
    assert len(projects) == 7
    assert all(
        (root / language / project["name"] / path).is_file()
        for language, project in projects
        for path in project["files"]
    )


def test_frontend_corpus_is_deterministic_and_bounded(corpus: tuple[Path, dict[str, Any]]):
    root, manifest = corpus
    for language, frontend in (("javascript", JavaScriptFrontend()), ("rust", RustFrontend())):
        for project in manifest[language]["projects"]:
            project_root = root / language / project["name"]
            source_paths = _source_paths(project_root, project)
            first = frontend.analyze(AdapterInput(project_root, source_paths))
            second = frontend.analyze(AdapterInput(project_root, tuple(reversed(source_paths))))
            assert _analysis_projection(first) == _analysis_projection(second)


def test_frontend_corpus_never_executes_subprocess(corpus: tuple[Path, dict[str, Any]], monkeypatch):
    root, manifest = corpus

    def forbidden(*_args, **_kwargs):
        raise AssertionError("frontend corpus executed a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for language, frontend in (("javascript", JavaScriptFrontend()), ("rust", RustFrontend())):
        for project in manifest[language]["projects"]:
            project_root = root / language / project["name"]
            frontend.analyze(AdapterInput(project_root, _source_paths(project_root, project)))


def test_frontend_resource_corpus_is_deterministic(tmp_path: Path):
    javascript_root = tmp_path / "javascript"
    javascript_root.mkdir()
    (javascript_root / "package.json").write_text("{}", encoding="utf-8")
    javascript_source = javascript_root / "oversized.js"
    javascript_source.write_bytes(b" " * (RUST_MAX_SOURCE_BYTES + 1))

    rust_root = tmp_path / "rust"
    rust_source_dir = rust_root / "src"
    rust_source_dir.mkdir(parents=True)
    (rust_root / "Cargo.toml").write_text(
        '[package]\nname = "resource-corpus"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    rust_source = rust_source_dir / "oversized.rs"
    rust_source.write_bytes(b" " * (RUST_MAX_SOURCE_BYTES + 1))

    javascript = JavaScriptFrontend().analyze(AdapterInput(javascript_root, (javascript_source,)))
    rust = RustFrontend().analyze(AdapterInput(rust_root, (rust_source,)))

    assert [(item.code, item.level.value) for item in javascript.diagnostics] == [
        ("frontend.javascript.resource_limit", "error")
    ]
    assert [(item.code, item.level.value) for item in rust.diagnostics] == [
        ("frontend.rust.resource_limit", "error")
    ]
    assert javascript.coverage[0].diagnostic_id == javascript.diagnostics[0].id
    assert rust.coverage[0].diagnostic_id == rust.diagnostics[0].id


def _source_paths(project_root: Path, project: dict[str, Any]) -> tuple[Path, ...]:
    return tuple(
        project_root / relative
        for relative in project["files"]
        if Path(relative).suffix in _SOURCE_SUFFIXES
    )


def _analysis_projection(analysis) -> tuple[object, ...]:
    return (
        tuple(item.relative_path for item in analysis.sources),
        getattr(analysis, "packages", ()),
        analysis.summaries,
        analysis.diagnostics,
        analysis.coverage,
    )


def _relative(path: Path | None, root: Path) -> str | None:
    return path.resolve().relative_to(root.resolve()).as_posix() if path is not None else None


def _merge(
    target: dict[str, set[tuple[object, ...]]],
    values: dict[str, Iterable[Iterable[object]]],
    project: str,
) -> None:
    for capability, items in values.items():
        target.setdefault(capability, set()).update((project, *item) for item in items)


def _assert_metrics(
    expected: dict[str, set[tuple[object, ...]]],
    observed: dict[str, set[tuple[object, ...]]],
) -> None:
    for capability, labels in expected.items():
        actual = observed.get(capability, set())
        true_positive = len(labels & actual)
        precision = true_positive / len(actual) if actual else 0.0
        recall = true_positive / len(labels) if labels else 1.0
        if precision < MIN_PRECISION:
            raise AssertionError(
                f"{capability} precision {precision:.3f}; missed={labels - actual!r}; extra={actual - labels!r}"
            )
        if recall < MIN_RECALL:
            raise AssertionError(
                f"{capability} recall {recall:.3f}; missed={labels - actual!r}; extra={actual - labels!r}"
            )
