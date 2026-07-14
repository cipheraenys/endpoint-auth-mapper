"""Integration tests: engine against language fixtures."""

from __future__ import annotations

from pathlib import Path

from authmapper.core.engine import Engine, EngineConfig
from authmapper.core.model import AuthState, CoverageStatus
from authmapper.core.rulepack import load_rulepacks


def _scan(root: Path):
    engine = Engine(load_rulepacks())
    return engine.scan(root)


def _by_route(result):
    return {f.endpoint.route: f for f in result.findings}


def test_node_fixture_classification(fixtures_dir: Path):
    result = _scan(fixtures_dir / "node")
    routes = _by_route(result)

    assert routes["/api/admin/delete-user"].auth_state is AuthState.EXPOSED
    assert routes["/api/profile"].auth_state is AuthState.PROTECTED
    assert routes["/health"].auth_state is AuthState.EXPOSED


def test_project_public_declaration_is_explicit(fixtures_dir: Path):
    engine = Engine(load_rulepacks(), EngineConfig(public_paths=("/health",)))
    routes = _by_route(engine.scan(fixtures_dir / "node"))

    assert routes["/health"].auth_state is AuthState.PUBLIC


def test_file_scope_auth_does_not_protect_sibling_route(tmp_path: Path):
    (tmp_path / "routes.js").write_text(
        'app.use(requireAuth)\n'
        'app.get("/guarded", requireAuth, handler)\n'
        'app.get("/sibling", handler)\n',
        encoding="utf-8",
    )

    routes = _by_route(_scan(tmp_path))

    assert routes["/guarded"].auth_state is AuthState.PROTECTED
    assert routes["/sibling"].auth_state is AuthState.UNKNOWN
    assert routes["/sibling"].evidence[0].signal == "router-level-guard"


def test_every_eligible_source_has_one_coverage_status(tmp_path: Path):
    (tmp_path / "analyzed.js").write_text('app.get("/ok", handler)\n', encoding="utf-8")
    (tmp_path / "binary.js").write_bytes(b"app.get(\x00)")
    (tmp_path / "unsupported.rs").write_text("fn main() {}\n", encoding="utf-8")
    excluded = tmp_path / "excluded"
    excluded.mkdir()
    (excluded / "route.js").write_text('app.get("/excluded", handler)\n', encoding="utf-8")

    result = Engine(load_rulepacks()).scan(tmp_path, extra_excludes=("excluded",))
    coverage = {record.file: record.status for record in result.coverage}

    assert coverage == {
        "analyzed.js": CoverageStatus.ANALYZED,
        "binary.js": CoverageStatus.SKIPPED,
        "excluded/route.js": CoverageStatus.EXCLUDED,
        "unsupported.rs": CoverageStatus.UNSUPPORTED,
    }


def test_analysis_failure_has_error_coverage(tmp_path: Path, monkeypatch):
    source = tmp_path / "route.js"
    source.write_text('app.get("/error", handler)\n', encoding="utf-8")
    engine = Engine(load_rulepacks())

    def fail_analysis(*_args, **_kwargs):
        raise RuntimeError("analysis failed")

    monkeypatch.setattr(engine, "_analyze_file", fail_analysis)
    result = engine.scan(tmp_path)

    assert result.coverage[0].status is CoverageStatus.ERROR
    assert result.errors[0].message.endswith("analysis failed")


def test_php_fixture_classification(fixtures_dir: Path):
    result = _scan(fixtures_dir / "php")
    states = {f.endpoint.file.split("/")[-1]: f.auth_state for f in result.findings}

    # No auth include -> not PROTECTED (UNKNOWN under the coarse file model).
    assert states["api_users.php"] is not AuthState.PROTECTED
    # File-wide auth presence is evidence, not proof of endpoint association.
    assert states["dashboard.php"] is AuthState.UNKNOWN


def test_custom_rulepack_extension_is_analyzed(tmp_path: Path):
    from authmapper.core.rulepack import load_rulepack

    pack = load_rulepack(
        {
            "name": "custom-swift",
            "language": "swift",
            "file_globs": ["**/*.swift"],
            "endpoint_patterns": [
                {"id": "route", "regex": 'route\\("([^\"]+)"', "capture": {"path": 1}}
            ],
            "auth_signals": [{"id": "auth", "regex": "requireAuth", "scope": "same_line"}],
        },
        source_name="custom-swift",
    )
    (tmp_path / "routes.swift").write_text('route("/custom")\n', encoding="utf-8")

    result = Engine([pack]).scan(tmp_path)

    assert result.coverage[0].status is CoverageStatus.ANALYZED
    assert result.coverage[0].rulepacks == ("custom-swift",)


def test_scan_is_deterministic(fixtures_dir: Path):
    first = _scan(fixtures_dir / "node").sorted_findings()
    second = _scan(fixtures_dir / "node").sorted_findings()
    assert [f.endpoint.identity for f in first] == [f.endpoint.identity for f in second]
