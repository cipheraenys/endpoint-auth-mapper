"""Integration tests: engine against language fixtures."""

from __future__ import annotations

from pathlib import Path

from authmapper.core.engine import Engine
from authmapper.core.model import AuthState
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
    assert routes["/health"].auth_state is AuthState.PUBLIC


def test_php_fixture_classification(fixtures_dir: Path):
    result = _scan(fixtures_dir / "php")
    states = {f.endpoint.file.split("/")[-1]: f.auth_state for f in result.findings}

    # No auth include -> not PROTECTED (UNKNOWN under the coarse file model).
    assert states["api_users.php"] is not AuthState.PROTECTED
    # auth.php include + session guard -> PROTECTED.
    assert states["dashboard.php"] is AuthState.PROTECTED


def test_scan_is_deterministic(fixtures_dir: Path):
    first = _scan(fixtures_dir / "node").sorted_findings()
    second = _scan(fixtures_dir / "node").sorted_findings()
    assert [f.endpoint.identity for f in first] == [f.endpoint.identity for f in second]
