"""Unit tests for the TUI application orchestrator."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from authmapper.core.model import (
    AuthState,
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    ScanResult,
    Severity,
)
from authmapper.tui.app import TuiApp, UnsupportedTerminalError
from authmapper.tui.input import SearchInput
from authmapper.tui.theme import Theme


def _make_finding(
    route: str = "/api/users",
    method: str = "GET",
    state: AuthState = AuthState.EXPOSED,
) -> Finding:
    return Finding(
        endpoint=Endpoint(file="src/app.py", line=10, method=method, route=route),
        auth_state=state,
        confidence=Confidence.HIGH,
        severity=Severity.CRITICAL,
        evidence=(Evidence(file="src/app.py", line=10, signal="route"),),
        rationale="none",
        fix_hint="add guard",
    )


def _make_result(findings: tuple[Finding, ...]) -> ScanResult:
    return ScanResult(
        findings=findings,
        errors=(),
        files_scanned=len(findings),
        files_skipped=0,
        rulepacks_used=("test",),
        duration_seconds=0.0,
    )


def _make_app(
    findings: tuple[Finding, ...] = (_make_finding(),),
    tmp_path: Path | None = None,
) -> TuiApp:
    result = _make_result(findings)
    report_dir = tmp_path or Path(".")
    return TuiApp(
        result,
        report_dir,
        stdin=io.StringIO(),
        stdout=io.StringIO(),
        theme=Theme(color=False),
    )


def test_app_state_filters_by_state(tmp_path):
    app = _make_app(
        (_make_finding(state=AuthState.EXPOSED), _make_finding(state=AuthState.PROTECTED)),
        tmp_path,
    )
    assert len(app._findings) == 2
    app._state_filter = AuthState.PROTECTED
    assert len(app._findings) == 1
    assert app._findings[0].auth_state is AuthState.PROTECTED


def test_app_search_filters(tmp_path):
    app = _make_app(
        (_make_finding(route="/api/users"), _make_finding(route="/api/admin")),
        tmp_path,
    )
    app._search = SearchInput("admin")
    assert len(app._findings) == 1
    assert "/api/admin" in app._findings[0].endpoint.route


def test_app_move_cursor_down_up(tmp_path):
    app = _make_app((_make_finding(route="/a"), _make_finding(route="/b")), tmp_path)
    assert app._selected_index == 0
    app._handle_normal_key("j")
    assert app._selected_index == 1
    app._handle_normal_key("k")
    assert app._selected_index == 0


def test_app_move_cursor_clamps(tmp_path):
    app = _make_app((_make_finding(),), tmp_path)
    app._handle_normal_key("j")
    assert app._selected_index == 0  # only one finding
    app._handle_normal_key("k")
    assert app._selected_index == 0


def test_app_quit_key(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("q")
    assert app._quit is True


def test_app_ctrl_c_quits(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("ctrl+c")
    assert app._quit is True


def test_app_toggle_help(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    assert app._help_visible is False
    app._handle_normal_key("?")
    assert app._help_visible is True
    app._handle_normal_key("h")
    assert app._help_visible is False


def test_app_help_overlay_blocks_keys(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._help_visible = True
    app._dispatch("j")  # should close help, not move
    assert app._help_visible is False
    assert app._selected_index == 0


def test_app_enter_search_mode(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("/")
    assert app._search_active is True


def test_app_search_mode_insert(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("/")
    app._handle_search_key("a")
    app._handle_search_key("b")
    assert app._search.text == "ab"


def test_app_search_mode_backspace(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("/")
    app._handle_search_key("a")
    app._handle_search_key("b")
    app._handle_search_key("backspace")
    assert app._search.text == "a"


def test_app_search_mode_escape_exits(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("/")
    app._handle_search_key("escape")
    assert app._search_active is False


def test_app_cycle_sort_mode(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    assert app._sort_mode == "severity"
    app._handle_normal_key("s")
    assert app._sort_mode == "file"
    app._handle_normal_key("s")
    assert app._sort_mode == "route"
    app._handle_normal_key("s")
    assert app._sort_mode == "state"
    app._handle_normal_key("s")
    assert app._sort_mode == "severity"


def test_app_cycle_state_filter(tmp_path):
    app = _make_app(
        (_make_finding(state=AuthState.EXPOSED), _make_finding(state=AuthState.PROTECTED)),
        tmp_path,
    )
    assert app._state_filter is None
    app._handle_normal_key("f")
    assert app._state_filter is AuthState.EXPOSED
    app._handle_normal_key("f")
    assert app._state_filter is AuthState.UNKNOWN


def test_app_export_writes_file(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("o")
    assert app._export_prompt is True
    app._handle_export_key("j")  # json
    assert app._export_prompt is False
    report = tmp_path / "authmap.json"
    assert report.exists()
    content = report.read_text(encoding="utf-8")
    assert "{" in content  # JSON output


def test_app_export_sarif(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("o")
    app._handle_export_key("s")
    report = tmp_path / "authmap.sarif"
    assert report.exists()


def test_app_export_cancel(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._handle_normal_key("o")
    app._handle_export_key("escape")
    assert app._export_prompt is False
    assert not (tmp_path / "authmap.json").exists()


def test_app_can_render_non_tty_returns_false(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    assert app._can_render() is False


def test_app_run_raises_on_non_tty(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    with pytest.raises(UnsupportedTerminalError):
        app.run()


def test_app_clamp_selection_after_filter(tmp_path):
    app = _make_app(
        (_make_finding(route="/a"), _make_finding(route="/b"), _make_finding(route="/c")),
        tmp_path,
    )
    app._selected_index = 2
    app._state_filter = AuthState.EXPOSED
    app._clamp_selection()
    assert app._selected_index <= 2


def test_app_ensure_visible_scrolls(tmp_path):
    app = _make_app(tuple(_make_finding(route=f"/r{i}") for i in range(20)), tmp_path)
    app._selected_index = 15
    app._ensure_visible(list_height=5)
    assert app._scroll_offset <= 15
    assert app._scroll_offset + 5 > 15


def test_app_findings_sort_by_file(tmp_path):
    app = _make_app(
        (_make_finding(route="/z"), _make_finding(route="/a")),
        tmp_path,
    )
    app._sort_mode = "file"
    findings = app._findings
    # Same file/line: stable sort preserves the severity-then-identity order
    # from sorted_findings(), so /a precedes /z.
    assert findings[0].endpoint.route == "/a"
    assert findings[1].endpoint.route == "/z"


def test_app_view_state_reflects_state(tmp_path):
    app = _make_app(tmp_path=tmp_path)
    app._search = SearchInput("test")
    state = app._view_state()
    assert state.search_query == "test"
    assert state.sort_mode == "severity"
