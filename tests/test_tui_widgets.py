"""Unit tests for TUI widget rendering."""

from __future__ import annotations

from authmapper.core.model import (
    AuthState,
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    ScanResult,
    Severity,
)
from authmapper.tui.screen import Rect, ScreenBuffer
from authmapper.tui.theme import Theme
from authmapper.tui.widgets import (
    ViewState,
    render_detail_pane,
    render_help_overlay,
    render_list_pane,
    render_status_bar,
    render_summary_bar,
)


def _make_finding(
    route: str = "/api/users",
    method: str = "GET",
    state: AuthState = AuthState.EXPOSED,
    severity: Severity = Severity.CRITICAL,
    confidence: Confidence = Confidence.HIGH,
    file: str = "src/app.py",
    line: int = 10,
) -> Finding:
    return Finding(
        endpoint=Endpoint(file=file, line=line, method=method, route=route),
        auth_state=state,
        confidence=confidence,
        severity=severity,
        evidence=(Evidence(file=file, line=line, signal="route-decorator"),),
        rationale="No auth guard found",
        fix_hint="Add @login_required",
    )


def _make_result(findings: tuple[Finding, ...]) -> ScanResult:
    return ScanResult(
        findings=findings,
        errors=(),
        files_scanned=len(findings),
        files_skipped=0,
        rulepacks_used=("python-flask",),
        duration_seconds=0.01,
    )


def _make_state(findings: tuple[Finding, ...], **kwargs) -> ViewState:
    defaults = dict(
        findings=findings,
        selected_index=0,
        sort_mode="severity",
        state_filter=None,
        severity_filter=None,
        search_query="",
        search_active=False,
        help_visible=False,
        export_prompt=False,
        export_format="json",
    )
    defaults.update(kwargs)
    return ViewState(**defaults)


def test_render_summary_bar_shows_counts():
    result = _make_result((_make_finding(), _make_finding(state=AuthState.PROTECTED)))
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_summary_bar(buf, result, 80)
    text = "".join(buf[x, 0].char for x in range(80))
    assert "E:" in text
    assert "P:" in text
    assert "authmap" in text


def test_render_list_pane_shows_findings():
    findings = (_make_finding(), _make_finding(route="/api/admin"))
    state = _make_state(findings)
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_list_pane(buf, state, Rect(0, 0, 80, 10), 0)
    # First finding row should contain the route.
    row0 = "".join(buf[x, 0].char for x in range(80))
    assert "/api/users" in row0


def test_render_list_pane_selected_row_highlighted():
    findings = (_make_finding(), _make_finding(route="/api/admin"))
    state = _make_state(findings, selected_index=0)
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_list_pane(buf, state, Rect(0, 0, 80, 10), 0)
    assert buf[0, 0].style is not None
    assert buf[0, 0].style == buf.theme.selected
    # A non-color selection indicator is rendered for the active row.
    row_text = "".join(buf[x, 0].char for x in range(80))
    assert row_text.startswith("> ")


def test_render_list_pane_empty_findings():
    state = _make_state(tuple())
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_list_pane(buf, state, Rect(0, 0, 80, 10), 0)
    # No crash; buffer remains spaces.
    assert buf[0, 0].char == " "


def test_render_list_pane_includes_state_and_severity_labels():
    findings = (_make_finding(state=AuthState.EXPOSED, severity=Severity.HIGH),)
    state = _make_state(findings)
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_list_pane(buf, state, Rect(0, 0, 80, 10), 0)
    row_text = "".join(buf[x, 0].char for x in range(80))
    assert "EXPOSED" in row_text
    assert "HIGH" in row_text


def test_render_detail_pane_shows_finding_fields():
    finding = _make_finding()
    state = _make_state((finding,))
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_detail_pane(buf, state, Rect(0, 0, 60, 20))
    # The title (border line) contains method + route.
    title_row = "".join(buf[x, 0].char for x in range(60))
    assert "GET" in title_row
    assert "/api/users" in title_row
    # A detail row contains the file location.
    file_row = "".join(buf[x, 2].char for x in range(60))
    assert "src/app.py" in file_row


def test_render_detail_pane_no_finding():
    state = _make_state(tuple())
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_detail_pane(buf, state, Rect(0, 0, 40, 20))
    text = "".join(buf[x, 0].char for x in range(40))
    assert "No findings" in text


def test_render_status_bar_normal():
    state = _make_state((_make_finding(),))
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_status_bar(buf, state, 80, 23)
    text = "".join(buf[x, 23].char for x in range(80))
    assert "[q]uit" in text
    assert "[s]ort:severity" in text


def test_render_status_bar_search_mode():
    state = _make_state((_make_finding(),), search_active=True, search_query="admin")
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_status_bar(buf, state, 80, 23)
    text = "".join(buf[x, 23].char for x in range(80))
    assert "/" in text
    assert "admin" in text


def test_render_status_bar_export_mode():
    state = _make_state((_make_finding(),), export_prompt=True, export_format="json")
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_status_bar(buf, state, 80, 23)
    text = "".join(buf[x, 23].char for x in range(80))
    assert "export" in text.lower() or "json" in text.lower() or "son" in text


def test_render_help_overlay_appears():
    buf = ScreenBuffer(80, 24, theme=Theme(color=False))
    render_help_overlay(buf, 80, 24)
    found = False
    for y in range(24):
        for x in range(80):
            if buf[x, y].char != " ":
                found = True
                break
        if found:
            break
    assert found, "help overlay should draw content"
