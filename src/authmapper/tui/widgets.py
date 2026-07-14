"""Stateless TUI widgets.

Each widget is a function (or thin class) that renders into a
:class:`ScreenBuffer`. They own no application state: the caller passes the
visible findings, selection index, sort/filter/search state, and the widgets
draw accordingly.

This keeps the rendering layer trivially testable: tests can build a small
buffer and assert on the characters/styles present at specific coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.model import AuthState, Finding, ScanResult, Severity
from .screen import Rect, ScreenBuffer
from .theme import Style


@dataclass(frozen=True)
class ViewState:
    """Snapshot of application state passed to the widget layer."""

    findings: tuple[Finding, ...]
    selected_index: int
    sort_mode: str
    state_filter: AuthState | None
    severity_filter: Severity | None
    search_query: str
    search_active: bool
    help_visible: bool
    export_prompt: bool
    export_format: str

    @property
    def selected_finding(self) -> Finding | None:
        """Return the currently selected finding, if any."""
        if 0 <= self.selected_index < len(self.findings):
            return self.findings[self.selected_index]
        return None


def _fit_width(text: str, width: int, *, pad: bool = True) -> str:
    if len(text) > width:
        return text[: max(width - 1, 0)] + "…" if width > 1 else ""
    if pad:
        return text.ljust(width)
    return text


def _state_label(state: AuthState) -> str:
    return str(state)


def _severity_label(severity: Severity) -> str:
    return str(severity)


def render_summary_bar(buffer: ScreenBuffer, result: ScanResult, width: int) -> None:
    """Render the top summary bar with a cyberpunk/system-monitor aesthetic."""
    theme = buffer.theme
    counts = result.counts_by_state()
    max_sev = result.max_severity()

    col = 0
    buffer.put_text(col, 0, "▶ ", style=theme.header)
    col += 2
    buffer.put_text(col, 0, "authmap", style=theme.header)
    col += 7
    buffer.put_text(col, 0, " │ ", style=theme.dim)
    col += 3

    sections = [
        ("E", str(counts["EXPOSED"]), theme.exposed),
        ("U", str(counts["UNKNOWN"]), theme.unknown),
        ("P", str(counts["PROTECTED"]), theme.protected),
        ("A", str(counts["PUBLIC"]), theme.public),
    ]
    for label, value, style in sections:
        chunk = f"{label}:{value} "
        buffer.put_text(col, 0, chunk, style=style)
        col += len(chunk)

    tail = (
        f"│ max:{max_sev} │ files:{result.files_scanned}"
        f" │ coverage!:{len(result.incomplete_coverage())}"
    )
    tail_text = _fit_width(tail, width - col, pad=False)
    buffer.put_text(col, 0, tail_text, style=theme.dim)
    # Fill remainder of the line with default style.
    for x in range(col + len(tail_text), width):
        buffer.put_text(x, 0, " ", style=theme.default)


def render_status_bar(
    buffer: ScreenBuffer,
    state: ViewState,
    width: int,
    row: int,
) -> None:
    """Render the bottom status bar with key hints and system glyphs."""
    theme = buffer.theme
    if state.search_active:
        prompt = f" / {state.search_query}_ "
        buffer.put_text(0, row, _fit_width(prompt, width, pad=False), style=theme.search_prompt)
        return

    if state.export_prompt:
        prompt = f" export:[{state.export_format}] (j)son (s)arif (t)able (esc)cancel "
        buffer.put_text(0, row, _fit_width(prompt, width, pad=False), style=theme.search_prompt)
        return

    sf = _state_label(state.state_filter) if state.state_filter else "all"
    sev = _severity_label(state.severity_filter) if state.severity_filter else "all"
    parts = [
        "[q]uit ",
        "[?]help ",
        f"[s]ort:{state.sort_mode} ",
        f"[f]ilter:{sf} ",
        f"[v]sev:{sev} ",
    ]
    if state.search_query:
        parts.append(f"/:{state.search_query} ")
    text = "│" + "│".join(parts)
    buffer.put_text(0, row, _fit_width(text, width, pad=False), style=theme.status_bar)


def render_list_pane(
    buffer: ScreenBuffer,
    state: ViewState,
    rect: Rect,
    scroll_offset: int,
) -> None:
    """Render the scrollable findings list into ``rect``."""
    theme = buffer.theme
    visible = state.findings[scroll_offset : scroll_offset + rect.height]
    # Fixed column widths: sel(2) idx(7) sev(4) auth(9) then endpoint + location.
    sel_w, idx_w, sev_w, auth_w = 2, 7, 4, 9
    fixed = sel_w + idx_w + sev_w + auth_w + 4  # indicator + three gaps

    def _field(text: str, width: int) -> str:
        return _fit_width(text, width, pad=True)

    for i, finding in enumerate(visible):
        row = rect.y + i
        is_selected = scroll_offset + i == state.selected_index
        state_style = theme.state_style(str(finding.auth_state))
        sev_style = theme.severity_style(str(finding.severity))

        sel = "> " if is_selected else "  "
        idx = _field(f"[{scroll_offset + i + 1:>3}]", idx_w)
        sev = _field(str(finding.severity), sev_w)
        auth = _field(str(finding.auth_state), auth_w)
        ep = f"{finding.endpoint.method} {finding.endpoint.route}"
        location = f"{finding.endpoint.file}:{finding.endpoint.line}"
        # Allocate remaining width: prefer endpoint, keep location visible.
        remaining = rect.width - fixed
        if remaining <= 0:
            tail = ""
        elif len(location) + 1 <= remaining:
            ep_part = _field(ep, remaining - len(location) - 1)
            tail = ep_part + " " + location
        else:
            tail = _field(ep + "  " + location, remaining)

        line = f"{sel}{idx} {sev} {auth} {tail}"[: rect.width]

        if is_selected:
            for col, ch in enumerate(line):
                buffer.put_text(rect.x + col, row, ch, style=theme.selected)
            # Fill remainder of row with selected background.
            for col in range(len(line), rect.width):
                buffer.put_text(rect.x + col, row, " ", style=theme.selected)
        else:
            col = 0
            buffer.put_text(rect.x + col, row, sel, style=theme.default)
            col += sel_w
            buffer.put_text(rect.x + col, row, idx, style=sev_style)
            col += idx_w
            buffer.put_text(rect.x + col, row, " ", style=theme.default)
            col += 1
            buffer.put_text(rect.x + col, row, sev, style=sev_style)
            col += sev_w
            buffer.put_text(rect.x + col, row, " ", style=theme.default)
            col += 1
            buffer.put_text(rect.x + col, row, auth, style=state_style)
            col += auth_w
            buffer.put_text(rect.x + col, row, " " + tail, style=theme.default)


class _DetailRow:
    def __init__(self, y: int, x: int, label_width: int) -> None:
        self.y = y
        self.x = x
        self.label_width = label_width

    def __call__(
        self,
        buffer: ScreenBuffer,
        label: str,
        value: str,
        value_style: Style | None = None,
        height: int = 1,
    ) -> int:
        theme = buffer.theme
        buffer.put_text(self.x, self.y, f"{label}: ".ljust(self.label_width + 2), style=theme.bold)
        buffer.put_text(self.x + self.label_width + 2, self.y, value, style=value_style)
        self.y += height
        return self.y


def render_detail_pane(
    buffer: ScreenBuffer,
    state: ViewState,
    rect: Rect,
) -> None:
    """Render the detail pane for the selected finding."""
    theme = buffer.theme
    finding = state.selected_finding
    if finding is None:
        text = "No findings to display."
        buffer.put_text(rect.x, rect.y, _fit_width(text, rect.width), style=theme.dim)
        return

    ep = finding.endpoint
    border_style = theme.border
    buffer.put_box(rect, style=border_style)

    # Title row (border line overwritten by title text)
    title = f"▣ {ep.method} {ep.route} "
    buffer.put_text(rect.x + 2, rect.y, title[: rect.width - 4], style=theme.header)

    label_width = 11
    row = _DetailRow(rect.y + 2, rect.x + 2, label_width)

    row(buffer, "File", f"{ep.file}:{ep.line}", value_style=theme.default)
    row(buffer, "Stack", f"{ep.language}/{ep.framework}", value_style=theme.default)
    state_str = str(finding.auth_state)
    row(buffer, "State", state_str, value_style=theme.state_style(state_str))
    row(buffer, "Confidence", str(finding.confidence), value_style=theme.default)
    row(buffer, "Severity", str(finding.severity),
        value_style=theme.severity_style(str(finding.severity)))
    row(buffer, "Rationale", finding.rationale or "-", value_style=theme.default)
    if finding.fix_hint:
        row(buffer, "Fix hint", finding.fix_hint, value_style=theme.default)

    evidence_text = "; ".join(f"{e.signal} @ {e.file}:{e.line}" for e in finding.evidence)
    if evidence_text:
        row(buffer, "Evidence", evidence_text, value_style=theme.dim)

    if finding.suppressed:
        row(buffer, "Suppressed", finding.suppression_reason, value_style=theme.dim)


def render_help_overlay(buffer: ScreenBuffer, width: int, height: int) -> None:
    """Render the help overlay in the center of the screen."""
    theme = buffer.theme
    lines = [
        " authmap  keybindings ",
        "",
        "Navigation",
        "  ↑/k      move up",
        "  ↓/j      move down",
        "  PgUp/PgDn page up/down",
        "  Home/End jump to first/last",
        "",
        "Filtering / Search / Sort",
        "  /        enter search mode",
        "  Esc      cancel search / close overlay",
        "  f        cycle state filter (e/u/p/a)",
        "  v        cycle severity filter",
        "  s        cycle sort mode",
        "",
        "Actions",
        "  o        export current view",
        "  ?/h      toggle this help",
        "  q/Ctrl+C quit",
    ]
    box_width = min(60, width - 4)
    box_height = min(len(lines) + 4, height - 4)
    x = (width - box_width) // 2
    y = (height - box_height) // 2

    for row in range(y, y + box_height):
        buffer.put_text(x, row, " " * box_width, style=theme.inverted)

    buffer.put_box(Rect(x, y, box_width, box_height), style=theme.border)
    title = " ▣ keybindings "
    buffer.put_text(x + 2, y, title, style=theme.header)
    for i, line in enumerate(lines):
        if i + 2 >= box_height:
            break
        buffer.put_text(x + 2, y + 2 + i, line[: box_width - 4], style=theme.default)
