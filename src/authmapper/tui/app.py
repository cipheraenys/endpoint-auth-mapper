"""Top-level TUI orchestrator.

:class:`TuiApp` owns the event loop, application state, and coordinates the
stateless widgets defined in :mod:`authmapper.tui.widgets`. It is the only
entry point the CLI needs to call.

Design notes:
- The app is strictly local and read-only: it navigates an already-computed
  :class:`ScanResult` and can export confidential reports, but never touches
  the network.
- When the terminal cannot support ANSI (no TTY, dumb TERM, Windows VT
  enablement fails), :meth:`run` raises :class:`UnsupportedTerminalError` so
  the caller can fall back to the plain table reporter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from ..core.model import AuthState, Finding, ScanResult, Severity
from ..core.safety import ensure_within
from ..reporters import REPORTERS
from .input import SearchInput, is_printable, read_keys
from .screen import (
    AnsiBackend,
    Rect,
    ScreenBuffer,
    VtEnableError,
    enable_windows_vt,
)
from .theme import Theme
from .widgets import (
    ViewState,
    render_detail_pane,
    render_help_overlay,
    render_list_pane,
    render_status_bar,
    render_summary_bar,
)


class UnsupportedTerminalError(RuntimeError):
    """Raised when the terminal cannot render the rich TUI."""


_SORT_MODES = ("severity", "file", "route", "state")
_STATE_CYCLE: list[AuthState | None] = [
    None, AuthState.EXPOSED, AuthState.UNKNOWN, AuthState.PROTECTED, AuthState.PUBLIC,
]
_SEV_CYCLE: list[Severity | None] = [
    None, Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
]
_EXPORT_FORMATS = ("json", "sarif", "table")


class TuiApp:
    """Rich terminal UI over a scan result."""

    def __init__(
        self,
        result: ScanResult,
        report_dir: Path,
        *,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        theme: Theme | None = None,
    ) -> None:
        self._result = result
        self._report_dir = report_dir
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout
        self._theme = theme or Theme.from_env()

        # Application state
        self._selected_index = 0
        self._scroll_offset = 0
        self._sort_mode = "severity"
        self._state_filter: AuthState | None = None
        self._severity_filter: Severity | None = None
        self._search = SearchInput()
        self._search_active = False
        self._help_visible = False
        self._export_prompt = False
        self._export_format_index = 0
        self._quit = False
        self._last_message = ""

    # -- public API ---------------------------------------------------------

    def run(self) -> None:
        """Start the event loop. Raises :class:`UnsupportedTerminalError`."""
        if not self._can_render():
            raise UnsupportedTerminalError("terminal does not support ANSI rendering")
        backend = AnsiBackend(self._stdout)
        for _key in read_keys(self._stdin):
            self._dispatch(_key)
            self._render(backend)
            if self._quit:
                break
        # Restore cursor visibility on exit.
        try:
            self._stdout.write("\033[?25h")
            self._stdout.flush()
        except OSError:  # pragma: no cover - terminal vanished
            pass

    # -- terminal capability ------------------------------------------------

    def _can_render(self) -> bool:
        """Return True when the terminal can render the rich TUI."""
        if not self._stdout.isatty():
            return False
        if sys.platform == "win32":
            try:
                enable_windows_vt()
            except VtEnableError:
                return False
        return True

    # -- state helpers ------------------------------------------------------

    @property
    def _findings(self) -> tuple[Finding, ...]:
        """Return the currently visible findings after filtering/sorting/search."""
        findings = list(self._result.sorted_findings())
        if self._state_filter is not None:
            findings = [f for f in findings if f.auth_state is self._state_filter]
        if self._severity_filter is not None:
            findings = [f for f in findings if f.severity is self._severity_filter]
        query = self._search.text.lower()
        if query:
            findings = [
                f for f in findings
                if query in f.endpoint.route.lower()
                or query in f.endpoint.file.lower()
                or query in f.endpoint.method.lower()
            ]
        self._sort_findings(findings)
        return tuple(findings)

    def _sort_findings(self, findings: list[Finding]) -> None:
        if self._sort_mode == "file":
            findings.sort(key=lambda f: (f.endpoint.file, f.endpoint.line))
        elif self._sort_mode == "route":
            findings.sort(key=lambda f: (f.endpoint.route, f.endpoint.method))
        elif self._sort_mode == "state":
            findings.sort(key=lambda f: (f.auth_state.value, -f.severity.rank))
        else:
            findings.sort(key=lambda f: f.sort_key)

    def _view_state(self) -> ViewState:
        return ViewState(
            findings=self._findings,
            selected_index=self._selected_index,
            sort_mode=self._sort_mode,
            state_filter=self._state_filter,
            severity_filter=self._severity_filter,
            search_query=self._search.text,
            search_active=self._search_active,
            help_visible=self._help_visible,
            export_prompt=self._export_prompt,
            export_format=_EXPORT_FORMATS[self._export_format_index],
        )

    def _clamp_selection(self) -> None:
        findings = self._findings
        if not findings:
            self._selected_index = 0
            self._scroll_offset = 0
            return
        if self._selected_index >= len(findings):
            self._selected_index = len(findings) - 1
        if self._selected_index < 0:
            self._selected_index = 0

    def _ensure_visible(self, list_height: int) -> None:
        if self._selected_index < self._scroll_offset:
            self._scroll_offset = self._selected_index
        elif self._selected_index >= self._scroll_offset + list_height:
            self._scroll_offset = self._selected_index - list_height + 1
        if self._scroll_offset < 0:
            self._scroll_offset = 0

    # -- keyboard dispatch --------------------------------------------------

    def _dispatch(self, key: str) -> None:
        if self._help_visible and key not in ("escape", "?", "h", "q", "ctrl+c"):
            self._help_visible = False
            return
        if self._export_prompt:
            self._handle_export_key(key)
            return
        if self._search_active:
            self._handle_search_key(key)
            return
        self._handle_normal_key(key)

    def _handle_normal_key(self, key: str) -> None:
        if key in ("q", "ctrl+c"):
            self._quit = True
        elif key in ("?", "h"):
            self._help_visible = not self._help_visible
        elif key in ("k", "up"):
            self._move_cursor(-1)
        elif key in ("j", "down"):
            self._move_cursor(1)
        elif key == "pageup":
            self._move_cursor(-10)
        elif key == "pagedown":
            self._move_cursor(10)
        elif key == "home":
            self._selected_index = 0
            self._clamp_selection()
        elif key == "end":
            self._selected_index = max(0, len(self._findings) - 1)
        elif key == "/":
            self._search_active = True
            self._search = SearchInput("")
        elif key == "f":
            self._cycle_state_filter()
        elif key == "v":
            self._cycle_severity_filter()
        elif key == "s":
            self._cycle_sort_mode()
        elif key == "o":
            self._export_prompt = True
            self._export_format_index = 0
        elif key == "escape":
            self._help_visible = False

    def _handle_search_key(self, key: str) -> None:
        if key == "escape" or key == "enter":
            self._search_active = False
            self._clamp_selection()
        elif key == "backspace":
            self._search.backspace()
            self._clamp_selection()
        elif key == "left":
            self._search.move_left()
        elif key == "right":
            self._search.move_right()
        elif key == "home":
            self._search.move_home()
        elif key == "end":
            self._search.move_end()
        elif is_printable(key):
            self._search.insert(key)
            self._clamp_selection()

    def _handle_export_key(self, key: str) -> None:
        if key in ("escape", "q"):
            self._export_prompt = False
        elif key == "j":
            self._export_format_index = 0
            self._do_export()
            self._export_prompt = False
        elif key == "s":
            self._export_format_index = 1
            self._do_export()
            self._export_prompt = False
        elif key == "t":
            self._export_format_index = 2
            self._do_export()
            self._export_prompt = False
        elif key == "enter":
            self._do_export()
            self._export_prompt = False

    def _move_cursor(self, delta: int) -> None:
        findings = self._findings
        if not findings:
            return
        self._selected_index = max(0, min(len(findings) - 1, self._selected_index + delta))

    def _cycle_state_filter(self) -> None:
        idx = 0 if self._state_filter is None else _STATE_CYCLE.index(self._state_filter)
        self._state_filter = _STATE_CYCLE[(idx + 1) % len(_STATE_CYCLE)]
        self._clamp_selection()

    def _cycle_severity_filter(self) -> None:
        current = self._severity_filter
        idx = 0 if current is None else _SEV_CYCLE.index(current)
        self._severity_filter = _SEV_CYCLE[(idx + 1) % len(_SEV_CYCLE)]
        self._clamp_selection()

    def _cycle_sort_mode(self) -> None:
        idx = _SORT_MODES.index(self._sort_mode)
        self._sort_mode = _SORT_MODES[(idx + 1) % len(_SORT_MODES)]

    # -- export -------------------------------------------------------------

    def _do_export(self) -> None:
        fmt = _EXPORT_FORMATS[self._export_format_index]
        reporter = REPORTERS.get(fmt)
        if reporter is None:
            self._last_message = f"unknown format: {fmt}"
            return
        self._report_dir.mkdir(parents=True, exist_ok=True)
        ext = {"table": "txt", "json": "json", "sarif": "sarif"}[fmt]
        target = ensure_within(self._report_dir, Path(f"authmap.{ext}"))
        target.write_text(reporter(self._result), encoding="utf-8")
        self._last_message = f"exported: {target}"

    # -- rendering ----------------------------------------------------------

    def _render(self, backend: AnsiBackend) -> None:
        cols, rows = backend.get_size()
        cols = max(cols, 40)
        rows = max(rows, 10)
        buffer = ScreenBuffer(cols, rows, theme=self._theme)
        buffer.clear()

        # Layout
        summary_h = 1
        status_h = 1
        gap = 1
        middle_h = rows - summary_h - status_h - gap
        if middle_h < 3:
            middle_h = 3
        list_w = max(30, cols * 2 // 5)
        detail_w = cols - list_w - 1

        list_rect = Rect(0, summary_h + gap, list_w, middle_h)
        detail_rect = Rect(list_w + 1, summary_h + gap, detail_w, middle_h)

        render_summary_bar(buffer, self._result, cols)

        list_state = self._view_state()
        list_height = middle_h
        self._ensure_visible(list_height)
        render_list_pane(buffer, list_state, list_rect, self._scroll_offset)
        render_detail_pane(buffer, list_state, detail_rect)

        render_status_bar(buffer, list_state, cols, rows - status_h)

        if self._help_visible:
            render_help_overlay(buffer, cols, rows)

        if self._last_message:
            msg_y = rows - status_h - 1
            buffer.put_text(0, msg_y, self._last_message[:cols], style=self._theme.dim)
            self._last_message = ""

        buffer.render(backend)


__all__ = ["TuiApp", "UnsupportedTerminalError"]
