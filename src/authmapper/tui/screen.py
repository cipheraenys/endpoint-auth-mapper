"""Screen buffer and ANSI rendering for the rich TUI.

All drawing is performed into an :class:`ScreenBuffer` and then flushed through a
backend. This keeps widgets pure (stateless renderers) and makes the whole TUI
testable without touching a real terminal.

The module is careful to avoid any third-party runtime dependencies. On Windows
it attempts to enable virtual terminal processing via ``ctypes``; if that fails,
the caller is informed so it can fall back to the plain table reporter.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Protocol, TextIO

from .theme import Style, Theme


@dataclass(frozen=True)
class _Cell:
    """A single screen cell: one character plus style."""

    char: str = " "
    style: Style | None = None


class Backend(Protocol):
    """Abstract terminal backend used by :class:`ScreenBuffer`."""

    def write(self, data: str) -> None: ...  # pragma: no cover - I/O
    def flush(self) -> None: ...  # pragma: no cover - I/O
    def get_size(self) -> tuple[int, int]: ...  # pragma: no cover - I/O


class AnsiBackend:
    """Backend that writes ANSI escape sequences to a file object (default stdout)."""

    def __init__(self, out: TextIO | None = None) -> None:
        self._out = out or sys.stdout

    def write(self, data: str) -> None:
        with contextlib.suppress(OSError):
            self._out.write(data)

    def flush(self) -> None:
        with contextlib.suppress(OSError):
            self._out.flush()

    def get_size(self) -> tuple[int, int]:
        return get_terminal_size(self._out)


class StringBackend:
    """In-memory backend used for tests and the degraded fallback."""

    def __init__(self) -> None:
        self._buffer: list[str] = []
        self.size: tuple[int, int] = (80, 24)

    def write(self, data: str) -> None:
        self._buffer.append(data)

    def flush(self) -> None:
        pass

    def get_size(self) -> tuple[int, int]:
        return self.size

    @property
    def value(self) -> str:
        return "".join(self._buffer)


@dataclass(frozen=True)
class Rect:
    """A rectangular region on screen."""

    x: int
    y: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height


class ScreenBuffer:
    """A grid of styled cells that can be rendered to a backend.

    Coordinates are 0-based with ``(0, 0)`` at the top-left. ``put_text`` clips
    text that would extend past the buffer edges.
    """

    def __init__(self, width: int, height: int, theme: Theme | None = None) -> None:
        if width < 1 or height < 1:
            raise ValueError("screen dimensions must be positive")
        self._width = width
        self._height = height
        self._theme = theme or Theme.from_env()
        self._cells: list[list[_Cell]] = [[_Cell() for _ in range(width)] for _ in range(height)]

    @property
    def width(self) -> int:
        return self._width

    @property
    def height(self) -> int:
        return self._height

    @property
    def theme(self) -> Theme:
        return self._theme

    def clear(self, style: Style | None = None) -> None:
        """Fill the entire buffer with spaces and the given style."""
        for row in self._cells:
            for i, _ in enumerate(row):
                row[i] = _Cell(" ", style)

    def put_text(
        self,
        x: int,
        y: int,
        text: str,
        style: Style | None = None,
        width: int | None = None,
        truncate: bool = True,
    ) -> None:
        """Write ``text`` at ``(x, y)``.

        If ``width`` is provided, the text is truncated or padded to that
        width. Lines are not wrapped; newlines move the cursor down one row.
        """
        if y >= self._height or x >= self._width or y < 0:
            return
        available = self._width - x if width is None else width
        if available <= 0:
            return

        col = x
        row = y
        for char in text:
            if char == "\n":
                row += 1
                col = x
                if row >= self._height:
                    break
                continue
            if col >= self._width:
                if not truncate:
                    break
                continue
            if col < 0:
                col += 1
                continue
            self._cells[row][col] = _Cell(char, style)
            col += 1

            if width is not None and col - x >= available:
                break

    def put_box(self, rect: Rect, style: Style | None = None) -> None:
        """Draw a single-line box border inside ``rect`` using Unicode box chars."""
        x, y, w, h = rect.x, rect.y, rect.width, rect.height
        if w < 2 or h < 2:
            return
        horizontal = "─" * (w - 2)
        self.put_text(x, y, "┌" + horizontal + "┐", style)
        self.put_text(x, y + h - 1, "└" + horizontal + "┘", style)
        for row in range(y + 1, y + h - 1):
            self.put_text(x, row, "│", style)
            self.put_text(x + w - 1, row, "│", style)

    def render(self, backend: Backend, *, diff: bool = False) -> None:
        """Flush the buffer to ``backend`` using ANSI escape sequences.

        ``diff=True`` is reserved for future optimisation and currently behaves
        identically to a full redraw.
        """
        _ = diff
        out: list[str] = []
        out.append("\033[?25l")  # hide cursor
        out.append("\033[H")      # move to top-left
        previous_style: Style | None = None
        for row in self._cells:
            line_chars: list[str] = []
            for cell in row:
                if cell.style != previous_style:
                    style = cell.style or self._theme.default
                    line_chars.append(style.to_ansi(color=self._theme.color))
                    previous_style = cell.style
                line_chars.append(cell.char)
            # Reset at end of each row so attributes never bleed across lines.
            line_chars.append("\033[0m")
            previous_style = None
            out.append("".join(line_chars))
            out.append("\n")
        out.append("\033[0m")
        backend.write("".join(out))
        backend.flush()

    def __getitem__(self, pos: tuple[int, int]) -> _Cell:
        x, y = pos
        if 0 <= x < self._width and 0 <= y < self._height:
            return self._cells[y][x]
        raise IndexError("position out of bounds")


def get_terminal_size(out: TextIO | None = None) -> tuple[int, int]:
    """Return ``(columns, rows)`` for ``out`` or stdout.

    Tries ``os.get_terminal_size`` first, then falls back to
    ``shutil.get_terminal_size``, and finally to ``(80, 24)``.
    """
    stream = out or sys.stdout
    try:
        size = os.get_terminal_size(stream.fileno())
        return size.columns, size.lines
    except (OSError, AttributeError):
        pass
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.columns, size.lines
    except OSError:
        return 80, 24


class VtEnableError(RuntimeError):
    """Raised when Windows virtual terminal processing cannot be enabled."""


def enable_windows_vt() -> bool:
    """Enable Windows virtual terminal processing if possible.

    Returns ``True`` if VT mode is (already) active, ``False`` only when
    ``ctypes`` or the kernel API is unavailable (should never happen on
    Windows).

    Raises:
        VtEnableError: when the Windows console does not support VT mode.
    """
    try:
        import ctypes
        import ctypes.wintypes as wintypes
    except ImportError:  # pragma: no cover - not Windows
        return False

    kernel32 = ctypes.windll.kernel32
    STD_OUTPUT_HANDLE = -11
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

    hstdout = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    if hstdout == -1 or hstdout is None:  # INVALID_HANDLE_VALUE or NULL
        raise VtEnableError("could not obtain stdout handle")

    mode = wintypes.DWORD()
    if not kernel32.GetConsoleMode(hstdout, ctypes.byref(mode)):
        # Not a console (e.g., piped). That is fine; ANSI will pass through if
        # the terminal emulator supports it, otherwise output is just text.
        return True

    if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
        return True

    new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    if not kernel32.SetConsoleMode(hstdout, new_mode):
        raise VtEnableError("console does not support virtual terminal processing")
    return True
