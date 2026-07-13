"""Cross-platform raw keyboard input for the rich TUI.

No third-party dependencies are used. Windows uses ``msvcrt`` while Unix-like
systems use ``tty``/``termios``. The module yields logical key strings so the
caller does not need to parse escape sequences.

The module is intentionally low-level: it only knows how to read keys, not what
they mean for application state. That responsibility lives in
``authmapper.tui.app``.
"""

from __future__ import annotations

import contextlib
import sys
import typing
from collections.abc import Iterator


class _WindowsInput:
    """Raw keyboard reader for Windows consoles."""

    def __init__(self) -> None:
        import msvcrt  # type: ignore[import-not-found, unused-ignore]

        self._getch = msvcrt.getwch
        self._kbhit = msvcrt.kbhit

    def read_key(self) -> str:
        ch = self._getch()
        if ch in ("\x00", "\xe0"):
            # Function / arrow key; read the scan code.
            try:
                scan = self._getch()
            except (EOFError, KeyboardInterrupt):
                return "escape"
            return _WINDOWS_SCAN_MAP.get(scan, f"<{ord(scan)}>")
        return _char_to_key(ch)

    def has_key(self) -> bool:  # pragma: no cover - interactive only
        return self._kbhit()


class _UnixInput:
    """Raw keyboard reader for Unix-like terminals."""

    def __init__(self, stdin: typing.TextIO | None = None) -> None:
        self._stdin = stdin or sys.stdin

    def read_key(self) -> str:
        import termios  # type: ignore[import-not-found, unused-ignore]
        import tty  # type: ignore[import-not-found, unused-ignore]

        fd = self._stdin.fileno()
        old = termios.tcgetattr(fd)  # type: ignore[attr-defined]
        try:
            tty.setraw(fd)  # type: ignore[attr-defined]
            ch = self._stdin.read(1)
            if not ch:
                return "escape"
            if ch == "\x1b":
                # Escape sequence; read up to two more bytes while still in raw
                # mode so the terminal does not echo/process the tail.
                seq = ch
                try:
                    seq += self._stdin.read(1)
                    if seq[-1] in ("[", "O"):
                        seq += self._stdin.read(1)
                except (EOFError, KeyboardInterrupt):
                    pass
                return _ANSI_MAP.get(seq, "escape")
            return _char_to_key(ch)
        except (EOFError, KeyboardInterrupt):
            return "escape"
        finally:
            with contextlib.suppress(termios.error):  # type: ignore[attr-defined]
                termios.tcsetattr(fd, termios.TCSADRAIN, old)  # type: ignore[attr-defined]


def _char_to_key(ch: str) -> str:
    """Map a single raw character to a logical key name."""
    code = ord(ch)
    if ch == "\x1b":
        return "escape"
    if ch == "\r" or ch == "\n":
        return "enter"
    if ch == "\t":
        return "tab"
    if ch == "\x7f":
        return "backspace"
    if ch == "\x00":
        return "escape"
    if code < 0x20:
        # Ctrl+A..Ctrl+Z, plus a few others.
        letter = chr(ord("a") + code - 1) if 1 <= code <= 26 else None
        if letter:
            return f"ctrl+{letter}"
        return f"ctrl+{code}"
    return ch


# Map of common ANSI escape sequences to logical key names.
_ANSI_MAP: dict[str, str] = {
    "\x1b[A": "up",
    "\x1b[B": "down",
    "\x1b[C": "right",
    "\x1b[D": "left",
    "\x1b[H": "home",
    "\x1b[F": "end",
    "\x1b[5~": "pageup",
    "\x1b[6~": "pagedown",
    "\x1b[3~": "delete",
    "\x1bOH": "home",
    "\x1bOF": "end",
}

# Windows virtual-key scan codes for extended keys.
_WINDOWS_SCAN_MAP: dict[str, str] = {
    "H": "up",
    "P": "down",
    "K": "left",
    "M": "right",
    "I": "pageup",
    "Q": "pagedown",
    "G": "home",
    "O": "end",
    "S": "delete",
}


def read_keys(stdin: typing.TextIO | None = None) -> Iterator[str]:
    """Yield logical key names from the terminal.

    This is a convenience generator for the interactive event loop. It handles
    platform detection and yields ``escape`` when interrupted by EOF.
    """

    if sys.platform == "win32":
        reader: _WindowsInput | _UnixInput = _WindowsInput()
    else:
        reader = _UnixInput(stdin)

    while True:
        try:
            yield reader.read_key()
        except KeyboardInterrupt:
            yield "ctrl+c"


def is_printable(key: str) -> bool:
    """Return ``True`` if ``key`` is a single printable character."""
    return len(key) == 1 and key.isprintable()


class SearchInput:
    """Simple editable text buffer used by the TUI search prompt.

    The widget is stateless in the sense that the application owns the current
    query string; this class merely provides helpers for inserting, deleting,
    and clearing characters in response to raw key events.
    """

    def __init__(self, text: str = "") -> None:
        self.text = text
        self.cursor = len(text)

    def insert(self, char: str) -> None:
        """Insert ``char`` at the current cursor position."""
        if not char:
            return
        left = self.text[: self.cursor]
        right = self.text[self.cursor :]
        self.text = left + char + right
        self.cursor += len(char)

    def backspace(self) -> None:
        """Remove the character before the cursor."""
        if self.cursor > 0:
            self.text = self.text[: self.cursor - 1] + self.text[self.cursor :]
            self.cursor -= 1

    def delete(self) -> None:
        """Remove the character under the cursor."""
        if self.cursor < len(self.text):
            self.text = self.text[: self.cursor] + self.text[self.cursor + 1 :]

    def move_home(self) -> None:
        self.cursor = 0

    def move_end(self) -> None:
        self.cursor = len(self.text)

    def move_left(self) -> None:
        if self.cursor > 0:
            self.cursor -= 1

    def move_right(self) -> None:
        if self.cursor < len(self.text):
            self.cursor += 1
