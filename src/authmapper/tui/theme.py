"""Color and style definitions for the rich TUI.

The theme applies a cyberpunk/hacker terminal aesthetic while remaining
dependency-free and accessible. It respects the ``NO_COLOR`` convention and
``TERM=dumb`` by disabling ANSI colors. Even when colors are enabled, important
status information is conveyed through labels, bold, and underline so that
colorblind users and monochrome terminals stay fully supported.

.. note::
    The palette is designed for a dark terminal background. Running on a light
    background may reduce contrast for the inverted selection style. Use
    ``NO_COLOR`` or switch to a dark terminal theme if legibility suffers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class _ColorName(str, Enum):
    """Named ANSI foreground/background colors (8-color palette)."""

    BLACK = "black"
    RED = "red"
    GREEN = "green"
    YELLOW = "yellow"
    BLUE = "blue"
    MAGENTA = "magenta"
    CYAN = "cyan"
    WHITE = "white"
    DEFAULT = "default"


# ANSI SGR codes for foreground and background colors (8-color).
_FG: dict[str, str] = {
    _ColorName.BLACK: "30",
    _ColorName.RED: "31",
    _ColorName.GREEN: "32",
    _ColorName.YELLOW: "33",
    _ColorName.BLUE: "34",
    _ColorName.MAGENTA: "35",
    _ColorName.CYAN: "36",
    _ColorName.WHITE: "37",
    _ColorName.DEFAULT: "39",
}

_BG: dict[str, str] = {
    _ColorName.BLACK: "40",
    _ColorName.RED: "41",
    _ColorName.GREEN: "42",
    _ColorName.YELLOW: "43",
    _ColorName.BLUE: "44",
    _ColorName.MAGENTA: "45",
    _ColorName.CYAN: "46",
    _ColorName.WHITE: "47",
    _ColorName.DEFAULT: "49",
}


def _should_use_color(force_color: bool | None = None) -> bool:
    """Return whether the TUI may emit ANSI colors.

    Honors ``NO_COLOR`` and ``TERM=dumb``. If ``force_color`` is given it
    overrides the environment (used by tests).
    """
    if force_color is not None:
        return force_color
    if os.environ.get("NO_COLOR"):
        return False
    # Fallback for non-TTY: still allow color when not explicitly forbidden.
    return os.environ.get("TERM") != "dumb"


@dataclass(frozen=True)
class Style:
    """A lightweight, immutable style descriptor.

    Only foreground color, background color, bold, and underline are supported.
    ``None`` means "do not change this attribute".
    """

    fg: str | None = None
    bg: str | None = None
    bold: bool = False
    underline: bool = False

    def merge(self, other: Style) -> Style:
        """Return a new style with ``other`` overriding non-None fields."""
        return Style(
            fg=other.fg if other.fg is not None else self.fg,
            bg=other.bg if other.bg is not None else self.bg,
            bold=other.bold if other.bold else self.bold,
            underline=other.underline if other.underline else self.underline,
        )

    def to_ansi(self, *, color: bool = True) -> str:
        """Return the ANSI SGR sequence for this style.

        When ``color`` is False the returned string contains only the reset and
        attribute codes (bold/underline), never the color codes.
        """
        codes: list[str] = []
        if self.fg is not None and color:
            codes.append(_FG.get(self.fg, "39"))
        if self.bg is not None and color:
            codes.append(_BG.get(self.bg, "49"))
        if self.bold:
            codes.append("1")
        if self.underline:
            codes.append("4")
        return "\033[" + ";".join(codes) + "m" if codes else ""


# Convenience reset style.
RESET = Style()


class Theme:
    """Cyberpunk/hacker-terminal colorblind-safe palette.

    Cyan is the primary phosphor accent, magenta/green/yellow are secondary
    accents, and the auth states/severities each have a neon-like color. Bold is
    used to simulate "bright" on 8-color terminals. Widgets receive a
    :class:`Theme` instance and never construct styles themselves, which keeps
    rendering predictable and easy to override in tests.

    The palette is intentionally small (8 ANSI colors) so it works in any
    standard terminal. To keep severity and auth state distinguishable for
    colorblind users, ``MEDIUM`` severity uses magenta while ``UNKNOWN`` state
    uses yellow; both also carry text labels rendered by the widgets.
    """

    def __init__(self, color: bool = True) -> None:
        self._color = color

        # Core palette: dark background, neon cyan primary.
        self.default = Style()
        self.bold = Style(bold=True)
        self.underline = Style(underline=True)
        # Use a deterministic low-intensity color instead of "default" so the
        # dim style is predictable on both dark and light terminal backgrounds.
        self.dim = Style(fg="white")
        self.inverted = Style(fg="black", bg="cyan")
        self.highlight = Style(fg="cyan", bold=True, underline=True)

        # Auth-state neon colors (labels always accompany these).
        self.exposed = Style(fg="red", bold=True)
        self.unknown = Style(fg="yellow", bold=True)
        self.protected = Style(fg="green", bold=True)
        self.public = Style(fg="magenta", bold=True)

        # Severity neon colors. Magenta is used for MEDIUM so it does not
        # collide with the UNKNOWN auth-state color (yellow).
        self.critical = Style(fg="red", bold=True)
        self.high = Style(fg="red", bold=True)
        self.medium = Style(fg="magenta", bold=True)
        self.low = Style(fg="green", bold=True)
        self.info = Style(fg="cyan", bold=True)

        # UI chrome.
        self.border = Style(fg="cyan", bold=False)
        self.header = Style(fg="cyan", bold=True)
        self.status_bar = Style(fg="cyan", bg="black", bold=True)
        self.search_prompt = Style(fg="black", bg="green", bold=True)
        self.error = Style(fg="red", bold=True)

        # Selection uses a neon-cyan background so the active row glows. Bold
        # and underline provide a non-color cue when the background is not
        # visible (e.g. NO_COLOR or a light terminal theme).
        self.selected = Style(fg="black", bg="cyan", bold=True, underline=True)

    @property
    def color(self) -> bool:
        """Whether this theme emits ANSI color codes."""
        return self._color

    def state_style(self, state_value: str) -> Style:
        """Return the style for an :class:`AuthState` value."""
        return {
            "EXPOSED": self.exposed,
            "UNKNOWN": self.unknown,
            "PROTECTED": self.protected,
            "PUBLIC": self.public,
        }.get(state_value, self.default)

    def severity_style(self, severity_value: str) -> Style:
        """Return the style for a :class:`Severity` value."""
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
            "INFO": self.info,
        }.get(severity_value, self.default)

    @classmethod
    def from_env(cls) -> Theme:
        """Build a theme honoring the runtime environment."""
        return cls(color=_should_use_color())


__all__ = ["Style", "Theme", "RESET", "_should_use_color"]
