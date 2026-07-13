"""Interactive terminal UI (Layer 2).

A dependency-free, ANSI-based rich TUI for exploring a scan result: scroll a
findings list, inspect a detail pane, filter by state/severity, sort, fuzzy
search, and export a confidential report without leaving the terminal. It
reuses the exact same :class:`Runner` as the CLI, so results never diverge
between layers.
"""

from __future__ import annotations

from .app import TuiApp, UnsupportedTerminalError

__all__ = ["TuiApp", "UnsupportedTerminalError"]
