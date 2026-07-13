"""Unit tests for the TUI theme module."""

from __future__ import annotations

from authmapper.tui.theme import Style, Theme, _should_use_color


def test_style_to_ansi_with_color():
    style = Style(fg="red", bold=True)
    ansi = style.to_ansi(color=True)
    assert "31" in ansi  # red fg
    assert "1" in ansi    # bold
    assert ansi.startswith("\033[")
    assert ansi.endswith("m")


def test_style_to_ansi_no_color_strips_color_codes():
    style = Style(fg="red", bg="blue", bold=True, underline=True)
    ansi = style.to_ansi(color=False)
    assert "31" not in ansi
    assert "41" not in ansi
    assert "1" in ansi
    assert "4" in ansi


def test_style_merge():
    base = Style(fg="red", bold=True)
    over = Style(fg="blue", underline=True)
    merged = base.merge(over)
    assert merged.fg == "blue"
    assert merged.bold is True
    assert merged.underline is True


def test_should_use_color_respects_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert _should_use_color() is False


def test_should_use_color_respects_term_dumb(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert _should_use_color() is False


def test_theme_state_style():
    theme = Theme(color=False)
    assert theme.state_style("EXPOSED").fg == "red"
    assert theme.state_style("UNKNOWN").fg == "yellow"
    assert theme.state_style("PROTECTED").fg == "green"
    assert theme.state_style("PUBLIC").fg == "magenta"


def test_theme_severity_style():
    theme = Theme(color=False)
    assert theme.severity_style("CRITICAL").fg == "red"
    assert theme.severity_style("HIGH").fg == "red"
    # MEDIUM uses magenta so it does not collide with UNKNOWN state (yellow).
    assert theme.severity_style("MEDIUM").fg == "magenta"
    assert theme.severity_style("LOW").fg == "green"
    assert theme.severity_style("INFO").fg == "cyan"


def test_theme_selected_has_non_color_cues():
    theme = Theme(color=False)
    assert theme.selected.bold is True
    assert theme.selected.underline is False  # underline removed: causes artifacts on bg-filled rows
    assert theme.selected.bg == "cyan"


def test_theme_dim_is_predictable():
    theme = Theme(color=False)
    assert theme.dim.fg == "white"


def test_theme_from_env_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("TERM", raising=False)
    theme = Theme.from_env()
    assert theme.color is False


def test_theme_from_env_term_dumb(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    theme = Theme.from_env()
    assert theme.color is False


def test_theme_color_property():
    assert Theme(color=True).color is True
    assert Theme(color=False).color is False
