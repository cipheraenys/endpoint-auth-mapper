"""Unit tests for the screen buffer and terminal sizing."""

from __future__ import annotations

import io

from authmapper.tui.screen import Rect, ScreenBuffer, StringBackend, get_terminal_size


def test_screen_buffer_dimensions():
    buf = ScreenBuffer(10, 5)
    assert buf.width == 10
    assert buf.height == 5


def test_screen_buffer_invalid_dimensions():
    import pytest

    with pytest.raises(ValueError):
        ScreenBuffer(0, 5)
    with pytest.raises(ValueError):
        ScreenBuffer(5, 0)


def test_put_text_basic():
    buf = ScreenBuffer(10, 3)
    buf.put_text(2, 1, "hi")
    assert buf[2, 1].char == "h"
    assert buf[3, 1].char == "i"


def test_put_text_clips_overflow():
    buf = ScreenBuffer(5, 3)
    buf.put_text(0, 0, "hello world")
    assert buf[0, 0].char == "h"
    assert buf[4, 0].char == "o"
    # The ' ' after 'hello' should not overwrite column 4.
    assert buf[4, 0].char == "o"


def test_put_text_width_truncates():
    buf = ScreenBuffer(20, 3)
    buf.put_text(0, 0, "hello", width=3)
    assert buf[0, 0].char == "h"
    assert buf[1, 0].char == "e"
    assert buf[2, 0].char == "l"
    assert buf[3, 0].char == " "  # not written


def test_put_text_newline_moves_down():
    buf = ScreenBuffer(10, 5)
    buf.put_text(0, 0, "ab\ncd")
    assert buf[0, 0].char == "a"
    assert buf[1, 0].char == "b"
    assert buf[0, 1].char == "c"
    assert buf[1, 1].char == "d"


def test_put_box():
    buf = ScreenBuffer(10, 5)
    buf.put_box(Rect(0, 0, 5, 3))
    assert buf[0, 0].char == "┌"
    assert buf[4, 0].char == "┐"
    assert buf[0, 2].char == "└"
    assert buf[4, 2].char == "┘"
    assert buf[0, 1].char == "│"
    assert buf[4, 1].char == "│"
    assert buf[2, 0].char == "─"


def test_clear():
    buf = ScreenBuffer(5, 3)
    buf.put_text(0, 0, "hello")
    buf.clear()
    assert buf[0, 0].char == " "


def test_render_to_backend():
    buf = ScreenBuffer(5, 2)
    buf.put_text(0, 0, "hello")
    backend = StringBackend()
    buf.render(backend)
    out = backend.value
    assert "\033[?25l" in out  # cursor hide
    assert "\033[H" in out     # home
    assert "hello" in out


def test_get_terminal_size_fallback(monkeypatch):
    """When get_terminal_size fails, falls back to shutil/defaults."""
    import os

    def fake_get_terminal_size(*_a, **_k):
        raise OSError("no tty")

    monkeypatch.setattr(os, "get_terminal_size", fake_get_terminal_size)
    # shutil fallback should still work, or return default 80x24.
    cols, rows = get_terminal_size(io.StringIO())
    assert cols >= 1
    assert rows >= 1


def test_string_backend_size():
    backend = StringBackend()
    backend.size = (100, 40)
    assert backend.get_size() == (100, 40)
