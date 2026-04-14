"""Unit tests for the input layer (key mapping and search input)."""

from __future__ import annotations

from authmapper.tui.input import _ANSI_MAP, SearchInput, _char_to_key, is_printable


def test_char_to_key_enter():
    assert _char_to_key("\r") == "enter"
    assert _char_to_key("\n") == "enter"


def test_char_to_key_escape():
    assert _char_to_key("\x1b") == "escape"


def test_char_to_key_tab():
    assert _char_to_key("\t") == "tab"


def test_char_to_key_backspace():
    assert _char_to_key("\x7f") == "backspace"


def test_char_to_key_ctrl():
    assert _char_to_key("\x03") == "ctrl+c"
    assert _char_to_key("\x06") == "ctrl+f"


def test_char_to_key_printable():
    assert _char_to_key("a") == "a"
    assert _char_to_key("Z") == "Z"


def test_ansi_map_has_arrows():
    assert _ANSI_MAP["\x1b[A"] == "up"
    assert _ANSI_MAP["\x1b[B"] == "down"
    assert _ANSI_MAP["\x1b[C"] == "right"
    assert _ANSI_MAP["\x1b[D"] == "left"


def test_is_printable():
    assert is_printable("a") is True
    assert is_printable(" ") is True
    assert is_printable("up") is False
    assert is_printable("\x1b") is False


def test_search_input_insert():
    s = SearchInput("")
    s.insert("a")
    s.insert("b")
    assert s.text == "ab"
    assert s.cursor == 2


def test_search_input_insert_at_cursor():
    s = SearchInput("ac")
    s.cursor = 1
    s.insert("b")
    assert s.text == "abc"
    assert s.cursor == 2


def test_search_input_backspace():
    s = SearchInput("abc")
    s.backspace()
    assert s.text == "ab"
    assert s.cursor == 2


def test_search_input_backspace_at_start():
    s = SearchInput("abc")
    s.cursor = 0
    s.backspace()
    assert s.text == "abc"
    assert s.cursor == 0


def test_search_input_delete():
    s = SearchInput("abc")
    s.cursor = 1
    s.delete()
    assert s.text == "ac"
    assert s.cursor == 1


def test_search_input_move_home_end():
    s = SearchInput("abc")
    s.move_home()
    assert s.cursor == 0
    s.move_end()
    assert s.cursor == 3


def test_search_input_move_left_right():
    s = SearchInput("abc")
    s.move_left()
    assert s.cursor == 2
    s.move_home()
    s.move_left()
    assert s.cursor == 0
    s.move_right()
    assert s.cursor == 1
