"""Unit tests for safety primitives (redaction, confinement, bounded reads)."""

from __future__ import annotations

from pathlib import Path

import pytest

from authmapper.core.safety import (
    PathConfinementError,
    RegexTimeout,
    SafeMatcher,
    compile_pattern,
    ensure_within,
    looks_binary,
    read_text_safely,
    redact,
)


def test_redact_masks_secrets():
    assert "<redacted>" in redact('password: "hunter2super"')
    assert "<redacted>" in redact("api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")


def test_redact_truncates():
    # Use many short words so the long-token redactor does not collapse them
    # first; this exercises the length cap specifically.
    long_text = " ".join(["word"] * 200)
    assert redact(long_text).endswith("\u2026")


def test_ensure_within_allows_child(tmp_path: Path):
    target = ensure_within(tmp_path, Path("report.json"))
    assert str(target).startswith(str(tmp_path.resolve()))


def test_ensure_within_blocks_traversal(tmp_path: Path):
    with pytest.raises(PathConfinementError):
        ensure_within(tmp_path, Path("../escape.json"))


def test_looks_binary_detects_nul():
    assert looks_binary(b"abc\x00def")
    assert not looks_binary(b"plain text content")


def test_read_text_skips_oversized(tmp_path: Path):
    big = tmp_path / "big.txt"
    big.write_text("A" * 100)
    assert read_text_safely(big, max_bytes=10) is None


def test_safe_matcher_returns_matches():
    pattern = compile_pattern(r"\d+")
    matcher = SafeMatcher(timeout_seconds=1.0)
    matches = matcher.finditer(pattern, "a1 b22 c333")
    assert [m.group(0) for m in matches] == ["1", "22", "333"]
