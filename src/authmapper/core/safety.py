"""Safety primitives shared across the analyzer.

Every function here exists to uphold one of the tool's non-negotiable
guarantees (see SECURITY.md):

    * ReDoS resistance   — regexes run under a wall-clock budget.
    * Path confinement   — output can only be written beneath an allowed root.
    * Redaction          — snippets never echo probable secrets.
    * Bounded reads      — oversized / binary files are refused, not parsed.

The module is deliberately dependency-free and side-effect-free except for the
explicit filesystem checks in :func:`ensure_within`.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

# --- Bounded file reading ---------------------------------------------------

#: Files larger than this are skipped (defensive against accidental huge inputs
#: and pathological regex cost). Tunable via the walker, not hard policy.
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

#: A NUL byte in the first chunk is a strong binary signal.
_BINARY_SNIFF_BYTES = 4096


def looks_binary(sample: bytes) -> bool:
    """Heuristically decide whether a byte sample belongs to a binary file."""
    if b"\x00" in sample:
        return True
    # High ratio of non-text control bytes -> treat as binary.
    if not sample:
        return False
    text_bytes = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    nontext = sum(byte not in text_bytes for byte in sample)
    return (nontext / len(sample)) > 0.30


def read_text_safely(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> str | None:
    """Read a file as text within safety bounds.

    Returns ``None`` when the file should be skipped (too large, binary, or
    unreadable). Decoding falls back through common encodings so the tool works
    on real-world, mixed-encoding codebases across operating systems.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        return None

    try:
        raw = path.read_bytes()
    except OSError:
        return None

    if looks_binary(raw[:_BINARY_SNIFF_BYTES]):
        return None

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


# --- ReDoS-resistant regex --------------------------------------------------


class RegexTimeout(Exception):
    """Raised when a single regex search exceeds its time budget."""


class SafeMatcher:
    """Run ``re`` searches under a wall-clock budget.

    Python's ``re`` has no native timeout, so we execute the search in a daemon
    worker thread and abandon it if it overruns. This caps the blast radius of a
    catastrophic-backtracking pattern applied to hostile input. Patterns are
    also compiled once and reused.
    """

    def __init__(self, timeout_seconds: float = 1.0) -> None:
        self._timeout = max(0.05, timeout_seconds)

    def finditer(self, pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
        """Return all non-overlapping matches, or raise :class:`RegexTimeout`."""
        result: list[re.Match[str]] = []
        error: list[BaseException] = []

        def _work() -> None:
            try:
                result.extend(pattern.finditer(text))
            except BaseException as exc:  # noqa: BLE001 - propagated to caller
                error.append(exc)

        worker = threading.Thread(target=_work, daemon=True)
        worker.start()
        worker.join(self._timeout)
        if worker.is_alive():
            # The daemon thread is abandoned; the process is unaffected because
            # we never touched shared mutable state from it beyond local lists.
            raise RegexTimeout(f"regex exceeded {self._timeout}s budget")
        if error:
            raise error[0]
        return result


def compile_pattern(source: str, ignore_case: bool = True) -> re.Pattern[str]:
    """Compile a rule-pack pattern with sane, uniform flags."""
    flags = re.MULTILINE
    if ignore_case:
        flags |= re.IGNORECASE
    return re.compile(source, flags)


# --- Redaction --------------------------------------------------------------

_SECRET_HINT = re.compile(
    r"""(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]\s*\S+""",
    re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")


def redact(snippet: str, max_len: int = 160) -> str:
    """Return a snippet safe to embed in a report.

    Masks probable secrets and long high-entropy-looking tokens, collapses
    whitespace, and truncates. The goal is human context, never disclosure.
    """
    text = " ".join(snippet.split())
    text = _SECRET_HINT.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _LONG_TOKEN.sub("<redacted>", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "\u2026"
    return text


# --- Path confinement -------------------------------------------------------


class PathConfinementError(Exception):
    """Raised when an output path would escape its allowed root."""


def ensure_within(root: Path, candidate: Path) -> Path:
    """Resolve ``candidate`` and guarantee it stays under ``root``.

    Prevents path-traversal when writing reports (e.g. a crafted ``--output``
    containing ``..``). Returns the resolved, confined path.
    """
    root_resolved = root.resolve()
    if candidate.is_absolute():
        target = candidate.resolve()
    else:
        target = (root_resolved / candidate).resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise PathConfinementError(
            f"refusing to write outside report root: {target} !< {root_resolved}"
        ) from exc
    return target
