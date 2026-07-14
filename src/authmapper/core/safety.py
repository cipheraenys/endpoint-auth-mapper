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

import contextlib
import multiprocessing
import multiprocessing.queues
import re
from pathlib import Path
from typing import Any

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


class MatchProxy:
    """Lightweight surrogate for ``re.Match`` serialized across processes.

    Provides the same attributes used by the analyzer: ``.start()``,
    ``.end()``, ``.group()``, and ``.groups()``.  Named groups are accessible
    via ``group("name")``.
    """

    __slots__ = ("_start", "_end", "_groups", "_groupdict")

    def __init__(
        self,
        start: int,
        end: int,
        groups: tuple[str | Any, ...],
        groupdict: dict[str, str | Any],
    ) -> None:
        self._start = start
        self._end = end
        self._groups = groups
        self._groupdict = groupdict

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self, __group: int | str = 0) -> str | Any:
        if isinstance(__group, str):
            return self._groupdict.get(__group)
        return self._groups[__group]

    def groups(self) -> tuple[str | Any, ...]:
        return self._groups[1:]  # Match.groups() excludes group(0)


def _serialize_match(m: re.Match[str]) -> tuple[int, int, tuple, dict]:
    """Pickle-safe representation of the parts we need from a Match."""
    return (
        m.start(),
        m.end(),
        (m.group(0),) + m.groups(),
        {k: v for k, v in m.groupdict().items()},
    )


def _worker_loop(
    task_queue: multiprocessing.Queue,  # type: ignore[type-arg]
    result_queue: multiprocessing.Queue,  # type: ignore[type-arg]
) -> None:
    """Worker process loop: receive (pattern_src, flags, text), return matches.

    Runs in a spawned child process.  The parent can hard-terminate this process
    on timeout — unlike a daemon thread, the OS reclaims all resources cleanly.
    """
    while True:
        item = task_queue.get()
        if item is None:
            break  # Sentinel: graceful shutdown
        pattern_src, flags, text = item
        try:
            pattern = re.compile(pattern_src, flags)
            serialized = [_serialize_match(m) for m in pattern.finditer(text)]
            result_queue.put(("ok", serialized))
        except Exception as exc:  # noqa: BLE001 — propagated to caller
            result_queue.put(("error", str(exc)))


class SafeMatcher:
    """Run ``re`` searches under a wall-clock budget using process isolation.

    Python's ``re`` has no native timeout and a daemon thread cannot be killed
    when it enters catastrophic backtracking.  This implementation spawns a
    worker process that the parent can hard-terminate (``SIGKILL`` / Windows
    ``TerminateProcess``) when the budget expires, guaranteeing resource
    reclamation.

    The worker is reused across calls within a scan for amortisation.  After a
    timeout or crash it is transparently respawned.
    """

    def __init__(self, timeout_seconds: float = 1.0) -> None:
        self._timeout = max(0.05, timeout_seconds)
        self._ctx = multiprocessing.get_context("spawn")
        self._task_q: multiprocessing.Queue | None = None  # type: ignore[type-arg]
        self._result_q: multiprocessing.Queue | None = None  # type: ignore[type-arg]
        self._worker: multiprocessing.Process | None = None

    def _ensure_worker(self) -> None:
        """Start or restart the worker process if it is not alive."""
        if self._worker is not None and self._worker.is_alive():
            return
        # Clean up any dead worker before creating a new one.
        self._teardown_worker()
        self._task_q = self._ctx.Queue()
        self._result_q = self._ctx.Queue()
        self._worker = self._ctx.Process(
            target=_worker_loop,
            args=(self._task_q, self._result_q),
            daemon=True,
        )
        self._worker.start()

    def _teardown_worker(self) -> None:
        """Terminate and join the worker, draining queues."""
        if self._worker is not None:
            if self._worker.is_alive():
                self._worker.terminate()
                self._worker.join(timeout=1.0)
                if self._worker.is_alive():
                    self._worker.kill()
                    self._worker.join(timeout=1.0)
            self._worker.close()
            self._worker = None
        # Close queues to free OS resources.
        for q in (self._task_q, self._result_q):
            if q is not None:
                try:
                    q.close()
                    q.join_thread()
                except Exception:  # noqa: BLE001, S110 — best-effort cleanup
                    pass
        self._task_q = None
        self._result_q = None

    def finditer(self, pattern: re.Pattern[str], text: str) -> list[MatchProxy]:
        """Return all non-overlapping matches, or raise :class:`RegexTimeout`.

        Returns :class:`MatchProxy` objects that support the same attribute
        access as ``re.Match`` (``start``, ``end``, ``group``, ``groups``).

        If the worker exceeds the time budget it is hard-terminated and a fresh
        one is spawned on the next call.
        """
        self._ensure_worker()
        assert self._task_q is not None and self._result_q is not None

        self._task_q.put((pattern.pattern, pattern.flags, text))

        try:
            status, payload = self._result_q.get(timeout=self._timeout)
        except Exception as exc:
            # Queue timeout or broken pipe — worker took too long or crashed.
            self._teardown_worker()
            raise RegexTimeout(f"regex exceeded {self._timeout}s budget") from exc

        if status == "error":
            raise RuntimeError(f"regex worker error: {payload}")

        return [MatchProxy(start, end, groups, gd) for start, end, groups, gd in payload]

    def close(self) -> None:
        """Shut down the worker process.  Safe to call multiple times."""
        if self._worker is not None and self._worker.is_alive() and self._task_q is not None:
            try:
                self._task_q.put(None)  # Graceful sentinel
                self._worker.join(timeout=2.0)
            except Exception:  # noqa: BLE001 — best-effort graceful shutdown
                pass
        self._teardown_worker()

    def __del__(self) -> None:  # pragma: no cover — destructor safety net
        with contextlib.suppress(Exception):
            self.close()


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
    if candidate.is_absolute():  # noqa: SIM108 — readability over ternary for path ops
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
