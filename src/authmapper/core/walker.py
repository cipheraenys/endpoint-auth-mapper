"""File discovery.

The walker turns a project root into a stream of candidate source files,
honouring:

    * an ignore file (``.authmapignore``, gitignore-style),
    * user ``--exclude`` directory names,
    * per-file size and binary guards (delegated to :mod:`safety`),
    * a set of glob patterns contributed by the active rule packs.

It performs *no* analysis; it only decides *what* to read and hands back decoded
text. Keeping discovery isolated makes performance tuning (streaming, parallel
reads) a local concern.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .model import CoverageStatus, SourceCoverage
from .safety import DEFAULT_MAX_FILE_BYTES, read_text_safely


@lru_cache(maxsize=512)
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob (with ``**`` support) into an anchored regex.

    Unlike :mod:`fnmatch`, this treats ``**`` as "any number of path segments"
    so ``**/*.js`` matches both ``a.js`` and ``src/a.js``. Paths are compared in
    POSIX form, so the same rule packs work identically on every OS.
    """
    i, n = 0, len(pattern)
    out = ["^"]
    while i < n:
        char = pattern[i]
        if char == "*":
            if pattern[i : i + 3] == "**/":
                out.append("(?:.*/)?")  # zero or more leading segments
                i += 3
                continue
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == ".":
            out.append(r"\.")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def glob_match(relpath: str, pattern: str) -> bool:
    """Return True when ``relpath`` (POSIX) matches a ``**``-aware ``pattern``."""
    return _glob_to_regex(pattern).match(relpath) is not None

#: Directories that are almost never worth scanning and are excluded by default.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".security-reports",
    "target",
    "bin",
    "obj",
)

# Broader than bundled pack support so relevant unsupported source stays visible.
ELIGIBLE_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".mjs",
        ".cjs",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".ts",
        ".tsx",
    }
)

IGNORE_FILENAME = ".authmapignore"


@dataclass(frozen=True)
class SourceFile:
    """A discovered, decoded file ready for the engine."""

    path: Path            # Absolute path on disk.
    relpath: str          # Project-relative POSIX path (stable across OS).
    text: str             # Decoded contents.


class FileWalker:
    """Discovers and reads candidate files under a project root."""

    def __init__(
        self,
        root: Path,
        *,
        include_globs: Sequence[str],
        extra_excludes: Sequence[str] = (),
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        self._root = root.resolve()
        self._include_globs = tuple(dict.fromkeys(include_globs))  # dedupe, keep order
        self._exclude_dirs = set(DEFAULT_EXCLUDES) | set(extra_excludes)
        self._max_file_bytes = max_file_bytes
        self._ignore_patterns = self._load_ignore_file()

        # Running counters for the summary; the walker owns discovery stats.
        self.skipped = 0
        self.coverage: list[SourceCoverage] = []

    # -- public API ----------------------------------------------------------

    def walk(self) -> Iterator[SourceFile]:
        """Yield decoded :class:`SourceFile` objects for matching files."""
        for path in self._iter_candidate_paths():
            rel = self._relpath(path)
            supported = self._matches_includes(rel)
            if path.suffix.lower() not in ELIGIBLE_SOURCE_SUFFIXES and not supported:
                continue
            if self._is_ignored(rel):
                self.coverage.append(
                    SourceCoverage(
                        file=rel,
                        status=CoverageStatus.EXCLUDED,
                        reason="matched project exclusion policy",
                    )
                )
                self.skipped += 1
                continue
            if not supported:
                self.coverage.append(
                    SourceCoverage(
                        file=rel,
                        status=CoverageStatus.UNSUPPORTED,
                        reason=f"no loaded rule pack supports {path.suffix.lower()}",
                    )
                )
                self.skipped += 1
                continue
            text = read_text_safely(path, max_bytes=self._max_file_bytes)
            if text is None:
                self.coverage.append(
                    SourceCoverage(
                        file=rel,
                        status=CoverageStatus.SKIPPED,
                        reason="safety/read guard rejected binary, oversized, undecodable, or unreadable source",
                    )
                )
                self.skipped += 1
                continue
            yield SourceFile(path=path, relpath=rel, text=text)

    # -- internals -----------------------------------------------------------

    def _iter_candidate_paths(self) -> Iterator[Path]:
        """Depth-first walk that prunes excluded directories early."""
        stack: list[Path] = [self._root]
        while stack:
            current = stack.pop()
            try:
                entries = list(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_dir():
                    stack.append(entry)
                elif entry.is_file():
                    yield entry

    def _relpath(self, path: Path) -> str:
        return path.relative_to(self._root).as_posix()

    def _matches_includes(self, rel: str) -> bool:
        return any(glob_match(rel, pat) for pat in self._include_globs)

    def _is_ignored(self, rel: str) -> bool:
        return bool(set(Path(rel).parts) & self._exclude_dirs) or any(
            glob_match(rel, pat) for pat in self._ignore_patterns
        )

    def _load_ignore_file(self) -> tuple[str, ...]:
        ignore_path = self._root / IGNORE_FILENAME
        text = read_text_safely(ignore_path) if ignore_path.exists() else None
        if not text:
            return ()
        patterns: list[str] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Normalise a trailing-slash dir pattern into a recursive glob.
            patterns.append(f"{line.rstrip('/')}/**" if line.endswith("/") else line)
        return tuple(patterns)


def resolve_project_root(candidate: str | None) -> Path:
    """Resolve and validate a user-supplied project path."""
    root = Path(candidate or ".").expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"project path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"project path is not a directory: {root}")
    return root
