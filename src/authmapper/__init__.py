"""Endpoint & Auth Mapper.

A universal, offline, dependency-free static analyzer that maps HTTP endpoints
across languages and classifies their authentication posture as one of:
PROTECTED, EXPOSED, UNKNOWN, or PUBLIC.

Design guarantees (see SECURITY.md):
    * Source-gated  — analyzes source you already possess; no network egress.
    * Fail-safe     — ambiguity is reported as UNKNOWN, never PROTECTED.
    * Read-only     — target code is parsed as text, never imported or executed.
    * Zero-deps     — Python standard library only at runtime.
    * Deterministic — stable, sorted output suitable for CI diffing.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
