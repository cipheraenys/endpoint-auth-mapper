"""Endpoint & Auth Mapper.

The default scanner inventories route-shaped candidates with legacy regex
heuristics and emits unverified compatibility states. The opt-in Express
evidence scan provides parser-backed v2 evidence within its documented support
envelope.

Design guarantees (see SECURITY.md):
    * Source-gated  — analyzes source you already possess; no network egress.
    * Fail-safe     — unassociated evidence remains UNKNOWN or UNRESOLVED.
    * Read-only     — target code is parsed as text, never imported or executed.
    * Audited deps  — explicit dependencies validate inert public contracts.
    * Deterministic — stable, sorted output suitable for CI diffing.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.2"
