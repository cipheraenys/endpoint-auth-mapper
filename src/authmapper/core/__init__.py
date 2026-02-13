"""Core analysis domain: model, discovery, engine, and classification.

This subpackage is intentionally free of any I/O concerned with *presentation*
(reporters) or *interaction* (CLI/TUI). It contains the pure analysis pipeline:

    walker  -> engine (rulepacks) -> classifier -> findings

Keeping this boundary crisp is what makes the tool a modular monolith: one
deployable unit, but with strongly separated internal modules.
"""

from __future__ import annotations
