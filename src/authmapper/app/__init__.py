"""Application layer.

This subpackage wires the pure core to the outside world: configuration,
baselines, confidential report writing, and the run orchestrator used by both
the CLI and the TUI. It is the only place (besides reporters/CLI) permitted to
touch the filesystem for output.
"""

from __future__ import annotations
