"""Output reporters.

Reporters are pure *presentation*: they take a :class:`ScanResult` and render it
in a specific format. They never analyze and never mutate. This keeps output
formats pluggable and independently testable.

A reporter is any callable matching :data:`Reporter`.
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.model import ScanResult

#: A reporter renders a scan result to a string.
Reporter = Callable[[ScanResult], str]

from .json_reporter import render_json  # noqa: E402
from .sarif_reporter import render_sarif  # noqa: E402
from .table_reporter import render_table  # noqa: E402

#: Registry used by the CLI to resolve ``--format``.
REPORTERS: dict[str, Reporter] = {
    "table": render_table,
    "json": render_json,
    "sarif": render_sarif,
}

__all__ = ["Reporter", "REPORTERS", "render_table", "render_json", "render_sarif"]
