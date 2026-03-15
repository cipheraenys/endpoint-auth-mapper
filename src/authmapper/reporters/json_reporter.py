"""Machine-readable JSON reporter.

Emits a stable, sorted JSON document suitable for programmatic consumption,
diffing, and baseline generation. The schema mirrors :meth:`ScanResult.to_dict`.
"""

from __future__ import annotations

import json

from ..core.model import ScanResult

SCHEMA_VERSION = "1.0"


def render_json(result: ScanResult) -> str:
    """Render ``result`` as an indented, deterministic JSON string."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": "endpoint-auth-mapper",
        **result.to_dict(),
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
