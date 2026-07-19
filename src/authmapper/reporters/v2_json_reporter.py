"""Deterministic JSON serializer for evidence report schema v2."""

from __future__ import annotations

import json

from ..core.v2.contracts import REPORT_SCHEMA_VERSION
from ..core.v2.report import EvidenceReport, report_document


def render_evidence_json(report: EvidenceReport) -> str:
    return json.dumps(
        report_document(report, schema_version=REPORT_SCHEMA_VERSION),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
