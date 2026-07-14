"""Contract tests for SARIF reporter metadata."""

from __future__ import annotations

import json

from authmapper import __version__
from authmapper.core.model import ScanResult
from authmapper.reporters.sarif_reporter import render_sarif


def test_sarif_driver_version_matches_package_version():
    result = ScanResult(
        findings=(),
        errors=(),
        files_scanned=0,
        files_skipped=0,
        rulepacks_used=(),
        duration_seconds=0.0,
    )
    report = json.loads(render_sarif(result))

    assert report["runs"][0]["tool"]["driver"]["version"] == __version__
