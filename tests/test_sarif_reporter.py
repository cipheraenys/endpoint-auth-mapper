"""Contract tests for SARIF reporter metadata."""

from __future__ import annotations

import json

from authmapper import __version__
from authmapper.core.model import CoverageStatus, ScanResult, SourceCoverage
from authmapper.reporters.json_reporter import render_json
from authmapper.reporters.sarif_reporter import render_sarif
from authmapper.reporters.table_reporter import render_table


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


def test_sarif_reports_incomplete_source_coverage():
    result = ScanResult(
        findings=(),
        errors=(),
        files_scanned=0,
        files_skipped=1,
        rulepacks_used=(),
        duration_seconds=0.0,
        coverage=(
            SourceCoverage(
                file="src/main.rs",
                status=CoverageStatus.UNSUPPORTED,
                reason="no loaded rule pack supports .rs",
            ),
        ),
    )

    report = json.loads(render_sarif(result))
    run = report["runs"][0]

    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} >= {"source-coverage"}
    assert run["results"][0]["ruleId"] == "source-coverage"
    assert run["results"][0]["properties"]["coverageStatus"] == "UNSUPPORTED"


def test_analysis_error_is_visible_in_all_reporters():
    result = ScanResult(
        findings=(),
        errors=(),
        files_scanned=0,
        files_skipped=1,
        rulepacks_used=("test",),
        duration_seconds=0.0,
        coverage=(
            SourceCoverage(
                file="src/broken.js",
                status=CoverageStatus.ERROR,
                reason="analysis failed; see scan errors",
                rulepacks=("test",),
            ),
        ),
    )

    json_report = json.loads(render_json(result))
    sarif_report = json.loads(render_sarif(result))
    table_report = render_table(result)

    assert json_report["coverage"][0]["status"] == "ERROR"
    assert sarif_report["runs"][0]["results"][0]["properties"]["coverageStatus"] == "ERROR"
    assert "ERROR: src/broken.js" in table_report
