"""M2-C SARIF evidence mapping contract tests."""

from __future__ import annotations

import json

from test_v2_report import evidence_report

from authmapper.reporters.v2_sarif_reporter import render_evidence_sarif


def test_v2_sarif_has_stable_rules_regions_provenance_and_properties():
    sarif = json.loads(render_evidence_sarif(evidence_report()))
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    guarded = run["results"][0]

    assert sarif["version"] == "2.1.0"
    assert [rule["id"] for rule in rules] == ["AMV2-0001", "AMV2-0002", "AMV2-0003", "AMV2-0004", "AMV2-0005"]
    assert guarded["ruleId"] == "AMV2-0001"
    assert guarded["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 3,
        "startColumn": 1,
        "endLine": 3,
        "endColumn": 42,
    }
    assert set(guarded["partialFingerprints"]) == {"authmapEndpointFingerprint/v1"}
    assert guarded["properties"]["authmap"]["sarifMappingVersion"] == "1.0"
    assert run["invocations"][0]["commandLine"] == "authmap --project ."
    assert run["versionControlProvenance"][0]["revisionId"] == "abc123"
    assert "authmap" not in run["tool"]["driver"]


def test_v2_sarif_emits_incomplete_coverage_diagnostic():
    results = json.loads(render_evidence_sarif(evidence_report()))["runs"][0]["results"]
    coverage = [item for item in results if item["ruleId"] == "AMV2-0005"]

    assert len(coverage) == 1
    assert coverage[0]["level"] == "error"
    assert coverage[0]["properties"]["authmap"]["status"] == "error"
    assert coverage[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.js"
