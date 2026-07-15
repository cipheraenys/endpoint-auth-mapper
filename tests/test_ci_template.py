"""M4-E CI template contract tests."""

from pathlib import Path

import pytest
import yaml

from authmapper.core.v2 import load_evidence_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "output_format"),
    [
        ("github-actions.yml", "sarif"),
        ("github-actions-json.yml", "json"),
    ],
)
def test_ci_template_uses_explicit_policy_and_safe_failure(filename: str, output_format: str):
    workflow = yaml.safe_load((ROOT / "examples/ci" / filename).read_text(encoding="utf-8"))
    steps = workflow["jobs"]["evidence-gate"]["steps"]
    gate = next(item for item in steps if item.get("name") == "Gate evidence")

    assert "--evidence-scan express" in gate["run"]
    assert "--evidence-policy examples/ci/evidence-policy.json" in gate["run"]
    assert f"--format {output_format}" in gate["run"]
    assert "continue-on-error" not in gate
    assert workflow["permissions"] == {"contents": "read"}
    load_evidence_policy(ROOT / "examples/ci/evidence-policy.json")
