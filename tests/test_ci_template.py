"""M4-E CI template contract tests."""

from pathlib import Path

import pytest

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
    workflow = (ROOT / "examples/ci" / filename).read_text(encoding="utf-8")

    assert "--evidence-scan express" in workflow
    assert "--evidence-policy examples/ci/evidence-policy.json" in workflow
    assert f"--format {output_format}" in workflow
    assert "continue-on-error" not in workflow
    assert "permissions:\n  contents: read" in workflow
    load_evidence_policy(ROOT / "examples/ci/evidence-policy.json")
