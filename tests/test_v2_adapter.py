"""M2-B adapter boundary tests."""

from __future__ import annotations

from dataclasses import fields

import pytest

from authmapper.core.v2 import AdapterArtifact, AdapterInput


def test_adapter_contract_cannot_emit_verdict_or_severity(tmp_path):
    names = {field.name for field in fields(AdapterArtifact)}

    assert "verdict" not in names
    assert "severity" not in names
    with pytest.raises(TypeError):
        AdapterArtifact(verdict="GUARDED")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        AdapterArtifact(severity="high")  # type: ignore[call-arg]

    input_data = AdapterInput(tmp_path, (tmp_path / "app.js",))
    assert input_data.project_root == tmp_path
