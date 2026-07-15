"""M3-D explicit evidence scan integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmapper.cli import main


def _project(tmp_path: Path) -> Path:
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0", "passport": "0.7.0"}}), encoding="utf-8"
    )
    tmp_path.joinpath("app.js").write_text(
        'const express = require("express");\nconst passport = require("passport");\n'
        'const app = express();\napp.get("/me", passport.authenticate("jwt"), handler);\n',
        encoding="utf-8",
    )
    return tmp_path


def test_explicit_json_scan_runs_adapter_to_v2_report(tmp_path: Path, capsys):
    code = main(["--project", str(_project(tmp_path)), "--evidence-scan", "express", "--format", "json"])

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["schema_version"] == "2.0"
    assert document["endpoint_resolutions"][0]["verdict"] == "GUARDED"
    assert document["graph"]["proofs"][0]["derived_from"]


def test_explanation_exposes_activation_and_rules_without_changing_report(tmp_path: Path, capsys):
    code = main(
        [
            "--project", str(_project(tmp_path)), "--evidence-scan", "express", "--format", "json",
            "--explain-adapter",
        ]
    )

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["adapter_explanation"]["applicability"]["state"] == "active"
    assert document["adapter_explanation"]["applied_rule_ids"] == ["express.passport.authenticate"]
    assert {
        item["capability"]: item["maturity"]
        for item in document["adapter_explanation"]["capabilities"]
    } == {
        "auth_association": "verified",
        "endpoint_discovery": "verified",
        "public_override": "experimental",
        "route_composition": "verified",
        "scope_resolution": "verified",
    }
    assert document["evidence_report"]["endpoint_resolutions"][0]["verdict"] == "GUARDED"


def test_evidence_scan_rejects_legacy_policy_flags(tmp_path: Path):
    with pytest.raises(SystemExit, match="2"):
        main(
            [
                "--project", str(_project(tmp_path)), "--evidence-scan", "express", "--format", "json",
                "--fail-on", "EXPOSED",
            ]
        )


def test_evidence_scan_excludes_dependency_directories(tmp_path: Path, capsys):
    root = _project(tmp_path)
    dependency = root / "node_modules" / "embedded"
    dependency.mkdir(parents=True)
    dependency.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    dependency.joinpath("app.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/dependency", handler);\n',
        encoding="utf-8",
    )

    code = main(["--project", str(root), "--evidence-scan", "express", "--format", "json"])

    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [item["path"] for item in document["graph"]["facts"] if item["path"] is not None] == ["/me"]
