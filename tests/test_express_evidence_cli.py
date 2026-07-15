"""M3-D explicit evidence scan integration tests."""

from __future__ import annotations

import json
from datetime import date, timedelta
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


def _policy(tmp_path: Path) -> Path:
    path = tmp_path / "evidence-policy.json"
    capabilities = (
        "auth_association",
        "endpoint_discovery",
        "route_composition",
        "scope_resolution",
    )
    path.write_text(
        json.dumps(
            {
                "$schema": "https://authmap.dev/schemas/evidence-policy-1.0.json",
                "schema_version": "1.0",
                "id": "default.assurance",
                "fail_on_unguarded": True,
                "fail_on_unresolved": False,
                "fail_on_incomplete_coverage": True,
                "requirements": [
                    {
                        "id": f"express.{capability}",
                        "adapter_id": "express",
                        "adapter_version": "0.1.0",
                        "capability": capability,
                        "minimum_maturity": "verified",
                    }
                    for capability in capabilities
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


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


def test_evidence_policy_gate_returns_satisfied_and_violation_exit_codes(tmp_path: Path, capsys):
    root = _project(tmp_path)
    policy = _policy(tmp_path)

    assert main([
        "--project", str(root), "--evidence-scan", "express", "--format", "json",
        "--evidence-policy", str(policy), "--quiet",
    ]) == 0

    root.joinpath("app.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/admin", handler);\n',
        encoding="utf-8",
    )
    assert main([
        "--project", str(root), "--evidence-scan", "express", "--format", "json",
        "--evidence-policy", str(policy), "--quiet",
    ]) == 1
    assert capsys.readouterr().err == ""


def test_invalid_evidence_policy_returns_setup_error_before_gate(tmp_path: Path, capsys):
    root = _project(tmp_path)
    policy = _policy(tmp_path)
    policy.write_text('{"schema_version":"2.0"}', encoding="utf-8")

    code = main([
        "--project", str(root), "--evidence-scan", "express", "--format", "json",
        "--evidence-policy", str(policy), "--quiet",
    ])

    assert code == 2
    assert "invalid evidence policy" in capsys.readouterr().err


def test_evidence_policy_options_require_explicit_evidence_scan(tmp_path: Path):
    policy = _policy(tmp_path)

    with pytest.raises(SystemExit, match="2"):
        main(["--evidence-policy", str(policy)])


def test_exception_audit_command_returns_satisfied_and_setup_exit_codes(tmp_path: Path):
    root = _project(tmp_path)
    root.joinpath("app.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/admin", handler);\n',
        encoding="utf-8",
    )
    policy = _policy(tmp_path)
    from authmapper.app.evidence_runner import run_express_evidence_scan
    from authmapper.core.v2 import endpoint_fingerprint

    report = run_express_evidence_scan(root, ("authmap",)).report
    endpoint = next(item for item in report.graph.facts if item.path == "/admin")
    exceptions = tmp_path / "exceptions.json"
    today = date.today()
    exceptions.write_text(
        json.dumps(
            {
                "$schema": "https://authmap.dev/schemas/evidence-exceptions-1.0.json",
                "schema_version": "1.0",
                "exceptions": [
                    {
                        "id": "exception.admin",
                        "reason": "migration",
                        "owner": "security",
                        "reference": "SEC-123",
                        "created_on": (today - timedelta(days=1)).isoformat(),
                        "expires_on": (today + timedelta(days=1)).isoformat(),
                        "review_on": None,
                        "authorizing_policy_id": "default.assurance",
                        "identity": {
                            "method": "GET",
                            "path": "/admin",
                            "adapter_id": "express",
                            "adapter_version": "0.1.0",
                            "capability": "auth_association",
                            "maturity": "verified",
                            "endpoint_fingerprint_algorithm": "authmap.endpoint.v1",
                            "endpoint_fingerprint": endpoint_fingerprint(endpoint).value,
                            "violation": "unguarded",
                            "policy_id": "default.assurance",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    args = [
        "--project", str(root), "--evidence-scan", "express", "--format", "json",
        "--evidence-policy", str(policy), "--audit-exceptions", str(exceptions), "--quiet",
    ]

    assert main(args) == 0
    document = json.loads(exceptions.read_text(encoding="utf-8"))
    document["exceptions"][0]["created_on"] = "1999-01-01"
    document["exceptions"][0]["expires_on"] = "2000-01-01"
    exceptions.write_text(json.dumps(document), encoding="utf-8")
    assert main(args) == 2


def test_exception_audit_requires_evidence_policy():
    with pytest.raises(SystemExit, match="2"):
        main(["--audit-exceptions", "exceptions.json"])


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
