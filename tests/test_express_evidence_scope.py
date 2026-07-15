"""M3 independent scan scope and member-auth tests."""

from __future__ import annotations

import json
from pathlib import Path

from authmapper.adapters import ExpressAdapter, build_express_graph
from authmapper.app.evidence_runner import run_express_evidence_scan
from authmapper.core.v2 import AdapterInput, EndpointVerdict, resolve_endpoints


def test_member_auth_middleware_is_proven_only_by_explicit_supported_member(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    tmp_path.joinpath("passport-config.js").write_text(
        "module.exports = { isAuthenticated: (req, res, next) => next() };\n", encoding="utf-8"
    )
    source = tmp_path / "app.js"
    source.write_text(
        'const express = require("express");\nconst passportConfig = require("./passport-config");\n'
        '// authmap-auth-v1 module=./passport-config symbol=passportConfig.isAuthenticated rule=session-auth\n'
        'const app = express();\napp.get("/account", passportConfig.isAuthenticated, handler);\n',
        encoding="utf-8",
    )

    adapter = ExpressAdapter()
    artifact = adapter.analyze(AdapterInput(tmp_path, (source,)))
    graph = build_express_graph(artifact, adapter_version=adapter.version)

    assert resolve_endpoints(graph)[0].verdict is EndpointVerdict.GUARDED


def test_evidence_runner_omits_test_and_dependency_sources(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    (tmp_path / "app.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/live", handler);\n',
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "app.test.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/test", handler);\n',
        encoding="utf-8",
    )
    dependency = tmp_path / "node_modules" / "other"
    dependency.mkdir(parents=True)
    dependency.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    dependency.joinpath("app.js").write_text(
        'const express = require("express");\nconst app = express();\napp.get("/dependency", handler);\n',
        encoding="utf-8",
    )

    result = run_express_evidence_scan(tmp_path, ("authmap", "--evidence-scan", "express"))

    paths = {fact.span.path for fact in result.report.graph.facts if fact.path is not None}
    assert paths == {"app.js"}
    assert [fact.path for fact in result.report.graph.facts if fact.path is not None] == ["/live"]
