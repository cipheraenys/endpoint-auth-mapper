"""M3-A parser and applicability tests."""

from __future__ import annotations

import json
from pathlib import Path

from authmapper.adapters import ExpressAdapter
from authmapper.adapters.express import MAX_SOURCE_BYTES
from authmapper.core.v2 import AdapterInput, ApplicabilityState


def _project(tmp_path: Path, dependencies: dict[str, str] | None = None) -> Path:
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": dependencies or {}}), encoding="utf-8"
    )
    return tmp_path


def _result(root: Path, *paths: Path):
    return ExpressAdapter().applicability(AdapterInput(root, paths))


def test_esm_and_cjs_bindings_activate_only_with_package_dependency(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0"})
    esm = root / "esm.mjs"
    cjs = root / "cjs.cjs"
    esm.write_text('import express from "express";\nconst app = express();\n', encoding="utf-8")
    cjs.write_text('const web = require("express");\nconst app = web();\n', encoding="utf-8")

    result = _result(root, esm, cjs)

    assert result.state is ApplicabilityState.ACTIVE
    assert [item.kind for item in result.evidence] == ["express_binding", "express_binding", "package_dependency"]
    assert {item.value for item in result.evidence} == {"express", "web", "package.json:express"}


def test_receiver_names_and_other_framework_imports_never_activate(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0", "fastify": "5.0.0"})
    source = root / "app.js"
    source.write_text(
        'const app = require("fastify")();\napp.get("/x", handler);\n'
        'const express = require("koa");\nconst router = express.Router();\n',
        encoding="utf-8",
    )

    assert _result(root, source).state is ApplicabilityState.INACTIVE


def test_nearest_package_prevents_monorepo_sibling_dependency_leak(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0"})
    sibling = root / "packages" / "hono-service"
    sibling.mkdir(parents=True)
    _project(sibling, {"hono": "4.0.0"})
    source = sibling / "app.js"
    source.write_text('const express = require("express");\n', encoding="utf-8")

    assert _result(root, source).state is ApplicabilityState.INACTIVE


def test_parse_and_package_failures_are_ambiguous_diagnostics(tmp_path: Path):
    root = tmp_path
    root.joinpath("package.json").write_text("{", encoding="utf-8")
    invalid_syntax = root / "invalid.js"
    invalid_syntax.write_text('const express = require("express";\n', encoding="utf-8")
    invalid_package = root / "valid.js"
    invalid_package.write_text('const express = require("express");\n', encoding="utf-8")
    adapter = ExpressAdapter()
    input_data = AdapterInput(root, (invalid_syntax, invalid_package))

    result = adapter.applicability(input_data)
    artifact = adapter.analyze(input_data)

    assert result.state is ApplicabilityState.AMBIGUOUS
    assert artifact.subjects == ()
    assert [item.code for item in artifact.diagnostics] == [
        "express.package.invalid",
        "express.source.parse_error",
    ]


def test_oversized_source_fails_closed_without_parsing(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0"})
    source = root / "large.js"
    source.write_bytes(b" " * (MAX_SOURCE_BYTES + 1))

    artifact = ExpressAdapter().analyze(AdapterInput(root, (source,)))

    assert artifact.facts == ()
    assert [item.code for item in artifact.diagnostics] == ["express.budget.source_bytes"]


def test_package_route_module_without_express_binding_is_incomplete(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0"})
    source = root / "routes.js"
    source.write_text(
        "module.exports = app => { app.get('/users', handler); };\n",
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(root, (source,)))

    assert artifact.facts == ()
    assert [item.code for item in artifact.diagnostics] == ["express.route.unresolved_binding"]
    assert artifact.diagnostics[0].level.value == "error"


def test_callback_route_module_with_nonstandard_receiver_is_incomplete(tmp_path: Path):
    root = _project(tmp_path, {"express": "4.21.0"})
    source = root / "routes.js"
    source.write_text(
        "module.exports = (application, passport) =>\n"
        "  application.post('/login', passport.authenticate('local'), handler);\n",
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(root, (source,)))

    assert artifact.facts == ()
    assert [item.code for item in artifact.diagnostics] == ["express.route.unresolved_binding"]
