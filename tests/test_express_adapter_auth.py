"""M3-C Express auth semantic and order tests."""

from __future__ import annotations

import json
from pathlib import Path

from authmapper.adapters import ExpressAdapter, build_express_graph
from authmapper.core.v2 import AdapterInput, EndpointVerdict, resolve_endpoints


def _resolve(tmp_path: Path, source: str):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0", "passport": "0.7.0"}}), encoding="utf-8"
    )
    path = tmp_path / "app.js"
    path.write_text(source, encoding="utf-8")
    adapter = ExpressAdapter()
    artifact = adapter.analyze(AdapterInput(tmp_path, (path,)))
    graph = build_express_graph(artifact, adapter_version=adapter.version)
    return graph, resolve_endpoints(graph)


def test_exact_passport_import_and_route_middleware_proves_guard(tmp_path: Path):
    graph, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst passport = require("passport");\n'
        'const app = express();\napp.get("/me", passport.authenticate("jwt"), handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.GUARDED]
    assert len(graph.proofs) == 1


def test_late_middleware_does_not_protect_earlier_route(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'import express from "express";\nimport passport from "passport";\nconst app = express();\n'
        'app.get("/early", handler);\napp.use(passport.authenticate("jwt"));\napp.get("/late", handler);\n',
    )

    verdicts = {item.endpoint_id: item.verdict for item in resolutions}
    assert list(verdicts.values()) == [EndpointVerdict.UNGUARDED, EndpointVerdict.GUARDED]


def test_auth_name_without_provenance_is_unresolved_not_guarded(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'app.get("/admin", requireAuth, handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNRESOLVED]


def test_passport_lookalike_import_never_proves_enforcement(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst passport = require("fake-passport");\nconst app = express();\n'
        'app.get("/admin", passport.authenticate("jwt"), handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNGUARDED]


def test_named_passport_export_alias_never_proves_enforcement(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'import express from "express";\nimport { Strategy as passport } from "passport";\n'
        'const app = express();\napp.get("/admin", passport.authenticate("jwt"), handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNGUARDED]


def test_passport_oauth_flow_is_not_treated_as_resource_enforcement(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst passport = require("passport");\nconst app = express();\n'
        'app.get("/auth/github/callback", passport.authenticate("github"), handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNGUARDED]


def test_passport_local_login_is_not_resource_enforcement(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst passport = require("passport");\nconst app = express();\n'
        'app.post("/login", passport.authenticate("local", { session: false }), handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNGUARDED]


def test_jwt_mount_protects_only_its_imported_router(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0", "passport": "0.7.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    protected = tmp_path / "protected.js"
    public = tmp_path / "public.js"
    app.write_text(
        'const express = require("express");\nconst passport = require("passport");\n'
        'const protectedRoutes = require("./protected");\nconst publicRoutes = require("./public");\n'
        'const app = express();\n'
        'app.use("/api", passport.authenticate("jwt", { session: false }), protectedRoutes);\n'
        'app.use("/api", publicRoutes);\n',
        encoding="utf-8",
    )
    protected.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/secret", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )
    public.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/status", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    adapter = ExpressAdapter()
    artifact = adapter.analyze(AdapterInput(tmp_path, (app, protected, public)))
    graph = build_express_graph(artifact, adapter_version=adapter.version)
    resolutions = resolve_endpoints(graph)

    assert [(item.method, item.path) for item in graph.facts if item.method] == [
        ("GET", "/api/secret"),
        ("GET", "/api/status"),
    ]
    assert [item.verdict for item in resolutions] == [EndpointVerdict.GUARDED, EndpointVerdict.UNGUARDED]


def test_auth_semantics_inside_handler_remain_unresolved(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'app.post("/change-password", async (req, res) => {\n'
        '  await services.changePasswordToken(req.body.token, req.body.password);\n'
        '  res.sendStatus(204);\n});\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNRESOLVED]


def test_handler_auth_lifecycle_members_are_unresolved(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'app.post("/logout", validate, authController.logout);\n'
        'app.post("/refresh", validate, authController.refreshTokens);\n'
        'app.post("/reset", validate, authController.resetPassword);\n'
        'app.post("/verify", validate, authController.verifyEmail);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNRESOLVED] * 4


def test_non_enforcement_handler_members_remain_unguarded(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'app.post("/register", validate, authController.register);\n'
        'app.post("/login", validate, authController.login);\n'
        'app.post("/forgot", validate, authController.forgotPassword);\n'
        'app.get("/profile", handlerController.getProfile);\n'
        'app.post("/ordinary", validate, handler);\n'
        'app.post("/inline", validate, (req, res) => res.send("ok"));\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.UNGUARDED] * 6


def test_versioned_public_declaration_requires_policy_owner_reason(tmp_path: Path):
    _, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        '// authmap-public-v1 policy=service-access owner=platform reason=healthcheck\n'
        'app.get("/health", handler);\n'
        '// authmap-public-v1 owner=platform reason=missing-policy\n'
        'app.get("/not-public", handler);\n',
    )

    assert [item.verdict for item in resolutions] == [
        EndpointVerdict.DECLARED_PUBLIC,
        EndpointVerdict.UNGUARDED,
    ]


def test_custom_auth_requires_exact_source_declaration_and_local_import(tmp_path: Path):
    tmp_path.joinpath("auth.js").write_text("module.exports = function requireAuth() {};\n", encoding="utf-8")
    graph, resolutions = _resolve(
        tmp_path,
        'const express = require("express");\nconst requireAuth = require("./auth.js");\n'
        '// authmap-auth-v1 module=./auth.js symbol=requireAuth rule=service-jwt\n'
        'const app = express();\napp.get("/admin", requireAuth, handler);\n',
    )

    assert [item.verdict for item in resolutions] == [EndpointVerdict.GUARDED]
    auth_subject = next(item for item in graph.subjects if item.name == "custom-auth:service-jwt")
    assert auth_subject.span.path == "app.js"
