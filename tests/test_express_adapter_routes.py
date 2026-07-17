"""M3-B route and composition evidence tests."""

from __future__ import annotations

import json
from pathlib import Path

from authmapper.adapters import ExpressAdapter
from authmapper.core.v2 import AdapterInput, RelationKind, SubjectKind


def _artifact(tmp_path: Path, source: str):
    tmp_path.joinpath("package.json").write_text(json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8")
    path = tmp_path / "app.js"
    path.write_text(source, encoding="utf-8")
    return ExpressAdapter().analyze(AdapterInput(tmp_path, (path,)))


def test_extracts_methods_multiline_handlers_and_route_chains(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'import express from "express";\nconst router = express.Router();\n'
        'router.get(\n  "/users",\n  audit,\n  handler\n);\n'
        'router.route("/account").delete(removeAccount);\n',
    )

    assert [(fact.method, fact.path) for fact in artifact.facts] == [
        ("GET", "/users"),
        ("DELETE", "/account"),
    ]
    handlers = [item.name for item in artifact.subjects if item.kind is SubjectKind.HANDLER]
    middleware = [item.name for item in artifact.subjects if item.kind is SubjectKind.MIDDLEWARE]
    assert handlers == ["handler", "removeAccount"]
    assert middleware == ["audit"]
    artifact_graph(artifact).validate()


def test_route_chain_emits_every_method_with_own_handlers(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst router = express.Router();\n'
        'router.route("/users").get(listUsers).post(requireAuth, createUser);\n',
    )

    assert [(fact.method, fact.path) for fact in artifact.facts] == [
        ("GET", "/users"),
        ("POST", "/users"),
    ]
    assert [item.name for item in artifact.subjects if item.kind is SubjectKind.MIDDLEWARE] == ["requireAuth"]
    assert [item.name for item in artifact.subjects if item.kind is SubjectKind.HANDLER] == ["listUsers", "createUser"]
    artifact_graph(artifact).validate()


def test_mounts_preserve_literal_prefix_and_registration_order(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'const parent = express.Router();\nconst child = express.Router();\n'
        'app.use("/api", parent);\nparent.use("/v1", child);\nchild.get("/users", handler);\n',
    )

    mounts = [item for item in artifact.relations if item.kind is RelationKind.COMPOSES]
    assert [item.order for item in mounts] == [1, 2]
    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/api/v1/users")]
    assert len(artifact.facts[0].derived_from) == 3
    artifact_graph(artifact).validate()


def test_dynamic_paths_and_prefixes_are_unresolved_without_fabricated_routes(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\nconst router = express.Router();\n'
        'app.use(prefix, router);\nrouter.get(path, handler);\n',
    )

    assert artifact.facts == ()
    assert [item.reason for item in artifact.unresolved] == [
        "computed or unsupported mount prefix",
        "computed or unsupported route path",
    ]
    artifact_graph(artifact).validate()


def test_comments_strings_and_unknown_receivers_do_not_create_evidence(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst text = "app.get(\\"/fake\\", handler)";\n'
        '// app.get("/comment", handler);\nunknown.get("/unknown", handler);\n',
    )

    assert artifact.facts == ()
    assert artifact.relations == ()


def test_app_get_setting_accessor_is_not_an_endpoint(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'if (app.get("env") === "test") process.exit(0);\n',
    )

    assert artifact.facts == ()
    assert artifact.unresolved == ()


def test_use_handlers_are_all_method_endpoints_not_mounts(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        'app.use("/api", handler);\napp.use((req, res) => res.send("ok"));\n',
    )

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("ALL", "/")]
    assert [item.reason for item in artifact.unresolved] == [
        "catch-all handler dispatch semantics are unresolved"
    ]


def test_constructed_default_import_owns_routes(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'import Express from "express";\nconst app = new Express();\n'
        'app.use("/api", (req, res) => res.send("ok"));\n',
    )

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("ALL", "/api")]


def test_duplicate_mount_is_unresolved_and_never_selects_a_prefix(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\nconst router = express.Router();\n'
        'app.use("/one", router);\napp.use("/two", router);\nrouter.get("/users", handler);\n',
    )

    assert artifact.facts[0].path == "/users"
    assert [item.reason for item in artifact.unresolved] == ["router has duplicate or ambiguous mount paths"]
    artifact_graph(artifact).validate()


def test_local_esm_module_mount_normalizes_route_with_cross_file_provenance(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    routes = tmp_path / "routes.js"
    app.write_text(
        'import express from "express";\nimport users from "./routes.js";\n'
        'const app = express();\napp.use("/api", users);\n',
        encoding="utf-8",
    )
    routes.write_text(
        'import express from "express";\nconst router = express.Router();\n'
        'router.get("/users", handler);\nexport default router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (app, routes)))

    assert artifact.facts[0].path == "/api/users"
    assert any("module-mount" in item.id for item in artifact.relations)
    artifact_graph(artifact).validate()


def test_nested_cjs_module_mounts_normalize_across_files(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    index = tmp_path / "index.js"
    users = tmp_path / "users.js"
    app.write_text(
        'const express = require("express");\nconst routes = require("./index");\n'
        'const app = express();\napp.use("/v1", routes);\n',
        encoding="utf-8",
    )
    index.write_text(
        'const express = require("express");\nconst users = require("./users");\n'
        'const router = express.Router();\nrouter.use("/users", users);\nmodule.exports = router;\n',
        encoding="utf-8",
    )
    users.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/profile", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (app, index, users)))

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/v1/users/profile")]
    artifact_graph(artifact).validate()


def test_extensionless_module_with_dotted_basename_resolves(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    users = tmp_path / "user.route.js"
    app.write_text(
        'const express = require("express");\nconst users = require("./user.route");\n'
        'const app = express();\napp.use("/users", users);\n',
        encoding="utf-8",
    )
    users.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/profile", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (app, users)))

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/users/profile")]
    artifact_graph(artifact).validate()


def test_static_array_mounts_normalize_nested_routers(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    index = tmp_path / "index.js"
    users = tmp_path / "users.js"
    index.write_text(
        'const express = require("express");\nconst users = require("./users");\n'
        'const router = express.Router();\n'
        'const routes = [{ path: "/users", route: users }];\n'
        'routes.forEach((route) => { router.use(route.path, route.route); });\n'
        'module.exports = router;\n',
        encoding="utf-8",
    )
    users.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/:id", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (index, users)))

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/users/:id")]
    artifact_graph(artifact).validate()


def test_exported_router_factory_inherits_caller_application_prefix(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    routes = tmp_path / "routes.js"
    users = tmp_path / "users.js"
    app.write_text(
        'const express = require("express");\nconst configure = require("./routes");\n'
        'const app = express();\nconfigure(app);\n',
        encoding="utf-8",
    )
    routes.write_text(
        'const express = require("express");\nconst users = require("./users");\n'
        'function configure(application) {\nconst router = express.Router();\n'
        'application.use("/api", router);\nrouter.use("/users", users);\n}\n'
        'module.exports = configure;\n',
        encoding="utf-8",
    )
    users.write_text(
        'const express = require("express");\nconst router = express.Router();\n'
        'router.get("/:id", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (app, routes, users)))

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/api/users/:id")]
    artifact_graph(artifact).validate()


def test_direct_cjs_router_and_literal_require_mounts_are_resolved(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    app = tmp_path / "app.js"
    index = tmp_path / "routes" / "index.js"
    users = tmp_path / "routes" / "users.js"
    index.parent.mkdir()
    app.write_text(
        'const express = require("express");\nconst app = express();\n'
        'app.use(require("./routes"));\n',
        encoding="utf-8",
    )
    index.write_text(
        'const router = require("express").Router();\n'
        'router.use("/api", require("./users"));\nmodule.exports = router;\n',
        encoding="utf-8",
    )
    users.write_text(
        'const router = require("express").Router();\n'
        'router.get("/users/:id", handler);\nmodule.exports = router;\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (app, index, users)))

    assert [(fact.method, fact.path, fact.span.path, fact.span.start_line) for fact in artifact.facts] == [
        ("GET", "/api/users/:id", "routes/users.js", 2)
    ]
    artifact_graph(artifact).validate()


def test_new_package_proven_express_router_is_resolved(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    source = tmp_path / "routes.js"
    source.write_text(
        'import express from "express";\nconst router = new express.Router();\n'
        'router.get("/users", handler);\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (source,)))

    assert [(fact.method, fact.path) for fact in artifact.facts] == [("GET", "/users")]
    artifact_graph(artifact).validate()


def test_direct_router_and_literal_mount_require_package_and_local_provenance(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    source = tmp_path / "routes.js"
    source.write_text(
        'const framework = require("not-express");\n'
        'const router = framework.Router();\nrouter.get("/fake", handler);\n'
        'const express = require("express");\nconst app = express();\n'
        'app.use(prefix, require(moduleName));\n',
        encoding="utf-8",
    )

    artifact = ExpressAdapter().analyze(AdapterInput(tmp_path, (source,)))

    assert artifact.facts == ()
    assert not any(subject.name == "router" for subject in artifact.subjects)
    artifact_graph(artifact).validate()


def artifact_graph(artifact):
    from authmapper.core.v2 import EvidenceGraph

    return EvidenceGraph(
        subjects=artifact.subjects,
        facts=artifact.facts,
        scopes=artifact.scopes,
        relations=artifact.relations,
        unresolved=artifact.unresolved,
        diagnostics=artifact.diagnostics,
    )
