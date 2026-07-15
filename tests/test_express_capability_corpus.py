"""Fixed M3-E capability corpus, separate from extractor unit fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmapper.adapters import ExpressAdapter, build_express_graph
from authmapper.core.v2 import AdapterInput, EndpointVerdict, resolve_endpoints

DISCOVERY_CASES = tuple(
    (method, f"/{method}")
    for method in ("get", "post", "put", "delete", "patch", "options", "head", "all")
) + tuple(("get", f"/literal-{index}") for index in range(12))

AUTH_CASES = (
    *(("passport.authenticate(\"jwt\")", EndpointVerdict.GUARDED) for _ in range(10)),
    *(
        (name, EndpointVerdict.UNRESOLVED)
        for name in ("requireAuth", "tokenGuard", "sessionAuth", "loginRequired")
        for _ in range(2)
    ),
    *((name, EndpointVerdict.UNGUARDED) for name in ("audit", "cors")),
)

COMPOSITION_CASES = tuple((f"/api-{index}", f"/route-{index}") for index in range(20))
PUBLIC_CASES = tuple(f"/public-{index}" for index in range(20))


def _artifact(tmp_path: Path, source: str):
    tmp_path.joinpath("package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0", "passport": "0.7.0"}}), encoding="utf-8"
    )
    path = tmp_path / "app.js"
    path.write_text(source, encoding="utf-8")
    adapter = ExpressAdapter()
    return adapter, adapter.analyze(AdapterInput(tmp_path, (path,)))


@pytest.mark.parametrize(("method", "path"), DISCOVERY_CASES)
def test_discovery_corpus(tmp_path: Path, method: str, path: str):
    adapter, artifact = _artifact(
        tmp_path,
        f'const express = require("express");\nconst app = express();\napp.{method}("{path}", handler);\n',
    )

    assert [(fact.method, fact.path) for fact in artifact.facts] == [(method.upper(), path)]
    resolution = resolve_endpoints(build_express_graph(artifact, adapter_version=adapter.version))[0]
    assert resolution.verdict is EndpointVerdict.UNGUARDED


@pytest.mark.parametrize(("middleware", "verdict"), AUTH_CASES)
def test_auth_corpus(tmp_path: Path, middleware: str, verdict: EndpointVerdict):
    adapter, artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst passport = require("passport");\nconst app = express();\n'
        f'app.get("/case", {middleware}, handler);\n',
    )

    resolution = resolve_endpoints(build_express_graph(artifact, adapter_version=adapter.version))[0]
    assert resolution.verdict is verdict


@pytest.mark.parametrize(("prefix", "route"), COMPOSITION_CASES)
def test_composition_corpus(tmp_path: Path, prefix: str, route: str):
    adapter, artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\nconst router = express.Router();\n'
        f'app.use("{prefix}", router);\nrouter.get("{route}", handler);\n',
    )

    assert artifact.facts[0].path == f"{prefix}{route}"
    resolution = resolve_endpoints(build_express_graph(artifact, adapter_version=adapter.version))[0]
    assert resolution.verdict is EndpointVerdict.UNGUARDED


@pytest.mark.parametrize("path", PUBLIC_CASES)
def test_public_declaration_corpus(tmp_path: Path, path: str):
    adapter, artifact = _artifact(
        tmp_path,
        'const express = require("express");\nconst app = express();\n'
        '// authmap-public-v1 policy=service-access owner=platform reason=healthcheck\n'
        f'app.get("{path}", handler);\n',
    )

    resolution = resolve_endpoints(build_express_graph(artifact, adapter_version=adapter.version))[0]
    assert resolution.verdict is EndpointVerdict.DECLARED_PUBLIC
