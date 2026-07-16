"""M5-D legacy pack capability claims and conservative behavior evidence."""

from __future__ import annotations

from pathlib import Path

from authmapper.core.engine import Engine
from authmapper.core.model import AuthState
from authmapper.core.rulepack import load_rulepacks

EXPECTED_PACKS = {
    "csharp-aspnet",
    "go-nethttp",
    "java-spring",
    "node-express",
    "php-native",
    "python-django",
    "python-flask",
    "ruby-rails",
}


def test_inventory_documents_every_bundled_pack_and_experimental_ast():
    inventory = (Path(__file__).parents[1] / "docs/reference/legacy-capabilities.md").read_text(
        encoding="utf-8"
    )

    assert {pack.name for pack in load_rulepacks()} == EXPECTED_PACKS
    for name in (*sorted(EXPECTED_PACKS), "experimental-ast"):
        assert f"`{name}`" in inventory
    assert "No entry below is `Verified`" in inventory
    assert "unverified legacy states" in inventory


def test_bundled_ast_path_remains_empty_and_advisory():
    packs = load_rulepacks()

    assert all(pack.ast_language is None for pack in packs)
    assert all(pack.ast_endpoints == () for pack in packs)
    assert all(pack.ast_auth_signals == () for pack in packs)


def test_spring_principal_injection_never_produces_protected(tmp_path: Path):
    source = tmp_path / "Controller.java"
    source.write_text(
        '@GetMapping("/profile") public User profile(@AuthenticationPrincipal User user) { return user; }\n',
        encoding="utf-8",
    )

    result = Engine(load_rulepacks()).scan(tmp_path)

    finding = next(item for item in result.findings if item.endpoint.framework == "spring")
    assert finding.auth_state is AuthState.UNKNOWN


def test_every_bundled_pack_has_discovery_and_conservative_unassociated_auth_fixture(tmp_path: Path):
    fixtures = {
        "php-native": ("index.php", "<?php session_start(); ?>\n"),
        "node-express": ("app.js", 'requireAuth();\napp.get("/x", handler);\n'),
        "python-flask": ("app.py", '@app.route("/x")\ndef x(): return 1\nlogin_required = True\n'),
        "python-django": ("urls.py", 'path("x", view)\npermission_classes = [IsAuthenticated]\n'),
        "java-spring": ("Controller.java", '@GetMapping("/x")\n@PreAuthorize("ok")\n'),
        "go-nethttp": ("main.go", 'http.HandleFunc("/x", handler)\nrouter.Use(RequireAuth)\n'),
        "ruby-rails": ("routes.rb", 'get "/x"\nbefore_action :authenticate_user!\n'),
        "csharp-aspnet": ("Api.cs", '[HttpGet("/x")]\n[Authorize]\n'),
    }

    for pack_name, (filename, content) in fixtures.items():
        package = tmp_path / pack_name
        package.mkdir()
        (package / filename).write_text(content, encoding="utf-8")

    result = Engine(load_rulepacks()).scan(tmp_path)

    frameworks = {item.endpoint.framework for item in result.findings}
    assert {
        "aspnet-core",
        "django",
        "express",
        "flask",
        "native",
        "net/http,chi,gin,mux",
        "rails,sinatra",
        "spring",
    } <= frameworks
    assert all(item.auth_state is not AuthState.PROTECTED for item in result.findings)


def test_legacy_public_override_and_coverage_are_shared_engine_behavior(tmp_path: Path):
    source = tmp_path / "app.js"
    source.write_text('app.get("/health", handler);\n', encoding="utf-8")

    result = Engine(load_rulepacks()).scan(tmp_path)

    assert result.findings
    assert result.coverage
    assert all(item.auth_state is not AuthState.PUBLIC for item in result.findings)


def test_public_docs_separate_legacy_and_verified_gates():
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    ci_guide = (root / "docs/how-to/gate-ci.md").read_text(encoding="utf-8")

    assert "Legacy compatibility gate over unverified regex findings" in readme
    assert "Verified Express evidence gate" in readme
    assert "unverified\nlegacy regex states" in ci_guide
    assert "--evidence-scan express --evidence-policy" in ci_guide
