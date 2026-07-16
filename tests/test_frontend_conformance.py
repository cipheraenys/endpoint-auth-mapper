"""M5-C applicability and declaration ownership collision conformance."""

from __future__ import annotations

import json
from itertools import permutations
from pathlib import Path

import pytest

from authmapper.adapters import ExpressAdapter
from authmapper.core.v2 import (
    ActivationEvidence,
    AdapterInput,
    ApplicabilityResult,
    ApplicabilityState,
    OwnershipState,
    SourceSpan,
)
from authmapper.frontends.conformance import ClaimRole, OwnershipClaim, resolve_ownership
from authmapper.frontends.javascript import JavaScriptFrontend
from authmapper.frontends.rust import RustFrontend


def _applicability(
    adapter_id: str,
    state: ApplicabilityState = ApplicabilityState.ACTIVE,
    *,
    evidence: tuple[tuple[str, str, str], ...] = (),
) -> ApplicabilityResult:
    if not evidence and state is not ApplicabilityState.INACTIVE:
        evidence = (("fixture_provenance", adapter_id, "fixture/source"),)
    activation = tuple(
        ActivationEvidence(
            f"evidence:{adapter_id}:{index}:{kind}",
            kind,
            value,
            SourceSpan(path, 1, 1, 1, 2),
        )
        for index, (kind, value, path) in enumerate(evidence)
    )
    return ApplicabilityResult(adapter_id, state, activation, (f"{state.value} fixture",))


def _js_applicability(root: Path, source: Path, adapter_id: str, dependency: str) -> ApplicabilityResult:
    frontend = JavaScriptFrontend()
    parsed = frontend.parse(AdapterInput(root, (source,)))
    item = parsed.sources[0]
    package_dependencies = item.package_data.get("dependencies", {}) if item.package_data else {}
    imports = frontend.imports(item, root)
    matching = tuple(binding for binding in imports if binding.module_name == dependency)
    active = dependency in package_dependencies and bool(matching)
    evidence = tuple(
        ActivationEvidence(
            f"evidence:{adapter_id}:{index}",
            "import_binding",
            binding.local_name,
            binding.span,
        )
        for index, binding in enumerate(matching)
    )
    if dependency in package_dependencies:
        assert item.package_path is not None
        evidence = (
            *evidence,
            ActivationEvidence(
                f"evidence:{adapter_id}:package",
                "package_dependency",
                dependency,
                SourceSpan(item.package_path.relative_to(root).as_posix(), 1, 1, 1, 2),
            ),
        )
    return ApplicabilityResult(
        adapter_id,
        ApplicabilityState.ACTIVE if active else ApplicabilityState.INACTIVE,
        evidence,
        ("resolved package and import provenance" if active else "missing package or import provenance",),
    )


@pytest.mark.parametrize(
    ("adapter_id", "dependency", "source_text"),
    (
        ("hono", "hono", 'import { Hono } from "hono";\nnew Hono().get("/x", handler);\n'),
        ("fastify", "fastify", 'import fastify from "fastify";\nfastify().get("/x", handler);\n'),
        ("koa", "koa-router", 'import Router from "koa-router";\nnew Router().get("/x", handler);\n'),
        ("oak", "@oak/oak", 'import { Router } from "@oak/oak";\nnew Router().get("/x", handler);\n'),
    ),
)
def test_real_javascript_import_and_nearest_package_provenance_selects_candidate(
    tmp_path: Path,
    adapter_id: str,
    dependency: str,
    source_text: str,
):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {dependency: "1.0.0"}}), encoding="utf-8"
    )
    source = tmp_path / "app.js"
    source.write_text(source_text, encoding="utf-8")
    applicability = _js_applicability(tmp_path, source, adapter_id, dependency)

    decisions = resolve_ownership(
        (_claim("source:app.js:2", "js-call-router", applicability),)
    )

    assert applicability.state is ApplicabilityState.ACTIVE
    assert decisions[0].state is OwnershipState.SELECTED


@pytest.mark.parametrize(
    ("adapter_id", "dependency", "source_text"),
    (
        ("axum", "axum", "use axum::Router;\nfn build() { Router::new(); }\n"),
        ("actix", "actix-web", "use actix_web::get;\n#[get(\"/x\")] fn handler() {}\n"),
        ("rocket", "rocket", "use rocket::get;\n#[get(\"/x\")] fn handler() {}\n"),
    ),
)
def test_real_cargo_alias_and_use_provenance_selects_candidate(
    tmp_path: Path,
    adapter_id: str,
    dependency: str,
    source_text: str,
):
    (tmp_path / "Cargo.toml").write_text(
        f'[package]\nname = "service"\nversion = "0.1.0"\n'
        f'[dependencies]\nweb = {{ package = "{dependency}", version = "1" }}\n',
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    source = source_dir / "lib.rs"
    source.write_text(source_text.replace(f"use {dependency.replace('-', '_')}", "use web"), encoding="utf-8")
    applicability = _rust_applicability(tmp_path, source, adapter_id, dependency)

    decisions = resolve_ownership(
        (_claim("source:src/lib.rs:2", "rust-declaration", applicability),)
    )

    assert applicability.state is ApplicabilityState.ACTIVE
    assert decisions[0].state is OwnershipState.SELECTED


def test_real_express_receiver_shape_without_import_never_activates(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    source = tmp_path / "app.js"
    source.write_text('app.get("/x", handler);\n', encoding="utf-8")

    applicability = ExpressAdapter().applicability(AdapterInput(tmp_path, (source,)))

    assert applicability.state is ApplicabilityState.INACTIVE


def test_real_monorepo_sibling_dependency_does_not_activate_express(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "4.21.0"}}), encoding="utf-8"
    )
    sibling = tmp_path / "packages" / "service"
    sibling.mkdir(parents=True)
    (sibling / "package.json").write_text(
        json.dumps({"dependencies": {"hono": "4.0.0"}}), encoding="utf-8"
    )
    source = sibling / "app.js"
    source.write_text('import express from "express";\nexpress().get("/x", handler);\n', encoding="utf-8")

    applicability = ExpressAdapter().applicability(AdapterInput(tmp_path, (source,)))

    assert applicability.state is ApplicabilityState.INACTIVE


def _rust_applicability(root: Path, source: Path, adapter_id: str, dependency: str) -> ApplicabilityResult:
    analysis = RustFrontend().analyze(AdapterInput(root, (source,)))
    package = analysis.packages[0]
    matching_dependencies = tuple(item for item in package.dependencies if item.package_name == dependency)
    matching_uses = tuple(
        item
        for summary in analysis.summaries
        for item in summary.uses
        if item.origin == dependency
    )
    evidence = tuple(
        ActivationEvidence(
            f"evidence:{adapter_id}:dependency:{index}",
            "cargo_dependency",
            item.alias,
            item.span,
        )
        for index, item in enumerate(matching_dependencies)
    ) + tuple(
        ActivationEvidence(
            f"evidence:{adapter_id}:use:{index}",
            "use_binding",
            item.path,
            item.span,
        )
        for index, item in enumerate(matching_uses)
    )
    active = bool(matching_dependencies and matching_uses)
    return ApplicabilityResult(
        adapter_id,
        ApplicabilityState.ACTIVE if active else ApplicabilityState.INACTIVE,
        evidence,
        ("resolved Cargo and use provenance" if active else "missing Cargo or use provenance",),
    )


def _claim(
    subject: str,
    group: str,
    applicability: ApplicabilityResult,
    role: ClaimRole = ClaimRole.OWNER,
) -> OwnershipClaim:
    return OwnershipClaim(
        subject,
        group,
        applicability,
        tuple(item.id for item in applicability.evidence),
        role,
    )


@pytest.mark.parametrize(
    ("adapter_id", "shape", "dependency"),
    (
        ("express", 'app.get("/x", handler)', "express"),
        ("hono", 'app.get("/x", handler)', "hono"),
        ("fastify", 'app.get("/x", handler)', "fastify"),
        ("koa", 'router.get("/x", handler)', "koa-router"),
        ("oak", 'router.get("/x", handler)', "jsr:@oak/oak"),
        ("nest", '@Controller("x")', "@nestjs/common"),
        ("bun-native", 'Bun.serve({ fetch })', "bun-runtime"),
        ("deno-native", 'Deno.serve(handler)', "deno-runtime"),
    ),
)
def test_javascript_collision_shapes_select_only_resolved_provenance(
    adapter_id: str,
    shape: str,
    dependency: str,
):
    subject = f"source:src/app.js:1:{shape}"
    selected = _applicability(
        adapter_id,
        evidence=(("dependency", dependency, "package.json"), ("syntax", shape, "src/app.js")),
    )
    lookalike = _applicability("lookalike", ApplicabilityState.INACTIVE)

    decisions = resolve_ownership(
        (
            _claim(subject, "js-declaration", lookalike),
            _claim(subject, "js-declaration", selected),
        )
    )

    assert {item.adapter_id: item.state for item in decisions} == {
        adapter_id: OwnershipState.SELECTED,
        "lookalike": OwnershipState.REJECTED,
    }


@pytest.mark.parametrize(
    ("adapter_id", "shape", "dependency"),
    (
        ("axum", "Router::new().route(\"/x\", get(handler))", "axum"),
        ("actix", '#[get("/x")]', "actix-web"),
        ("rocket", '#[get("/x")]', "rocket"),
    ),
)
def test_rust_collision_shapes_select_only_crate_provenance(
    adapter_id: str,
    shape: str,
    dependency: str,
):
    subject = f"source:src/lib.rs:1:{shape}"
    selected = _applicability(
        adapter_id,
        evidence=(("cargo_dependency", dependency, "Cargo.toml"), ("use_binding", dependency, "src/lib.rs")),
    )

    decisions = resolve_ownership((_claim(subject, "rust-declaration", selected),))

    assert [(item.adapter_id, item.state) for item in decisions] == [
        (adapter_id, OwnershipState.SELECTED)
    ]


def test_receiver_name_without_dependency_or_import_is_inactive():
    receiver_only = _applicability("express", ApplicabilityState.INACTIVE)

    decisions = resolve_ownership(
        (_claim('source:app.js:app.get("/x")', "js-declaration", receiver_only),)
    )

    assert decisions[0].state is OwnershipState.REJECTED
    assert decisions[0].reason == "adapter applicability is inactive"


def test_missing_dependency_rejects_resolved_import_shape():
    missing = _applicability(
        "hono",
        ApplicabilityState.INACTIVE,
        evidence=(("import_binding", "Hono", "src/app.js"),),
    )

    decisions = resolve_ownership((_claim("source:src/app.js:1", "js-declaration", missing),))

    assert decisions[0].state is OwnershipState.REJECTED


def test_alias_and_reexport_evidence_can_select_one_owner():
    hono = _applicability(
        "hono",
        evidence=(
            ("package_dependency", "hono", "packages/api/package.json"),
            ("reexport_binding", "Web as Hono", "packages/api/src/web.js"),
            ("import_binding", "Hono", "packages/api/src/app.js"),
        ),
    )

    decisions = resolve_ownership(
        (_claim("source:packages/api/src/app.js:4", "js-call-router", hono),)
    )

    assert decisions[0].state is OwnershipState.SELECTED
    assert len(decisions[0].evidence_ids) == 3


def test_nearest_package_and_crate_keep_sibling_candidates_inactive():
    js_sibling = _applicability(
        "fastify",
        ApplicabilityState.INACTIVE,
        evidence=(("sibling_dependency", "fastify", "packages/other/package.json"),),
    )
    rust_sibling = _applicability(
        "axum",
        ApplicabilityState.INACTIVE,
        evidence=(("sibling_dependency", "axum", "crates/other/Cargo.toml"),),
    )

    decisions = resolve_ownership(
        (
            _claim("source:packages/api/src/app.js:1", "js-declaration", js_sibling),
            _claim("source:crates/api/src/lib.rs:1", "rust-declaration", rust_sibling),
        )
    )

    assert {item.state for item in decisions} == {OwnershipState.REJECTED}


def test_competing_active_candidates_are_explicitly_ambiguous_without_selection():
    first = _applicability("koa", evidence=(("dependency", "koa-router", "package.json"),))
    second = _applicability("oak", evidence=(("dependency", "jsr:@oak/oak", "deno.json"),))
    subject = "source:src/routes.ts:8"

    decisions = resolve_ownership(
        (
            _claim(subject, "js-call-router", first),
            _claim(subject, "js-call-router", second),
        )
    )

    assert {item.state for item in decisions} == {OwnershipState.AMBIGUOUS}
    assert not any(item.state is OwnershipState.SELECTED for item in decisions)


def test_ambiguous_applicability_cannot_be_selected():
    ambiguous = _applicability(
        "nest",
        ApplicabilityState.AMBIGUOUS,
        evidence=(("decorator", "Controller", "src/controller.ts"),),
    )

    decisions = resolve_ownership(
        (_claim("source:src/controller.ts:1", "js-decorator-route", ambiguous),)
    )

    assert decisions[0].state is OwnershipState.AMBIGUOUS


def test_duplicate_claims_merge_evidence_without_duplicate_owners():
    first = _applicability("express", evidence=(("dependency", "express", "package.json"),))
    second = _applicability("express", evidence=(("import", "express", "src/app.js"),))
    subject = "source:src/app.js:3"

    decisions = resolve_ownership(
        (
            _claim(subject, "js-call-router", first),
            _claim(subject, "js-call-router", second),
        )
    )

    assert len(decisions) == 1
    assert decisions[0].state is OwnershipState.SELECTED
    assert len(decisions[0].evidence_ids) == 2


def test_duplicate_claims_with_conflicting_state_fail_closed():
    active = _applicability("express", ApplicabilityState.ACTIVE)
    inactive = _applicability("express", ApplicabilityState.INACTIVE)
    subject = "source:src/app.js:3"

    with pytest.raises(ValueError, match="disagree"):
        resolve_ownership(
            (
                _claim(subject, "js-call-router", active),
                _claim(subject, "js-call-router", inactive),
            )
        )


def test_runtime_metadata_does_not_duplicate_hono_framework_ownership():
    hono = _applicability(
        "hono",
        evidence=(("framework_import", "Hono", "src/app.js"),),
    )
    bun = _applicability("bun-runtime", evidence=(("runtime", "bun", "package.json"),))
    deno = _applicability("deno-runtime", evidence=(("runtime", "deno", "deno.json"),))
    workers = _applicability("workers-runtime", evidence=(("runtime", "workers", "wrangler.toml"),))
    subject = "source:src/app.js:5"

    decisions = resolve_ownership(
        (
            _claim(subject, "js-framework-route", hono),
            _claim(subject, "js-framework-route", bun, ClaimRole.METADATA),
            _claim(subject, "js-framework-route", deno, ClaimRole.METADATA),
            _claim(subject, "js-framework-route", workers, ClaimRole.METADATA),
        )
    )

    assert [item.adapter_id for item in decisions if item.state is OwnershipState.SELECTED] == ["hono"]
    assert all(
        item.state is OwnershipState.REJECTED
        for item in decisions
        if item.adapter_id.endswith("runtime")
    )


def test_native_bun_and_deno_markers_remain_distinct_declarations():
    bun = _applicability("bun-native", evidence=(("runtime_symbol", "Bun.serve", "src/bun.js"),))
    deno = _applicability("deno-native", evidence=(("runtime_symbol", "Deno.serve", "src/deno.ts"),))

    decisions = resolve_ownership(
        (
            _claim("source:src/bun.js:1", "native-runtime-declaration", bun),
            _claim("source:src/deno.ts:1", "native-runtime-declaration", deno),
        )
    )

    assert [(item.adapter_id, item.state) for item in decisions] == [
        ("bun-native", OwnershipState.SELECTED),
        ("deno-native", OwnershipState.SELECTED),
    ]


def test_output_is_stable_across_candidate_permutations():
    claims = (
        _claim("source:src/app.js:1", "js", _applicability("express")),
        _claim("source:src/other.js:1", "js", _applicability("hono")),
        _claim("source:src/lib.rs:1", "rust", _applicability("axum")),
    )

    expected = resolve_ownership(claims)

    assert all(resolve_ownership(tuple(order)) == expected for order in permutations(claims))


def test_path_separators_normalize_to_stable_declaration_identity():
    applicability = _applicability("express")

    windows = resolve_ownership(
        (_claim(r"source:src\routes\app.js:1", r"js\call-router", applicability),)
    )
    posix = resolve_ownership(
        (_claim("source:src/routes/app.js:1", "js/call-router", applicability),)
    )

    assert windows == posix


def test_claim_cannot_reference_unknown_activation_evidence():
    applicability = _applicability("express")
    claim = OwnershipClaim("source:app.js:1", "js", applicability, ("missing",))

    with pytest.raises(ValueError, match="unknown activation evidence"):
        resolve_ownership((claim,))


def test_active_owner_without_activation_evidence_fails_closed():
    applicability = ApplicabilityResult("express", ApplicabilityState.ACTIVE, (), ("invalid fixture",))

    with pytest.raises(ValueError, match="requires activation evidence"):
        resolve_ownership((_claim("source:app.js:1", "js", applicability),))


def test_same_adapter_cannot_claim_owner_and_metadata_roles():
    applicability = _applicability("hono")
    subject = "source:app.js:1"

    with pytest.raises(ValueError, match="disagree on role"):
        resolve_ownership(
            (
                _claim(subject, "js", applicability),
                _claim(subject, "js", applicability, ClaimRole.METADATA),
            )
        )
