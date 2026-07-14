"""Golden evidence tests for M1's non-public Express spike."""

from __future__ import annotations

from pathlib import Path

from authmapper.spike.express import extract_express_spike


def _artifact(fixtures_dir: Path, name: str):
    root = fixtures_dir / "express_spike"
    return extract_express_spike(root / name, root=root)


def _observation(artifact, identifier: str):
    return next(observation for observation in artifact.observations if observation.id == identifier)


def test_scoped_middleware_associates_only_its_router(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "scoped_middleware.js")

    associations = [(edge.endpoint_id, edge.evidence_id, edge.scope_id, edge.reason) for edge in artifact.associations]
    assert associations == [
        (
            "endpoint:6",
            "middleware:5",
            "scope:router:protectedRouter",
            "router middleware registered before route (1 < 2)",
        )
    ]
    assert _observation(artifact, "endpoint:6").attribute("path") == "/account"
    assert _observation(artifact, "endpoint:7").attribute("path") == "/status"
    assert _observation(artifact, "endpoint:6").attribute("order") == "2"
    assert _observation(artifact, "endpoint:7").attribute("order") == "3"


def test_nested_mount_retains_edges_and_normalized_route_span(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "nested_mount.js")

    endpoint = _observation(artifact, "endpoint:7")
    assert endpoint.attribute("path") == "/api/v1/users"
    assert (endpoint.span.start_line, endpoint.span.start_column, endpoint.span.end_column) == (7, 1, 30)
    app_scope = next(scope for scope in artifact.scopes if scope.id == "scope:application:app")
    assert (app_scope.span.start_line, app_scope.span.start_column, app_scope.span.end_column) == (2, 1, 23)
    mounts = [
        (edge.id, edge.from_id, edge.to_id, edge.attribute("path"), edge.attribute("order"))
        for edge in artifact.composition_edges
        if edge.kind == "mount"
    ]
    assert mounts == [
        ("edge:mount:5", "scope:application:app", "scope:router:parent", "/api", "1"),
        ("edge:mount:6", "scope:router:parent", "scope:router:child", "/v1", "2"),
    ]
    mount_spans = [edge.span for edge in artifact.composition_edges if edge.kind == "mount"]
    assert [(span.start_line, span.start_column, span.end_column) for span in mount_spans] == [(5, 1, 25), (6, 1, 26)]
    handler_edges = [
        (edge.from_id, edge.to_id, edge.span.start_line)
        for edge in artifact.composition_edges
        if edge.kind == "handler_reference"
    ]
    assert handler_edges == [("scope:route:7", "scope:handler:7", 7)]


def test_inline_public_and_source_spans_are_observed_without_verdicts(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "inline_and_public.js")

    assert [(edge.endpoint_id, edge.evidence_id, edge.reason) for edge in artifact.associations] == [
        ("endpoint:3", "inline:3:requireAuth", "inline route middleware at registration order 1"),
        ("endpoint:3", "inline:3:audit", "inline route middleware at registration order 1"),
    ]
    require_auth = _observation(artifact, "inline:3:requireAuth")
    audit = _observation(artifact, "inline:3:audit")
    assert (require_auth.span.start_column, require_auth.span.end_column) == (21, 32)
    assert (audit.span.start_column, audit.span.end_column) == (34, 39)
    public = _observation(artifact, "public:4")
    assert public.kind == "public_override"
    assert public.span.start_line == 4
    assert public.attribute("path") == "/health"
    assert not hasattr(artifact, "verdict")
    assert not hasattr(artifact, "confidence")
    assert not hasattr(artifact, "severity")


def test_unrelated_middleware_has_no_positive_association(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "unrelated_middleware.js")

    assert artifact.associations == ()
    assert _observation(artifact, "middleware:5").attribute("name") == "requireAuth"


def test_dynamic_registration_is_explicitly_unresolved(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "dynamic_route.js")

    unresolved = [
        (observation.subject_id, observation.reason, observation.span.start_line) for observation in artifact.unresolved
    ]
    assert unresolved == [
        ("dynamic_route:3", "dynamic or unsupported registration form", 3),
        ("dynamic_route:4", "dynamic or unsupported registration form", 4),
    ]
    assert [(observation.span.start_column, observation.span.end_column) for observation in artifact.unresolved] == [
        (1, 29),
        (1, 24),
    ]
    assert [observation.kind for observation in artifact.observations] == ["dynamic_route", "dynamic_route"]


def test_registration_order_records_before_and_after_associations(fixtures_dir: Path):
    artifact = _artifact(fixtures_dir, "registration_order.js")

    assert [(edge.endpoint_id, edge.evidence_id, edge.reason) for edge in artifact.associations] == [
        ("endpoint:6", "middleware:5", "router middleware registered before route (2 < 3)")
    ]
    assert _observation(artifact, "endpoint:4").attribute("order") == "1"
    assert _observation(artifact, "middleware:5").attribute("order") == "2"
    assert _observation(artifact, "endpoint:6").attribute("order") == "3"


def test_comments_strings_unknown_and_duplicate_receivers_do_not_fabricate_facts(tmp_path: Path):
    source = tmp_path / "negative.js"
    source.write_text(
        '// app.get("/comment", requireAuth, handler)\n'
        'const text = "router.get(\\"/string\\", handler)";\n'
        'duplicate.get("/unknown", handler);\n',
        encoding="utf-8",
    )

    artifact = extract_express_spike(source)

    assert artifact.observations == ()
    assert [(item.subject_id, item.reason, item.span.start_line) for item in artifact.unresolved] == [
        (None, "route receiver is not a known literal router", 3)
    ]

    duplicate = tmp_path / "duplicate.js"
    duplicate.write_text(
        'const router = express.Router();\n'
        'const router = express.Router();\n'
        'router.get("/ambiguous", handler);\n',
        encoding="utf-8",
    )

    artifact = extract_express_spike(duplicate)

    assert [observation.kind for observation in artifact.observations] == ["router"]
    assert [(item.reason, item.span.start_line) for item in artifact.unresolved] == [
        ("duplicate router receiver declaration", 2),
        ("route receiver has a duplicate declaration", 3),
    ]


def test_literal_path_with_double_slash_is_not_treated_as_a_comment(tmp_path: Path):
    source = tmp_path / "path.js"
    source.write_text('app.get("/redirect//target", handler); // literal route\n', encoding="utf-8")

    artifact = extract_express_spike(source)

    endpoint = _observation(artifact, "endpoint:1")
    assert endpoint.attribute("path") == "/redirect//target"
