"""M3-E reproducible metrics for audited independent-repository snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from authmapper.app.evidence_runner import run_express_evidence_scan
from authmapper.core.v2 import Capability, CoverageStatus, EndpointVerdict


@dataclass(frozen=True, slots=True)
class Label:
    repository: str
    method: str
    path: str
    expected: EndpointVerdict
    source_path: str
    source_line: int


LABELS = (
    Label("hackathon-starter", "GET", "/", EndpointVerdict.UNGUARDED, "app.js", 6),
    Label("hackathon-starter", "GET", "/account", EndpointVerdict.UNRESOLVED, "app.js", 7),
    Label("hackathon-starter", "GET", "/auth/github", EndpointVerdict.UNGUARDED, "app.js", 8),
    Label(
        "express-rest-boilerplate", "GET", "/v1/status", EndpointVerdict.UNGUARDED,
        "src/api/routes/v1/index.js", 6,
    ),
    Label(
        "express-rest-boilerplate", "GET", "/v1/users/profile", EndpointVerdict.UNRESOLVED,
        "src/api/routes/v1/user.route.js", 5,
    ),
    Label(
        "express-rest-boilerplate", "POST", "/v1/auth/login", EndpointVerdict.UNGUARDED,
        "src/api/routes/v1/auth.route.js", 5,
    ),
    Label("passport-jwt-api", "POST", "/signup", EndpointVerdict.UNGUARDED, "routes/api.js", 5),
    Label("passport-jwt-api", "GET", "/signout", EndpointVerdict.GUARDED, "routes/api.js", 6),
    Label("passport-jwt-api", "POST", "/book", EndpointVerdict.GUARDED, "routes/api.js", 7),
    Label("passport-jwt-api", "GET", "/book", EndpointVerdict.GUARDED, "routes/api.js", 8),
)


def test_audited_snapshot_metrics(fixtures_dir: Path):
    results = {
        repository: run_express_evidence_scan(
            fixtures_dir / "express_evaluation" / repository,
            ("authmap", "--evidence-scan", "express"),
        )
        for repository in {label.repository for label in LABELS}
    }
    observed = []
    for label in LABELS:
        result = results[label.repository]
        matches = [
            resolution
            for resolution in result.report.resolutions
            if _resolution_matches(result, resolution.endpoint_id, label)
        ]
        assert len(matches) == 1, label
        observed.append((label, matches[0].verdict))

    # Every endpoint in the snapshots has one audited source label: exact discovery
    # precision and recall can be measured, not inferred from a subset.
    assert sum(len(result.report.resolutions) for result in results.values()) == len(LABELS)
    assert all(verdict is label.expected for label, verdict in observed)

    guarded = [(label, verdict) for label, verdict in observed if label.expected is EndpointVerdict.GUARDED]
    assert len(guarded) == 3
    assert all(verdict is EndpointVerdict.GUARDED for _, verdict in guarded)
    assert not any(
        verdict is EndpointVerdict.GUARDED and label.expected is not EndpointVerdict.GUARDED
        for label, verdict in observed
    )

    for result in results.values():
        endpoint_ids = {resolution.endpoint_id for resolution in result.report.resolutions}
        coverage = [record for record in result.report.graph.coverage if record.target_id in endpoint_ids]
        assert len(coverage) == len(endpoint_ids) * 4
        assert {record.capability for record in coverage} == {
            Capability.AUTH_ASSOCIATION,
            Capability.ENDPOINT_DISCOVERY,
            Capability.ROUTE_COMPOSITION,
            Capability.SCOPE_RESOLUTION,
        }
        assert all(record.status is CoverageStatus.ANALYZED for record in coverage)


def _resolution_matches(result, endpoint_id: str, label: Label) -> bool:
    fact = next(fact for fact in result.report.graph.facts if fact.id == endpoint_id)
    return (
        fact.method == label.method
        and fact.path == label.path
        and fact.span.path == label.source_path
        and fact.span.start_line == label.source_line
    )
