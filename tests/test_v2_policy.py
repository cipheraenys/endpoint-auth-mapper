"""M4-A versioned evidence policy and deterministic gate tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from authmapper.app.evidence_runner import run_express_evidence_scan
from authmapper.core.v2 import (
    ApplicabilityState,
    Capability,
    CapabilityMaturity,
    CapabilityProvenance,
    CapabilityRequirement,
    CoverageRecord,
    CoverageStatus,
    Diagnostic,
    DiagnosticLevel,
    EndpointVerdict,
    EvidenceAssociation,
    EvidenceGraph,
    EvidencePolicyError,
    EvidenceReport,
    Fact,
    FactKind,
    GateDisposition,
    GateIssueKind,
    InvocationProvenance,
    Proof,
    ProofKind,
    Relation,
    RelationKind,
    ReportedCapability,
    Scope,
    ScopeKind,
    SourceSpan,
    Subject,
    SubjectKind,
    UnresolvedRecord,
    evaluate_evidence_policy,
    parse_evidence_policy,
    resolve_endpoints,
)

SCHEMA_ID = "https://authmap.dev/schemas/evidence-policy-1.0.json"
SPAN = SourceSpan("app.js", 1, 1, 1, 24)
REQUIRED_CAPABILITIES = (
    Capability.AUTH_ASSOCIATION,
    Capability.ENDPOINT_DISCOVERY,
    Capability.ROUTE_COMPOSITION,
    Capability.SCOPE_RESOLUTION,
)


def _policy_document(**updates: object) -> dict:
    document = {
        "$schema": SCHEMA_ID,
        "schema_version": "1.0",
        "id": "default.assurance",
        "fail_on_unguarded": True,
        "fail_on_unresolved": False,
        "fail_on_incomplete_coverage": True,
        "requirements": [
            {
                "id": f"express.{capability.value}",
                "adapter_id": "express",
                "adapter_version": "0.1.0",
                "capability": capability.value,
                "minimum_maturity": "verified",
            }
            for capability in REQUIRED_CAPABILITIES
        ],
    }
    document.update(updates)
    return document


def _report(
    verdict: EndpointVerdict,
    *,
    coverage_status: CoverageStatus = CoverageStatus.ANALYZED,
    adapter_version: str = "0.1.0",
) -> EvidenceReport:
    endpoint = Fact("fact:route", FactKind.ENDPOINT_DECLARATION, "subject:route", SPAN, method="GET", path="/me")
    facts = [endpoint]
    associations = []
    proofs = []
    relations = []
    unresolved = []
    scope = Scope("scope:route", ScopeKind.ROUTE, "subject:route", SPAN)
    if verdict is EndpointVerdict.GUARDED:
        auth = Fact("fact:auth", FactKind.AUTH_ENFORCEMENT, "subject:route", SPAN)
        relation = Relation(
            "relation:auth",
            RelationKind.REFERENCES,
            scope.id,
            auth.subject_id,
            SPAN,
        )
        association = EvidenceAssociation(
            "association:auth",
            endpoint.id,
            auth.id,
            scope.id,
            SPAN,
            tuple(sorted((auth.id, endpoint.id, relation.id))),
        )
        proof = Proof(
            "proof:auth",
            ProofKind.AUTH_ENFORCEMENT,
            endpoint.id,
            (auth.id,),
            (association.id,),
            (relation.id,),
            tuple(
                sorted(
                    (
                        association.id,
                        auth.id,
                        endpoint.id,
                        "provenance:express:auth_association",
                        relation.id,
                    )
                )
            ),
        )
        facts.append(auth)
        relations.append(relation)
        associations.append(association)
        proofs.append(proof)
    elif verdict is EndpointVerdict.DECLARED_PUBLIC:
        public = Fact("fact:public", FactKind.PUBLIC_DECLARATION, "subject:route", SPAN)
        relation = Relation(
            "relation:public",
            RelationKind.REFERENCES,
            scope.id,
            public.subject_id,
            SPAN,
        )
        association = EvidenceAssociation(
            "association:public",
            endpoint.id,
            public.id,
            scope.id,
            SPAN,
            tuple(sorted((endpoint.id, public.id, relation.id))),
        )
        proof = Proof(
            "proof:public",
            ProofKind.PUBLIC_POLICY,
            endpoint.id,
            (public.id,),
            (association.id,),
            (relation.id,),
            tuple(sorted((association.id, endpoint.id, public.id, relation.id))),
        )
        facts.append(public)
        relations.append(relation)
        associations.append(association)
        proofs.append(proof)
    elif verdict is EndpointVerdict.UNRESOLVED and coverage_status is CoverageStatus.ANALYZED:
        unresolved.append(UnresolvedRecord("unresolved:route", "dynamic scope", endpoint.id, SPAN, (endpoint.id,)))
    provenance = tuple(
        CapabilityProvenance(
            f"provenance:express:{capability.value}", capability, "express", adapter_version, ()
        )
        for capability in REQUIRED_CAPABILITIES
    )
    coverage = tuple(
        CoverageRecord(
            f"coverage:{capability.value}",
            endpoint.id,
            capability,
            coverage_status if capability is Capability.AUTH_ASSOCIATION else CoverageStatus.ANALYZED,
            f"provenance:express:{capability.value}",
            None,
        )
        for capability in REQUIRED_CAPABILITIES
    )
    graph = EvidenceGraph(
        subjects=(Subject("subject:route", SubjectKind.ROUTE_CALL, SPAN),),
        facts=tuple(sorted(facts, key=lambda item: item.id)),
        scopes=(scope,),
        relations=tuple(relations),
        associations=tuple(associations),
        proofs=tuple(proofs),
        unresolved=tuple(unresolved),
        capability_provenance=provenance,
        coverage=coverage,
    )
    resolutions = resolve_endpoints(graph)
    assert resolutions[0].verdict is verdict
    return EvidenceReport(
        graph,
        resolutions,
        InvocationProvenance(("authmap",), ".", "0.1.2"),
        _capabilities(version=adapter_version),
    )


def _capabilities(
    *,
    maturity: CapabilityMaturity = CapabilityMaturity.VERIFIED,
    public_maturity: CapabilityMaturity = CapabilityMaturity.EXPERIMENTAL,
    state: ApplicabilityState = ApplicabilityState.ACTIVE,
    version: str = "0.1.0",
) -> tuple[ReportedCapability, ...]:
    return tuple(
        sorted(
            (
                *(
                    ReportedCapability("express", version, capability.value, maturity, state)
                    for capability in REQUIRED_CAPABILITIES
                ),
                ReportedCapability("express", version, "public_override", public_maturity, state),
            ),
            key=lambda item: (item.adapter_id, item.adapter_version, item.capability),
        )
    )


def test_policy_schema_is_strict_and_versioned():
    for field, value in (
        ("schema_version", "2.0"),
        ("fail_on_unresolved", "yes"),
    ):
        document = _policy_document()
        document[field] = value
        with pytest.raises(EvidencePolicyError, match="invalid evidence policy"):
            parse_evidence_policy(document)

    unknown = _policy_document(legacy_fail_on="EXPOSED")
    with pytest.raises(EvidencePolicyError, match="Additional properties"):
        parse_evidence_policy(unknown)

    enum = _policy_document()
    enum["requirements"][0]["minimum_maturity"] = "stable"
    with pytest.raises(EvidencePolicyError, match="not one of"):
        parse_evidence_policy(enum)


def test_policy_rejects_duplicate_rules_and_targets():
    duplicate_id = _policy_document()
    duplicate_id["requirements"].append({**duplicate_id["requirements"][0], "capability": "other"})
    with pytest.raises(EvidencePolicyError, match="requirement IDs"):
        parse_evidence_policy(duplicate_id)

    duplicate_target = _policy_document()
    duplicate_target["requirements"].append({**duplicate_target["requirements"][0], "id": "other.rule"})
    with pytest.raises(EvidencePolicyError, match="capability requirements"):
        parse_evidence_policy(duplicate_target)


def test_policy_values_are_immutable_and_deterministically_ordered():
    document = _policy_document(requirements=list(reversed(_policy_document()["requirements"])))
    policy = parse_evidence_policy(document)

    assert tuple(item.id for item in policy.requirements) == tuple(sorted(item.id for item in policy.requirements))
    with pytest.raises(FrozenInstanceError):
        policy.fail_on_unresolved = True  # type: ignore[misc]


def test_direct_domain_construction_cannot_bypass_policy_invariants():
    with pytest.raises(EvidencePolicyError, match="adapter version"):
        CapabilityRequirement(
            "express.auth_association",
            "express",
            "latest",
            "auth_association",
            CapabilityMaturity.VERIFIED,
        )
    with pytest.raises(EvidencePolicyError, match="unavailable"):
        CapabilityRequirement(
            "express.auth_association",
            "express",
            "0.1.0",
            "auth_association",
            CapabilityMaturity.UNAVAILABLE,
        )


def test_verified_unguarded_fails_and_unresolved_is_advisory_by_default():
    policy = parse_evidence_policy(_policy_document())

    unguarded = evaluate_evidence_policy(policy, _report(EndpointVerdict.UNGUARDED))
    unresolved = evaluate_evidence_policy(policy, _report(EndpointVerdict.UNRESOLVED))

    assert [(item.kind, item.disposition) for item in unguarded.violations] == [
        (GateIssueKind.UNGUARDED, GateDisposition.VIOLATION)
    ]
    assert not unresolved.violations
    assert [item.kind for item in unresolved.advisories] == [GateIssueKind.UNRESOLVED]


def test_strict_unresolved_and_assurance_coverage_are_independent_opt_ins():
    strict_unresolved = parse_evidence_policy(_policy_document(fail_on_unresolved=True))
    advisory_coverage = parse_evidence_policy(_policy_document(fail_on_incomplete_coverage=False))
    incomplete = _report(EndpointVerdict.UNRESOLVED, coverage_status=CoverageStatus.ERROR)

    unresolved_result = evaluate_evidence_policy(strict_unresolved, incomplete)
    coverage_result = evaluate_evidence_policy(advisory_coverage, incomplete)

    assert {item.kind for item in unresolved_result.violations} == {
        GateIssueKind.INCOMPLETE_COVERAGE,
        GateIssueKind.UNRESOLVED,
    }
    assert not coverage_result.violations
    assert {item.kind for item in coverage_result.advisories} == {
        GateIssueKind.INCOMPLETE_COVERAGE,
        GateIssueKind.UNRESOLVED,
    }


def test_experimental_result_is_advisory_when_policy_explicitly_accepts_it():
    document = _policy_document(
        requirements=[
            {
                "id": "express.auth_association",
                "adapter_id": "express",
                "adapter_version": "0.1.0",
                "capability": "auth_association",
                "minimum_maturity": "experimental",
            }
        ]
    )
    report = replace(
        _report(EndpointVerdict.UNGUARDED),
        capabilities=_capabilities(maturity=CapabilityMaturity.EXPERIMENTAL),
    )
    result = evaluate_evidence_policy(parse_evidence_policy(document), report)

    assert not result.violations
    assert [item.kind for item in result.advisories] == [GateIssueKind.UNGUARDED]


def test_experimental_public_override_is_visible_and_cannot_bypass_verified_gate():
    document = _policy_document()
    document["requirements"].append(
        {
            "id": "express.public_override",
            "adapter_id": "express",
            "adapter_version": "0.1.0",
            "capability": "public_override",
            "minimum_maturity": "experimental",
        }
    )

    result = evaluate_evidence_policy(
        parse_evidence_policy(document),
        _report(EndpointVerdict.DECLARED_PUBLIC),
    )

    assert [item.kind for item in result.violations] == [GateIssueKind.UNGUARDED]
    assert [item.kind for item in result.advisories] == [GateIssueKind.PUBLIC_DECLARATION]


def test_reported_verified_public_override_cannot_satisfy_gate_without_proof_provenance():
    report = replace(
        _report(EndpointVerdict.DECLARED_PUBLIC),
        capabilities=_capabilities(public_maturity=CapabilityMaturity.VERIFIED),
    )
    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert [item.kind for item in result.violations] == [GateIssueKind.UNGUARDED]
    assert [item.kind for item in result.advisories] == [GateIssueKind.PUBLIC_DECLARATION]


def test_forged_resolution_cannot_bypass_evidence_first_gate():
    report = _report(EndpointVerdict.UNGUARDED)
    forged = replace(
        report,
        resolutions=(replace(report.resolutions[0], verdict=EndpointVerdict.GUARDED),),
    )

    with pytest.raises(EvidencePolicyError, match="resolutions do not match"):
        evaluate_evidence_policy(parse_evidence_policy(_policy_document()), forged)


def test_analysis_error_diagnostic_fails_closed():
    report = _report(EndpointVerdict.GUARDED)
    diagnostic = Diagnostic(
        "diagnostic:analysis-error",
        "AM-PARSER-ERROR",
        "route module could not be analyzed",
        DiagnosticLevel.ERROR,
        SPAN,
    )
    graph = replace(report.graph, diagnostics=(diagnostic,))
    report = EvidenceReport(graph, resolve_endpoints(graph), report.invocation, report.capabilities)

    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert [item.kind for item in result.violations] == [GateIssueKind.ANALYSIS_ERROR]


def test_guard_proof_requires_selected_verified_auth_provenance():
    report = _report(EndpointVerdict.GUARDED)
    other_provenance = CapabilityProvenance(
        "provenance:zother:auth_association",
        Capability.AUTH_ASSOCIATION,
        "zother",
        "1.0.0",
        (),
    )
    proof = replace(
        report.graph.proofs[0],
        derived_from=tuple(
            "provenance:zother:auth_association"
            if item == "provenance:express:auth_association"
            else item
            for item in report.graph.proofs[0].derived_from
        ),
    )
    graph = replace(
        report.graph,
        proofs=(proof,),
        capability_provenance=(*report.graph.capability_provenance, other_provenance),
    )
    report = EvidenceReport(graph, resolve_endpoints(graph), report.invocation, report.capabilities)

    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert [item.kind for item in result.violations] == [GateIssueKind.CAPABILITY_REQUIREMENT]
    assert "proof lacks" in result.violations[0].reason


def test_unselected_adapter_maturity_cannot_dilute_verified_gate():
    report = _report(EndpointVerdict.UNGUARDED)
    other_provenance = CapabilityProvenance(
        "provenance:zother:auth_association",
        Capability.AUTH_ASSOCIATION,
        "zother",
        "1.0.0",
        (),
    )
    other_coverage = CoverageRecord(
        "coverage:zother:auth_association",
        report.resolutions[0].endpoint_id,
        Capability.AUTH_ASSOCIATION,
        CoverageStatus.ANALYZED,
        other_provenance.id,
        None,
    )
    graph = replace(
        report.graph,
        capability_provenance=(*report.graph.capability_provenance, other_provenance),
        coverage=(*report.graph.coverage, other_coverage),
    )
    capabilities = (
        *_capabilities(),
        ReportedCapability(
            "zother",
            "1.0.0",
            "auth_association",
            CapabilityMaturity.EXPERIMENTAL,
            ApplicabilityState.ACTIVE,
        ),
    )
    report = EvidenceReport(graph, resolve_endpoints(graph), report.invocation, capabilities)

    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert [item.kind for item in result.violations] == [GateIssueKind.UNGUARDED]


def test_discovery_only_policy_is_inventory_not_auth_gating():
    document = _policy_document(
        requirements=[
            {
                "id": "express.endpoint_discovery",
                "adapter_id": "express",
                "adapter_version": "0.1.0",
                "capability": "endpoint_discovery",
                "minimum_maturity": "verified",
            }
        ]
    )
    result = evaluate_evidence_policy(
        parse_evidence_policy(document),
        _report(EndpointVerdict.UNGUARDED),
    )

    assert not result.violations
    assert [item.kind for item in result.advisories] == [GateIssueKind.UNGUARDED]


def test_required_coverage_is_scoped_to_adapter_owned_endpoints():
    report = _report(EndpointVerdict.GUARDED)
    other_subject = Subject("subject:zother", SubjectKind.ROUTE_CALL, SPAN)
    other_endpoint = Fact(
        "fact:zother",
        FactKind.ENDPOINT_DECLARATION,
        other_subject.id,
        SPAN,
        method="GET",
        path="/other",
    )
    other_scope = Scope("scope:zother", ScopeKind.ROUTE, other_subject.id, SPAN)
    other_provenance = tuple(
        CapabilityProvenance(
            f"provenance:zother:{capability.value}",
            capability,
            "zother",
            "1.0.0",
            (),
        )
        for capability in REQUIRED_CAPABILITIES
    )
    other_coverage = tuple(
        CoverageRecord(
            f"coverage:zother:{capability.value}",
            other_endpoint.id,
            capability,
            CoverageStatus.ANALYZED,
            f"provenance:zother:{capability.value}",
        )
        for capability in REQUIRED_CAPABILITIES
    )
    graph = replace(
        report.graph,
        subjects=tuple(sorted((*report.graph.subjects, other_subject), key=lambda item: item.id)),
        facts=tuple(sorted((*report.graph.facts, other_endpoint), key=lambda item: item.id)),
        scopes=tuple(sorted((*report.graph.scopes, other_scope), key=lambda item: item.id)),
        capability_provenance=tuple(
            sorted((*report.graph.capability_provenance, *other_provenance), key=lambda item: item.id)
        ),
        coverage=tuple(sorted((*report.graph.coverage, *other_coverage), key=lambda item: item.id)),
    )
    report = EvidenceReport(graph, resolve_endpoints(graph), report.invocation, report.capabilities)

    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert not result.violations
    assert [item.subject_id for item in result.advisories] == [other_endpoint.id]


@pytest.mark.parametrize(
    ("capabilities", "report", "reason"),
    [
        ((), _report(EndpointVerdict.GUARDED), "missing"),
        (_capabilities(state=ApplicabilityState.INACTIVE), _report(EndpointVerdict.GUARDED), "inactive"),
        (
            _capabilities(maturity=CapabilityMaturity.EXPERIMENTAL),
            _report(EndpointVerdict.GUARDED),
            "below verified",
        ),
        (_capabilities(version="0.2.0"), _report(EndpointVerdict.GUARDED), "incompatible"),
        (_capabilities(), _report(EndpointVerdict.GUARDED, adapter_version="0.2.0"), "provenance"),
    ],
)
def test_missing_inactive_demoted_or_incompatible_requirement_fails_closed(
    capabilities: tuple[ReportedCapability, ...],
    report: EvidenceReport,
    reason: str,
):
    report = replace(report, capabilities=capabilities)
    result = evaluate_evidence_policy(parse_evidence_policy(_policy_document()), report)

    assert not result.passed
    assert result.violations[0].kind is GateIssueKind.CAPABILITY_REQUIREMENT
    assert reason in result.violations[0].reason


def test_policy_rejects_legacy_or_unversioned_input():
    with pytest.raises(EvidencePolicyError, match="v2 EvidenceReport"):
        evaluate_evidence_policy(
            parse_evidence_policy(_policy_document()),
            {"findings": []},  # type: ignore[arg-type]
        )


def test_gate_result_order_does_not_depend_on_policy_input_order():
    policy = parse_evidence_policy(_policy_document())
    reversed_document = _policy_document(requirements=list(reversed(_policy_document()["requirements"])))
    reversed_policy = parse_evidence_policy(reversed_document)

    assert evaluate_evidence_policy(
        reversed_policy, _report(EndpointVerdict.UNGUARDED)
    ) == evaluate_evidence_policy(policy, _report(EndpointVerdict.UNGUARDED))


def test_policy_evaluates_actual_express_v2_result(tmp_path: Path):
    tmp_path.joinpath("package.json").write_text(
        '{"dependencies":{"express":"4.21.0"}}', encoding="utf-8"
    )
    tmp_path.joinpath("app.js").write_text(
        'const express = require("express");\n'
        'const app = express();\n'
        'app.get("/admin", handler);\n',
        encoding="utf-8",
    )
    result = run_express_evidence_scan(tmp_path, ("authmap", "--evidence-scan", "express"))

    gate = evaluate_evidence_policy(
        parse_evidence_policy(_policy_document()),
        result.report,
    )

    assert [item.kind for item in gate.violations] == [GateIssueKind.UNGUARDED]
