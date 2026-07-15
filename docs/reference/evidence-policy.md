# Evidence Policy 1.0

Evidence policy `1.0` applies deterministic CI semantics only to evidence report
`2.0`. It is separate from legacy `.authmap.json`, `fail_on`, and baselines.
M4-A exposes domain and evaluation contracts only; CLI gate options arrive in a
later slice.

Normative schema:
`https://authmap.dev/schemas/evidence-policy-1.0.json`, bundled as
`authmapper/schemas/evidence-policy-1.0.schema.json`.

## Document

```json
{
  "$schema": "https://authmap.dev/schemas/evidence-policy-1.0.json",
  "schema_version": "1.0",
  "id": "default.assurance",
  "fail_on_unguarded": true,
  "fail_on_unresolved": false,
  "fail_on_incomplete_coverage": true,
  "requirements": [
    {
      "id": "express.auth_association",
      "adapter_id": "express",
      "adapter_version": "0.1.0",
      "capability": "auth_association",
      "minimum_maturity": "verified"
    }
  ]
}
```

Unknown fields, unknown enum values, incompatible schema versions, duplicate
requirement IDs, and duplicate adapter/version/capability targets are errors.
Requirements use exact adapter ID, adapter version, and capability identity.
Missing, inactive, demoted, incompatible, or unproven required capability input
fails closed.

Maturity and applicability come from immutable runner `EvidenceReport` input,
not adapter explanation or caller-supplied evaluator values. JSON exposure stays
deferred to M4-D so evidence report schema `2.0` remains unchanged. Auth posture blocks only when
all four verdict-critical capabilities (`endpoint_discovery`,
`route_composition`, `scope_resolution`, and `auth_association`) are selected as
Verified for same adapter/version. Discovery-only selection remains inventory.
Any analysis error diagnostic is a setup violation.

## Gate Semantics

| Evidence | Default result |
|---|---|
| Verified `UNGARDED` | Violation |
| Verified `UNRESOLVED` | Advisory; `fail_on_unresolved` can make it a violation |
| Incomplete required Verified coverage | Violation when `fail_on_incomplete_coverage` is true |
| Experimental or Unavailable result | Advisory unless it violates an explicit maturity requirement |
| Experimental public override | Visible advisory; cannot bypass a Verified unguarded gate |

`fail_on_unguarded`, `fail_on_unresolved`, and
`fail_on_incomplete_coverage` are independent. Coverage remains separate from
endpoint verdict. Gate evaluation does not alter report verdicts, evidence,
policy, or capability maturity.
