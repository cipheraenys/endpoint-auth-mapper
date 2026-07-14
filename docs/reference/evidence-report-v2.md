# Evidence Report V2

Evidence report `2.0` is an additive contract for provenance-rich v2 analysis.
It does not replace default legacy JSON `1.1` during M2, and no CLI schema
selector is exposed until a production adapter can produce v2 evidence.

Normative schema:
`https://authmap.dev/schemas/evidence-report-2.0.json`, bundled as
`authmapper/schemas/evidence-report-2.0.schema.json`.

The report contains:

- Fact graph `2.0`: subjects, facts, scopes, relations, associations, proofs,
  unresolved records, diagnostics, capability provenance, and coverage.
- Endpoint resolutions: `GUARDED`, `UNGARDED`, `DECLARED_PUBLIC`, or
  `UNRESOLVED`, linked to proof, unresolved, and coverage IDs.
- Invocation and tool provenance.
- Semantic endpoint and proof fingerprints with explicit algorithm names.

Contract versions are independent of package version:

| Contract | Version |
|---|---|
| Fact graph | `2.0` |
| Evidence JSON report | `2.0` |
| SARIF authmap mapping | `1.0` |
| Project config | `1.0` |
| Exception contract | `1.0` reserved; no public exception file yet |
| Baseline | `1.0` legacy only |
| Rulepack manifest | `1.0` |

Endpoint fingerprints use `authmap.endpoint.v1`. Proof fingerprints use
`authmap.proof.v1`. Components are serialized with stable ordering and hashed
using SHA-256. These fingerprints are not legacy baseline fingerprints and do
not establish proof validity by themselves.

## SARIF Mapping

The v2 SARIF mapping uses stable opaque rules `AMV2-0001` through `AMV2-0005`,
precise source regions, invocation and version-control provenance, and
`authmapEndpointFingerprint/v1` partial fingerprints. Custom metadata appears
only beneath SARIF `properties.authmap`.

Incomplete coverage is emitted as `AMV2-0005`; coverage remains separate from
endpoint results.

## Legacy Compatibility

`legacy_compatibility_document` creates a one-way compatibility artifact from a
legacy scan result. Every item is labeled `legacy_unverified`, retains original
legacy state and severity, and has `v2_verdict: null`. In particular:

- `PROTECTED` is not converted to `GUARDED`.
- `EXPOSED` is not converted to `UNGARDED`.
- Legacy baseline fingerprints are not reused as endpoint or proof identity.

Legacy JSON `1.1`, table output, SARIF output, config `1.0`, and baseline `1.0`
remain supported without deprecation through M3. A later default-output change
requires production adapter evidence, a release decision, and a separately
documented deprecation window.
