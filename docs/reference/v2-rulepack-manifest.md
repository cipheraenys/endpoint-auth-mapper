# V2 Rulepack Manifest

V2 adapter and semantic-rule packages use the independent manifest contract
`1.0`. This contract does not replace legacy bundled regex rule packs and does
not imply verified framework support.

Normative schema:
`https://authmap.dev/schemas/rulepack-manifest-1.0.json`, bundled as
`authmapper/schemas/rulepack-manifest-1.0.schema.json`.

Required fields describe package identity and version, engine compatibility,
languages, runtimes, optional framework identity, lifecycle, capability
maturity, applicability signals, collision group, and inert entrypoint
identity. Unknown fields are errors.

Package lifecycle and capability maturity are separate:

- Lifecycle: `draft`, `active`, `deprecated`, `retired`.
- Capability maturity: `unavailable`, `experimental`, `verified`.
- Applicability outcome, produced during activation rather than stored in the
  manifest: `active`, `inactive`, `ambiguous`.

`jsonschema==4.26.0` validates the schema using Draft 2020-12 semantics.
`authmapper.core.v2.load_manifest` also rejects manifests whose engine range
does not include the running engine version.

Adapters emit source subjects, facts, scopes, relations, unresolved records,
diagnostics, capability provenance, and coverage. Adapter artifacts have no
verdict or severity field. Semantic rules classify evidence into
`auth_enforcement`, `public_override`, `identity_use`, `session_presence`,
`routing_predicate`, or `weak_indicator`; only the resolver creates endpoint
verdicts.
