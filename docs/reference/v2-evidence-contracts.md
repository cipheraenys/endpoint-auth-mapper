# V2 Semantic Evidence Contracts

Evidence report `2.1` encodes auth assurance through framework-neutral graph
shapes. Framework names, runtime names, symbols, receiver names, and numeric
confidence do not change resolver behavior.

## Proven Auth Enforcement

`GUARDED` requires all of these records:

- A sourced `AUTH_ENFORCEMENT` fact with a source span.
- An `EvidenceAssociation` that binds the enforcement fact to an endpoint and
  scope and retains derivation.
- An `AUTH_ENFORCEMENT` proof that references the fact and matching endpoint
  association and retains derivation.
- Analyzed endpoint discovery, route composition, scope resolution, and auth
  association coverage for the endpoint.
- No endpoint-bound unresolved evidence or invalid proof.

This is the only auth route to `GUARDED`. Adapters and rulepacks must not emit an
enforcement fact or proof for identity access, session access, auth-looking text,
or unproven middleware association.

## Ambiguous Auth

Auth evidence that cannot satisfy enforcement proof obligations uses all of
these records:

- A sourced `AUTH_AMBIGUITY` fact with a source span.
- An `EvidenceAssociation` to one endpoint and scope. Its derivation includes
  the ambiguity fact and endpoint fact.
- An endpoint-bound `UnresolvedRecord`. Its derivation includes exactly the
  matching ambiguity fact and association.

Graph validation rejects missing, dangling, crossed-endpoint, or malformed
ambiguity references. A valid shape resolves `UNRESOLVED`; it is not a proof and
cannot produce `GUARDED`.

## Weak Signals

`IDENTITY_USE`, `SESSION_PRESENCE`, and `WEAK_INDICATOR` facts are advisory.
They retain spans, provenance, association, and coverage where known, but never
change an otherwise complete endpoint verdict and never satisfy an enforcement
proof.

## Coverage

Coverage remains separate from semantic class and endpoint verdict. Adapters
must preserve explicit `ANALYZED`, `EXCLUDED`, `UNSUPPORTED`, `SKIPPED`, or
`ERROR` records and capability provenance. Incomplete required coverage resolves
an endpoint `UNRESOLVED`; it cannot be hidden by enforcement, ambiguity, or weak
evidence.

## Report Version

Current semantic graph and report contract is `2.1`, identified by
`https://authmap.dev/schemas/evidence-report-2.1.json`. Callers select `2.1`
explicitly when building a report document. Schema `2.0` remains bundled and
byte-identical for existing documents; it does not accept the new ambiguity
contract.

## Legacy Boundary

Bundled regex packs remain discovery-only compatibility heuristics. Their
auth-looking matches and legacy confidence cannot become v2 facts, associations,
proofs, Verified capability, or evidence-policy authority without a separately
authorized parser-backed adapter and independent capability evaluation. See
[Legacy Capability Inventory](legacy-capabilities.md).
