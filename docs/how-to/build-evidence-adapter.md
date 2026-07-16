# Build an Evidence Adapter

Use this guide only after a framework track has a locked scope and independent
evaluation plan. Shared frontend availability does not authorize a framework
adapter or capability promotion.

## 1. Establish applicability

Require package, import, symbol, or explicit policy provenance. Receiver names
and route-shaped syntax are insufficient. Emit `ApplicabilityResult` with stable
activation evidence IDs and source spans.

## 2. Consume shared frontend facts

Use `JavaScriptFrontend` or `RustFrontend` for parser lifecycle, package/module
boundaries, aliases, imports/uses, exports/re-exports, syntax hooks,
diagnostics, and source-level failure coverage. Do not add framework branches to
the frontend or core resolver.

## 3. Resolve declaration ownership

Create `OwnershipClaim` values and use `resolve_ownership()`. Active owners need
activation evidence. Competing candidates remain explicitly ambiguous. Runtime
metadata uses `ClaimRole.METADATA` and never owns framework declarations.

## 4. Emit evidence, not verdicts

Adapters emit immutable facts, relations, diagnostics, coverage, and derivation
links. They do not emit verdict, severity, suppression, proof, or policy. The v2
resolver applies framework-neutral proof obligations.

## 5. Evaluate independently

Build an independent framework corpus separate from implementation fixtures.
Measure applicability, endpoint discovery, composition, scope, auth association,
public declaration, coverage, collision, and policy outcomes against
`quality-evaluation.md`. Any false confident `GUARDED` is a stop condition.

## 6. Validate security and packaging

Run focused tests, `pytest`, `ruff check .`, `mypy src`, `python -m build`, clean
wheel install, supported OS/Python matrix, parser no-execution/network tests,
resource tests, and dependency/license review. Record results in roadmap
execution evidence before requesting capability promotion.

See [Shared frontend reference](../reference/shared-frontends.md).
