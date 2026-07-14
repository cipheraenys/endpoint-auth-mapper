# Adapter Explanation View

M2 defines internal adapter explanation view `1.0`. No `authmap
explain-adapter` command is exposed yet because production runner has no v2
adapter activation result. M3 may expose command without changing view fields.

`authmapper.core.v2.AdapterExplanation` includes:

- Adapter ID and version.
- Applicability result: `active`, `inactive`, or `ambiguous`.
- Activation evidence and reasons.
- Ownership and collision decisions.
- Capability maturity per capability.
- Applied semantic rule IDs.
- Unresolved or ownership diagnostics.

`render_adapter_explanation` emits deterministic JSON. Collections must use
unique, stable ordering. View explains evidence and decisions but never changes
activation, evidence, verdict, or policy.

No framework support is promoted by this internal formatter.
