# Evidence Governance

Evidence policy is separate from verdict resolution. Resolver derives endpoint
truth; policy decides whether Verified evidence satisfies governance. Exceptions
suppress only named policy violations and never rewrite truth.

Blocking requires selected Verified endpoint discovery, route composition,
scope resolution, and auth association for same adapter/version. Discovery-only
and Experimental output remain advisory. Express public override remains
Experimental and cannot bypass Verified unguarded gate.

Exact exception identity prevents accidental carryover across route, method,
adapter, capability, fingerprint, or policy changes. UTC date boundaries and
visible audit states make lifecycle review deterministic.

JSON and SARIF preserve evidence, spans, proofs, coverage, rationale, and
suppressed endpoints. This supports audit without producing a second analysis
engine or increasing confidence beyond measured capability maturity.
