# Evidence Exceptions 1.0

Evidence exceptions are committed, reviewed, time-bounded suppressions for one
named evidence-policy violation. They never alter endpoint verdict, coverage,
proof, capability maturity, applicability, parser diagnostics, or setup status.

Normative schema:
`https://authmap.dev/schemas/evidence-exceptions-1.0.json`, bundled as
`authmapper/schemas/evidence-exceptions-1.0.schema.json`.

Exact identity includes normalized method and path, adapter ID and version,
required capability and maturity, endpoint fingerprint algorithm and value,
allowed violation kind, and policy ID. Every exception also requires stable ID,
reason, owner, reference, creation date, authorizing policy, and expiry or review
date.

Dates are evaluated using timezone-aware clocks converted to UTC. Expiry and
review dates are due at `00:00:00Z` on specified date. Invalid, expired,
review-due, duplicate, unmatched, and malformed exceptions fail closed. Matching
is exact; route refactors never carry exceptions automatically.

Audit states are `active`, `consumed`, `expired`, `review_due`, `unmatched`, and
`invalid`. Explicit replacement requires known old ID and new stable ID through
`replace_evidence_exception`; replacement identity is supplied and reviewed in
full.
