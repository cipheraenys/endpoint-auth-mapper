# Manage Evidence Exceptions

Create exceptions only for named `unguarded` or strict `unresolved` violations.
Follow `docs/reference/evidence-exceptions.md` exactly. Every exception binds
method/path, adapter/version, capability/maturity, endpoint fingerprint,
violation, and policy.

Audit without changing evidence:

```console
authmap --project . --evidence-scan express --format json \
  --evidence-policy .authmap-policy.json \
  --audit-exceptions .authmap-exceptions.json
```

Consumed exceptions can satisfy gate while original endpoint remains visible.
Expired, review-due, invalid, duplicate, or unmatched exceptions fail with exit
`2`. After route refactor, create reviewed replacement with new stable ID; never
carry old fingerprint automatically.
