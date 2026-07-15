# Gate Express Evidence in CI

This tutorial creates one explicit Verified evidence gate. It does not change
legacy scanning or infer policy from route names.

1. Copy `examples/ci/evidence-policy.json` into repository.
2. Confirm its Express adapter version matches installed authmap capability
   metadata.
3. Run:

```console
authmap --project . --evidence-scan express --format json --evidence-policy examples/ci/evidence-policy.json
```

Exit `0` means policy satisfied, `1` means unsuppressed policy violation, and
`2` means invalid policy, exception, setup, adapter, report, or invocation.
JSON retains endpoint verdict and evidence alongside gate audit.

Use `examples/ci/github-actions.yml` as tested CI starting point. Pin authmap and
dependencies with hashes before use.
