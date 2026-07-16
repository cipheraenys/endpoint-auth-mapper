# Gate CI with verified Express evidence

For supported Express JavaScript, use the parser-backed evidence scan and a
versioned evidence policy. This gates only reported Verified capabilities.

## 1. GitHub Actions

Create `.github/workflows/authmap.yml`:

```yaml
name: AuthMap
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Endpoint & Auth Mapper
        run: pip install ./endpoint-auth-mapper
      - name: Run Scan
        run: authmap --project . --evidence-scan express --evidence-policy evidence-policy.json
```

## 2. GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
authmap:
  stage: test
  image: python:3.12
  script:
    - pip install ./endpoint-auth-mapper
    - authmap --project . --evidence-scan express --evidence-policy evidence-policy.json
```

## Legacy Compatibility Gate

`--fail-on EXPOSED` is retained for backwards compatibility over unverified
legacy regex states. It is useful as an inventory heuristic, but it does not
prove endpoints authenticated or provide Verified framework assurance. No
Verified evidence gate is currently available for other bundled legacy packs.

See [Evidence policy](../reference/evidence-policy.md) for policy fields and the
[legacy capability inventory](../reference/legacy-capabilities.md) for limits.
