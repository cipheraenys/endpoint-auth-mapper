# Gate CI on new exposed endpoints

Configure CI to fail when pull requests introduce unauthenticated endpoints.

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
        run: authmap --project . --fail-on EXPOSED --min-confidence high
```

## 2. GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
authmap:
  stage: test
  image: python:3.12
  script:
    - pip install ./endpoint-auth-mapper
    - authmap --project . --fail-on EXPOSED --min-confidence high
```

## Flags Details

- `--fail-on EXPOSED`: Fails pipeline (exit code 1) if any EXPOSED endpoints exist.
- `--min-confidence high`: Skips low or medium confidence detections to reduce false positives in CI blocks.
