# Add a new language

Endpoint & Auth Mapper uses JSON rule packs for candidate discovery and auth-signal
recognition. A custom pack can add syntax inventory without engine changes, but
does not become verified framework protection support.

Review the [legacy capability inventory](../reference/legacy-capabilities.md)
before describing support or using legacy findings as assurance.

## 1. Define rule pack

Create `src/authmapper/rulepacks/<language>.json`.
Alternatively, load custom files via `authmap --rulepacks /path/to/dir`.

Follow `docs/reference/rulepack-schema.md` for pattern specifications.

**Constraints:**
* **Regex execution:** No nested quantifiers (`(a+)+`). Engine aborts on slow regex execution to block ReDoS.
* **Escaping:** JSON requires double backslash (`\\s` for whitespace, `\\(` for parenthesis).
* **Association:** Only `same_line` auth signals can produce `PROTECTED` in the
  current route model. File-wide signals remain unassociated evidence.
* **Precision:** Broad auth guard patterns create noise. Write strict patterns.

## 2. Add test fixtures

Path: `tests/fixtures/<language>/`
Required files:
1. `vulnerable.<ext>`: Unauthenticated endpoints.
2. `secure.<ext>`: Authenticated endpoints.

## 3. Add Golden Assertion

File: `tests/test_engine_integration.py`
Add tests for candidate discovery, coverage status, and supported route-local
association. Do not claim global/group auth or bypass support from regex presence.

## 4. Validate

```bash
pytest
ruff check .
```
