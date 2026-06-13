# Add a new language

Endpoint & Auth Mapper uses JSON rule packs for language detection. Engine logic remains language-agnostic. 

## 1. Define rule pack

Create `src/authmapper/rulepacks/<language>.json`.
Alternatively, load custom files via `authmap --rulepacks /path/to/dir`.

Follow `docs/reference/rulepack-schema.md` for pattern specifications.

**Constraints:**
* **Regex execution:** No nested quantifiers (`(a+)+`). Engine aborts on slow regex execution to block ReDoS.
* **Escaping:** JSON requires double backslash (`\\s` for whitespace, `\\(` for parenthesis).
* **Precision:** Broad auth guard patterns misclassify EXPOSED endpoints as PROTECTED. Write strict patterns.

## 2. Add test fixtures

Path: `tests/fixtures/<language>/`
Required files:
1. `vulnerable.<ext>`: Unauthenticated endpoints.
2. `secure.<ext>`: Authenticated endpoints.

## 3. Add Golden Assertion

File: `tests/test_engine_integration.py`
Add test function asserting engine output on new fixtures against expected EXPOSED or PROTECTED counts.

## 4. Validate

```bash
pytest
ruff check .
```
