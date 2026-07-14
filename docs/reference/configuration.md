# Configuration

## Project configuration (`.authmap.json`)

Commit shared default options to a `.authmap.json` file at the root of your project. Command-line flags always take precedence over these defaults.

```json
{
  "schema_version": "1.0",
  "excludes": ["legacy", "third_party"],
  "min_confidence": "high",
  "fail_on": "EXPOSED",
  "public_paths": ["/health"],
  "strict_coverage": true
}
```

The file is fail-closed. `schema_version` is required and must be `"1.0"`.
Unknown fields, wrong JSON types, and unknown enum values stop before scanning.

### Supported fields

- `excludes`: Array of directory name strings to skip.
- `min_confidence`: String (`low`, `medium`, `high`).
- `fail_on`: String (`EXPOSED`, `UNKNOWN`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `experimental_ast`: Boolean — enable experimental AST-based analysis (default: `false`).
- `public_paths`: Array of route prefixes explicitly declared public. Paths must
  start with `/`; descendants match on path-segment boundaries.
- `strict_coverage`: Boolean. Exit `2` when eligible source is `UNSUPPORTED`,
  `SKIPPED`, or `ERROR` (default: `false`). `ERROR` always exits `2`.

CLI values override committed config. Path names such as `/health` and
`/metrics` are not inherently public.

## Ignore file (`.authmapignore`)

Use `.authmapignore` to specify files or directories that the tool should skip entirely. The file uses Gitignore-style patterns.

```text
# skip generated code
**/generated/**
**/*.min.js
```

## Inline suppression

When a guard exists in a form the analyzer cannot see (for example, enforced by an API gateway), you can suppress the finding using an inline comment.

The comment must include `authmap:ignore` followed by a `reason=...`.

```js
// authmap:ignore reason=auth enforced by API gateway policy
app.get("/api/internal/metrics", (req, res) => { /* ... */ });
```

The annotation can be placed on the endpoint line or the line immediately preceding it.

Suppressed findings are excluded from CI gating but are still recorded in the JSON/SARIF reports for auditability. See [Suppress a finding](../how-to/suppress-a-finding.md) for how to use this workflow.

## Source coverage

Eligible source suffixes are `.c`, `.cc`, `.cpp`, `.cs`, `.go`, `.java`, `.js`,
`.jsx`, `.kt`, `.kts`, `.mjs`, `.cjs`, `.php`, `.py`, `.rb`, `.rs`, `.ts`, and
`.tsx`. Every eligible source receives one coverage status:

| Status | Meaning |
|---|---|
| `ANALYZED` | One or more loaded packs processed the source. |
| `EXCLUDED` | Committed ignore policy, default directory policy, or `--exclude` matched. |
| `UNSUPPORTED` | No loaded pack supports the eligible source. |
| `SKIPPED` | A size, binary, decoding, or read guard prevented analysis. |
| `ERROR` | Analysis failed; a diagnostic is also emitted. |

`UNSUPPORTED`, `SKIPPED`, and `ERROR` make the run incomplete. `ERROR` always
returns exit code `2`; `UNSUPPORTED` and `SKIPPED` return `2` in strict coverage
mode. `EXCLUDED` remains visible but is an intentional policy outcome.
