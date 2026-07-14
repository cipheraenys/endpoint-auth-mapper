# Configuration

## Project configuration (`.authmap.json`)

Commit shared default options to a `.authmap.json` file at the root of your project. Command-line flags always take precedence over these defaults.

```json
{
  "excludes": ["legacy", "third_party"],
  "min_confidence": "high",
  "fail_on": "EXPOSED"
}
```

### Supported fields

- `excludes`: Array of directory name strings to skip.
- `min_confidence`: String (`low`, `medium`, `high`).
- `fail_on`: String (`EXPOSED`, `UNKNOWN`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `experimental_ast`: Boolean — enable experimental AST-based analysis (default: `false`).

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
