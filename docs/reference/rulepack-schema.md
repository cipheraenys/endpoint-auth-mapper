# Rule Pack Schema

A legacy rule pack teaches the regex scanner candidate and signal syntax using
pure JSON data. It does not prove framework applicability, ownership,
enforcement, or Verified v2 capability maturity.

Valid packs must adhere to the schema below. Invalid packs raise a `RulePackError` on load.

## Top-level fields

| Field | Required | Type | Description |
|---|---|---|---|
| `name` | no | string | Pack ID (defaults to the filename stem). |
| `language` | **yes** | string | Language label reported on findings (e.g. `"javascript"`). |
| `framework` | no | string | Framework label reported on findings (defaults to `"generic"`). |
| `file_globs` | **yes** | array of strings | Glob patterns for files to scan (e.g. `["**/*.js", "**/*.ts"]`). |
| `endpoint_model` | no | string | `"route"` (default) or `"file"`. Route model matches routed handlers; file model treats each matching file as one endpoint. |
| `endpoint_patterns` | yes (route model) | array of objects | Rules for discovering endpoints. Required when `endpoint_model` is `"route"`. |
| `auth_signals` | **yes** | array of objects | Rules for discovering authentication guards. At least one is required. |
| `exempt_paths` | no | array of strings | Explicit custom-pack public declarations. Bundled packs do not declare paths public by name. Prefer committed project `public_paths` for project policy. |
| `file_endpoint_method` | no | string | HTTP method assigned to file-model endpoints (default: `"ANY"`). |
| `ast_language` | no | string | Tree-sitter language name for experimental AST analysis. |
| `ast_endpoints` | no | array of objects | AST-based endpoint discovery queries. |
| `ast_auth_signals` | no | array of objects | AST-based auth signal queries. |

No bundled pack currently declares AST queries. Custom AST output is opt-in and
advisory; it never participates in `--fail-on`.

## Endpoint pattern objects

Objects in the `endpoint_patterns` array.

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | **yes** | string | Unique rule identifier. |
| `regex` | **yes** | string | Regex to match endpoint declarations. Must escape backslashes for JSON (e.g. `\\b`). |
| `capture` | no | object | Capture group mapping: `{ "method": <int>, "path": <int> }`. |
| `default_method` | no | string | HTTP method when `capture.method` is absent (default: `"ANY"`). |
| `ignore_case` | no | boolean | Case-insensitive matching (default: `true`). |

### Capture object

| Field | Type | Description |
|---|---|---|
| `method` | integer | Regex capture group index for the HTTP method (e.g. `1`). |
| `path` | integer | Regex capture group index for the route path (e.g. `2`). |

## Auth signal objects

Objects in the `auth_signals` array.

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | **yes** | string | Unique signal identifier. |
| `regex` | **yes** | string | Regex to match auth guard patterns. |
| `scope` | no | string | `"same_line"` or `"file"` (default: `"file"`). `same_line` can protect that route declaration. In route-model packs, `file` is unassociated evidence and cannot prove sibling routes protected. |
| `ignore_case` | no | boolean | Case-insensitive matching (default: `true`). |

## AST pattern objects (experimental)

Requires `tree-sitter` optional dependency (`pip install endpoint-auth-mapper[ast]`).

### `ast_endpoints`

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | **yes** | string | Rule identifier. |
| `query` | **yes** | string | Tree-sitter query string for endpoint discovery. |

### `ast_auth_signals`

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | **yes** | string | Signal identifier. |
| `query` | **yes** | string | Tree-sitter query string for auth guard detection. |
| `scope` | no | string | `"same_line"` or `"file"` (default: `"file"`). |

## Example: route model (Node/Express)

```json
{
  "name": "node-express",
  "language": "javascript",
  "framework": "express",
  "file_globs": ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"],
  "endpoint_model": "route",
  "endpoint_patterns": [
    {
      "id": "express-route",
      "regex": "\\b(?:app|router|api)\\.(get|post|put|delete|patch|all)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]",
      "capture": { "method": 1, "path": 2 }
    }
  ],
  "auth_signals": [
    {
      "id": "inline-auth-middleware",
      "regex": "\\b(requireAuth|isAuthenticated|authenticate|passport\\.authenticate)\\b",
      "scope": "same_line"
    }
  ]
}
```

## Example: file model (PHP)

```json
{
  "name": "php-native",
  "language": "php",
  "framework": "native",
  "file_globs": ["**/*.php"],
  "endpoint_model": "file",
  "file_endpoint_method": "ANY",
  "endpoint_patterns": [],
  "auth_signals": [
    {
      "id": "session-guard",
      "regex": "\\$_SESSION\\s*\\[\\s*['\"][^'\"]*auth",
      "scope": "file"
    }
  ]
}
```
