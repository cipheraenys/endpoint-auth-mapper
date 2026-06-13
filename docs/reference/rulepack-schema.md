# Rule Pack Schema

A rule pack teaches the analyzer about a specific language or framework using pure JSON data.

Valid packs must adhere to the schema below. Invalid packs raise a `RulePackError` on load.

## Top-level fields

| Field | Required | Type | Description |
|---|---|---|---|
| `name` | no | string | Pack ID (defaults to the filename stem). |
| `language` | **yes** | string | Language label reported on findings. |
| `framework` | **yes** | string | Framework label reported on findings. |
| `extensions` | **yes** | array of strings | File extensions to scan (e.g. `[".js", ".ts"]`). |
| `endpoints` | **yes** | array of objects | Rules for discovering endpoints. |
| `auth_guards` | no | array of objects | Rules for discovering authentication. |
| `public_exemptions` | no | array of objects | Rules for intentionally public paths. |

## Pattern objects

The `endpoints`, `auth_guards`, and `public_exemptions` arrays contain pattern objects. 

| Field | Required | Type | Description |
|---|---|---|---|
| `regex` | **yes** | string | The PCRE regex to match. Must escape backslashes for JSON (e.g., `\\b`). |
| `confidence` | **yes** | string | `low`, `medium`, or `high`. |
| `signal` | **yes** | string | Human-readable explanation of what matched. |

### Endpoint-specific pattern fields

Pattern objects in the `endpoints` array support two additional required fields:

| Field | Required | Type | Description |
|---|---|---|---|
| `method_group` | **yes** | integer | Regex capture group index containing the HTTP method (e.g., GET). |
| `route_group` | **yes** | integer | Regex capture group index containing the route path (e.g., `/api/users`). |