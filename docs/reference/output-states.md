# Output States

Endpoint & Auth Mapper classifies every detected endpoint into one of four states based on the presence of authentication guards.

| State | Severity mapping | Description |
|---|---|---|
| `EXPOSED` | `CRITICAL` or `HIGH` | Confidently an endpoint, and no auth guard was found. |
| `UNKNOWN` | `MEDIUM` | Structure or guard could not be confidently resolved — review required. |
| `PROTECTED` | `INFO` | An auth guard was confidently associated with this endpoint. |
| `PUBLIC` | `INFO` | Intentionally public through committed `public_paths` policy or an explicit custom rule-pack exemption. |

## State resolution

The tool resolves states using a fail-safe approach:
- To classify an endpoint as `PROTECTED`, the engine must match both the endpoint structure and an authentication guard associated with that endpoint.
- To classify an endpoint as `EXPOSED`, the engine must match the endpoint structure with high confidence, but find no authentication guard.
- If the endpoint structure is ambiguous, or if an auth guard uses a pattern the tool does not confidently recognize, the state resolves to `UNKNOWN`.

A file-wide auth-looking token is unassociated evidence for route-model packs;
it does not protect sibling routes. `/health`, `/metrics`, and similar names do
not produce `PUBLIC` without an explicit declaration.

Source coverage is separate from endpoint state. JSON schema `1.1` adds a
top-level `coverage` array and `summary.counts_by_coverage`; see
[Configuration](configuration.md#source-coverage).

For more details on the rationale behind this fail-safe approach, see the [Classification model](../explanation/classification-model.md) explanation.
