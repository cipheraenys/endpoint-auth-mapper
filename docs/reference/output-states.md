# Output States

Endpoint & Auth Mapper classifies every detected endpoint into one of four states based on the presence of authentication guards.

| State | Severity mapping | Description |
|---|---|---|
| `EXPOSED` | `CRITICAL` or `HIGH` | Confidently an endpoint, and no auth guard was found. |
| `UNKNOWN` | `MEDIUM` | Structure or guard could not be confidently resolved — review required. |
| `PROTECTED` | `INFO` | An auth guard was confidently detected. |
| `PUBLIC` | `INFO` | Intentionally public (e.g., a health check or explicitly exempt path). |

## State resolution

The tool resolves states using a fail-safe approach:
- To classify an endpoint as `PROTECTED`, the engine must match both the endpoint structure and the authentication guard with high confidence.
- To classify an endpoint as `EXPOSED`, the engine must match the endpoint structure with high confidence, but find no authentication guard.
- If the endpoint structure is ambiguous, or if an auth guard uses a pattern the tool does not confidently recognize, the state resolves to `UNKNOWN`.

For more details on the rationale behind this fail-safe approach, see the [Classification model](../explanation/classification-model.md) explanation.