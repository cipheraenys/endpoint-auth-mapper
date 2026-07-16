# Output States

The default legacy scanner assigns every detected candidate one of four
compatibility states. These states summarize regex evidence; they are not v2
verdicts or Verified framework assurance.

| State | Severity mapping | Description |
|---|---|---|
| `EXPOSED` | `CRITICAL` or `HIGH` | A high-confidence candidate matched without an associated legacy auth pattern. |
| `UNKNOWN` | `MEDIUM` | Structure or guard could not be confidently resolved — review required. |
| `PROTECTED` | `INFO` | A high-confidence same-line legacy auth pattern was associated; not enforcement proof. |
| `PUBLIC` | `INFO` | Intentionally public through committed `public_paths` policy or an explicit custom rule-pack exemption. |

## State resolution

The legacy scanner resolves states using a fail-safe compatibility approach:
- To classify a candidate as `PROTECTED`, the engine must match both endpoint syntax and a same-line legacy auth pattern.
- To classify a candidate as `EXPOSED`, the engine must match endpoint syntax with high confidence but find no associated legacy auth pattern.
- If the endpoint structure is ambiguous, or if an auth guard uses a pattern the tool does not confidently recognize, the state resolves to `UNKNOWN`.

A file-wide auth-looking token is unassociated evidence for route-model packs;
it does not protect sibling routes. `/health`, `/metrics`, and similar names do
not produce `PUBLIC` without an explicit declaration.

Source coverage is separate from endpoint state. JSON schema `1.1` adds a
top-level `coverage` array and `summary.counts_by_coverage`; see
[Configuration](configuration.md#source-coverage).

For more details on the rationale behind this fail-safe approach, see the [Classification model](../explanation/classification-model.md) explanation.

These are legacy JSON `1.1` states. Evidence report `2.0` defines separate
evidence-first verdicts and does not translate these states. See
[Evidence report v2](evidence-report-v2.md).
