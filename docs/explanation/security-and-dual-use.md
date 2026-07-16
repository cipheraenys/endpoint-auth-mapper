# Security and Dual-Use

Endpoint & Auth Mapper is a defensive application-security tool. It inventories
route-shaped candidates and, for supported Express capabilities, maps static
auth evidence for developer review.

However, like most security tooling, it is **dual-use**. Candidate and evidence
maps aid defenders but could also aid an attacker seeking review targets.

We deliberately constrain the tool to the defensive side of that line.

## Core constraints

- **Source code only**: The tool requires read access to the source code repository. It cannot be pointed at a live website or production URL.
- **Zero network capability**: The tool has no HTTP clients, sockets, or telemetry. It cannot send requests, nor can it exfiltrate findings. 
- **Confidential reports**: Scan outputs are saved to a `.security-reports/` directory that is listed in the project's `.gitignore`, preventing accidental commit of sensitive vulnerability maps.
- **Fail-safe analysis**: Ambiguity is always flagged for human review (`UNKNOWN`), rather than assuming an endpoint is safe.

For the complete, authoritative statement on our threat model, safety boundaries, and vulnerability reporting process, please read the [SECURITY.md](../../SECURITY.md) file at the root of the repository.
