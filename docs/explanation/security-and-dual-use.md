# Security and Dual-Use

Endpoint & Auth Mapper is a defensive application-security tool. Its primary goal is to help developers find unauthenticated HTTP endpoints in their code so they can add proper authentication before deployment.

However, like most security tooling, it is **dual-use**. A map of unauthenticated endpoints aids a defender in fixing them, but in principle, it could also aid an attacker seeking vulnerabilities.

We deliberately constrain the tool to the defensive side of that line.

## Core constraints

- **Source code only**: The tool requires read access to the source code repository. It cannot be pointed at a live website or production URL.
- **Zero network capability**: The tool has no HTTP clients, sockets, or telemetry. It cannot send requests, nor can it exfiltrate findings. 
- **Confidential reports**: Scan outputs are saved to a `.security-reports/` directory that is automatically ignored by Git (via the generated `.gitignore`), preventing accidental commit of sensitive vulnerability maps.
- **Fail-safe analysis**: Ambiguity is always flagged for human review (`UNKNOWN`), rather than assuming an endpoint is safe.

For the complete, authoritative statement on our threat model, safety boundaries, and vulnerability reporting process, please read the [SECURITY.md](../../SECURITY.md) file at the root of the repository.