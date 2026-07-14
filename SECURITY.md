# Security & Dual-Use Statement

Endpoint & Auth Mapper is a **defensive** application-security tool. It helps
developers find unauthenticated HTTP endpoints in code they own so they can add
proper authentication before deployment.

Like most security tooling, it is **dual-use**: a map of unauthenticated
endpoints aids a defender fixing them and, in principle, an attacker seeking
them. This document states plainly how the tool is deliberately constrained to
the defensive side of that line.

## Threat model

**Intended operator:** a developer or security engineer auditing a codebase they
own or are authorized to assess.

**Assets to protect:**
- The analyzed source (must never be transmitted anywhere).
- The analysis output (a sensitive map of weak points).
- The host running the tool (must not be harmed by hostile input).

**Out of scope:** the tool does not attack, scan, fuzz, or interact with any
running system. It has no capability to do so by design.

## Design constraints and how they are enforced

| Constraint | Enforcement | Where |
|---|---|---|
| **No network egress** | No sockets, no HTTP client, no URL input anywhere in the codebase. | whole project |
| **No live-target mode** | The only input is a local `--project` path. There is no host/URL argument. | `cli.py` |
| **Read-only on target** | Target files are read as text and matched with regex. Never imported, `eval`'d, or executed. | `core/engine.py`, `core/safety.py` |
| **Fail-safe classification** | Ambiguity → `UNKNOWN`; `EXPOSED` requires HIGH discovery confidence. | `core/classifier.py` |
| **Confidential output** | Reports default to a gitignored dir; write paths are confined (no traversal). | `.gitignore`, `core/safety.ensure_within` |
| **Secret redaction** | Snippets mask passwords, tokens, and long high-entropy strings. | `core/safety.redact` |
| **ReDoS resistance** | Every regex runs under a wall-clock budget; overruns are isolated per file. | `core/safety.SafeMatcher` |
| **Bounded reads** | Oversized and binary files are skipped, not parsed. | `core/safety.read_text_safely` |
| **Resilience** | A failure on one file becomes a recorded warning, never a crash. | `core/engine.Engine.scan` |
| **Zero dependencies** | Standard library only at runtime; nothing to supply-chain compromise. | `pyproject.toml` |

## Why the output is confidential

A report can enumerate an application's weakest entry points. Treat it like a
penetration-test finding:

- It is written to `.security-reports/` which is gitignored by default.
- It should not be committed to a public repository or shared broadly.
- Reports reference `file:line` and signal names, **not** secret values.

## Responsible use

- Run only on code you **own or are explicitly authorized to audit**.
- Do not use the output to target systems you do not control.
- Static analysis is a **first-pass triage**, not a proof. A `PROTECTED` result
  is not a guarantee; a `UNKNOWN`/`EXPOSED` result is a prompt for review.

## Reporting a vulnerability in this tool

If you discover a security issue in Endpoint & Auth Mapper itself (for example,
a way to make it write outside its report directory, execute target code, or
exfiltrate data), please report it privately to the maintainers rather than
opening a public issue.

## Limitations (honest disclosure)

- Regex/heuristic detection can miss auth performed in unusual ways
  (custom frameworks, reverse-proxy rules, gateway policies, `.htaccess`). Such
  cases surface as `UNKNOWN`, which is intentional.
- The classic-PHP "file as endpoint" model is coarse and yields `MEDIUM`
  confidence, so a missing guard becomes `UNKNOWN` rather than `EXPOSED` unless
  corroborated.
- It analyzes source, not runtime; endpoints created dynamically at runtime may
  not be visible.

## Runtime dependencies

`jsonschema==4.26.0` is the maintained MIT-licensed validator used for public
JSON Schema 2020-12 contracts, including `$ref` and
`unevaluatedProperties`. It validates inert manifest data only; it does not
load package entrypoints, import target projects, access the network, or execute
target code. Dependency source and release metadata are published at
<https://github.com/python-jsonschema/jsonschema> and PyPI. Dependency updates
require schema conformance, full regression, license, and vulnerability review.

`types-jsonschema==4.26.0.20260518` is a development-only Apache-2.0 typeshed
stub package and is not installed at runtime.
