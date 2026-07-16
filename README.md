# Endpoint & Auth Mapper

![CI](https://github.com/cipheraenys/endpoint-auth-mapper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/github/license/cipheraenys/endpoint-auth-mapper)
![Version](https://img.shields.io/github/v/tag/cipheraenys/endpoint-auth-mapper?label=version)

A local, offline static analyzer with two explicit modes:

- Default legacy regex inventory across bundled language labels. Its
  `PROTECTED`, `EXPOSED`, `UNKNOWN`, and `PUBLIC` states are unverified
  compatibility output, not framework assurance.
- Opt-in parser-backed Express evidence scan with capability-level verification
  inside its documented JavaScript support envelope.

It answers one question fast, in any codebase you own:

> *Which route-shaped candidates and evidence paths need security review?*

<p align="center">
  <img src="docs/assets/demo.gif" alt="authmap interactive TUI demo" width="900">
</p>

---

## Table of contents

- [Why it exists](#why-it-exists)
- [Design guarantees](#design-guarantees)
- [Bundled rule-pack capabilities](#bundled-rule-pack-capabilities)
- [Install](#install)
- [Quick start](#quick-start)
- [The three layers](#the-three-layers)
- [Exit codes (CI contract)](#exit-codes-ci-contract)
- [How classification works](#how-classification-works)
- [Documentation](#documentation)
- [Scope of use](#scope-of-use)
- [License](#license)

---

## Why it exists

Unauthenticated endpoints are one of the most common and highest-impact
web vulnerabilities (OWASP API Security **API2: Broken Authentication**,
**API5: Broken Function Level Authorization**). They are easy to introduce and
hard to spot in review. This tool gives developers a fast, repeatable inventory
for review. Verified CI assurance is currently available only through the
documented Express evidence scan and evidence policy.

## Design guarantees

<details>
<summary>Click to expand</summary>

| Guarantee | How it is enforced |
|---|---|
| **Source-gated** | Analyzes source you already possess. No network, no URLs, no live probing. |
| **Fail-safe** | Unassociated evidence remains `UNKNOWN`/`UNRESOLVED`; Verified verdicts require proof. |
| **Read-only** | Target code is parsed as text, never imported or executed. |
| **Audited dependencies** | Explicit pinned dependencies validate public contracts; target code is never executed. |
| **Confidential output** | Reports are written to a gitignored directory; secrets are redacted. |
| **Deterministic** | Sorted, stable output suitable for CI diffing and baselines. |
| **Coverage-aware** | Every eligible source is reported as analyzed, excluded, unsupported, skipped, or error. |

See [`SECURITY.md`](./SECURITY.md) for the full dual-use statement and threat model.

</details>

## Bundled legacy rule-pack inventory

All eight bundled JSON packs are legacy discovery heuristics. None establishes
Verified v2 framework support merely by loading. See the complete
[legacy capability inventory](./docs/reference/legacy-capabilities.md), the
[rule pack schema](./docs/reference/rulepack-schema.md), and the
[Express evidence scan](./docs/reference/express-evidence-scan.md).

---

## Install

Requires Python 3.10+. Installation includes the pinned `jsonschema` validator
used for public v2 manifest contracts.

```bash
# From a checkout:
pip install ./endpoint-auth-mapper

# Or run without installing:
python -m authmapper --project /path/to/your/code
```

## Quick start

```bash
# Human-readable table
authmap --project . 

# Machine-readable JSON, written to the confidential report dir
authmap --project . --format json --output authmap

# SARIF for GitHub code scanning
authmap --project . --format sarif --output authmap

# Interactive terminal UI (Layer 2)
authmap --project . --interactive

# Legacy compatibility gate over unverified regex findings
authmap --project . --fail-on EXPOSED --min-confidence high \
        --strict-coverage --baseline .authmap-baseline.json --quiet

# Verified Express evidence gate
authmap --project . --evidence-scan express \
        --evidence-policy evidence-policy.json
```

## The three layers

1. **Batch CLI** — one run, one report, clean exit codes. The core.
2. **Interactive terminal UI** — a stdlib-only ANSI rich TUI to browse,
   filter, search, and export results (`--interactive`). Falls back to the
   table report on terminals without ANSI support.
3. **CI gate** — pre-commit hook and GitHub/GitLab templates in [`ci/`](./ci).
   Legacy `--fail-on` is a compatibility heuristic; evidence policy gates only
   Verified v2 capabilities. This is the intended
   "service" placement — an on-demand gate, never a running daemon.

## Exit codes (CI contract)

<details>
<summary>Click to expand</summary>

| Code | Meaning |
|---|---|
| `0` | No legacy compatibility finding or evidence-policy violation |
| `1` | Legacy compatibility gate or evidence-policy violation |
| `2` | Tool/setup error, analysis error, or strict-coverage violation |

</details>

## How classification works

This diagram describes only the unverified legacy compatibility classifier. The
v2 evidence resolver uses `GUARDED`, `UNGARDED`, `DECLARED_PUBLIC`, and
`UNRESOLVED` with separate coverage and proof obligations.

```mermaid
flowchart TD
    A[Discover endpoints via rule pack] --> B{Auth guard found?}
    B -->|Yes| C["🟢 PROTECTED"]
    B -->|No| D{Explicit public declaration?}
    D -->|Yes| E["🔵 PUBLIC"]
    D -->|No| F{High confidence?}
    F -->|Yes| G["🔴 EXPOSED"]
    F -->|No| H["🟡 UNKNOWN — fail-safe"]
```

Full details in the [Architecture explanation](./docs/explanation/architecture.md).

## Documentation

The project documentation is organized using the [Diátaxis framework](https://diataxis.fr/). Start at the [Docs overview](./docs/README.md).

- [**Tutorials**](./docs/tutorials/) — Guided step-by-step introductions (e.g. Getting started).
- [**How-to guides**](./docs/how-to/) — Task-oriented instructions (e.g. Gating CI, suppressing findings).
- [**Reference**](./docs/reference/) — Technical descriptions (e.g. CLI flags, rule pack schema).
- [**Explanation**](./docs/explanation/) — Background context (e.g. Architecture, classification model).

Other important documents:
- [`SECURITY.md`](./SECURITY.md) — dual-use statement, threat model, mitigations
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — dev setup, tests, style

## Scope of use

Run this tool only on code you **own or are explicitly authorized to audit**.
It performs no network activity and cannot interact with running systems.

## License

MIT — see [`LICENSE`](./LICENSE).
