# Architecture

Endpoint & Auth Mapper is a **modular monolith**: a single installable unit with strictly separated internal layers. Each layer depends only on the ones beneath it, ensuring responsibilities never blur and every piece is independently testable.

The default legacy pipeline is retained for compatibility and emits unverified
regex states. The parser-backed v2 pipeline uses adapters, shared frontends,
evidence graphs, and capability-level governance; currently only the documented
Express envelope is Verified.

## Layered overview

```text
┌─────────────────────────────────────────────────────────────┐
│ Interface layer   cli.py            tui/ (app, screen, input, │  Layers 1 & 2
│                                     widgets, theme)             │
├─────────────────────────────────────────────────────────────┤
│ Application layer app/runner.py  app/config.py  app/baseline  │  orchestration
├─────────────────────────────────────────────────────────────┤
│ Presentation      reporters/{table,json,sarif}               │  pure rendering
├─────────────────────────────────────────────────────────────┤
│ Core (pure)       core/{walker,engine,classifier,            │  analysis
│                           rulepack,model,safety}                │
├─────────────────────────────────────────────────────────────┤
│ Data              rulepacks/*.json                              │  language knowledge
└─────────────────────────────────────────────────────────────┘
```

**Dependency rule**: Arrows point down only. The `core` knows nothing about reporters, the CLI, or the TUI. Reporters and the runner depend on `core`. The CLI and TUI depend on the runner. This keeps the analysis engine pure and reusable.

## Data flow

```text
project path
   │
   ▼
walker.FileWalker ───► decoded SourceFile stream + coverage records
   │                    (size/binary/ignore filtered)
   ▼
engine.Engine
   ├─ rulepack.RulePack (endpoint patterns + auth signals)
   ├─ safety.SafeMatcher (ReDoS-bounded regex)
   └─ classifier (fail-safe state + severity)
   │
   ▼
model.ScanResult (Findings, coverage, errors, summary)
   │
   ├─► reporters.* ───► rendered string
   └─► app.runner  ───► gating + exit code + confidential report file
```

## Module responsibilities

### Core (pure analysis, no output I/O)

- **`model.py`** — Immutable value objects (`Endpoint`, `Finding`, `AuthState`, `Confidence`, `Severity`, `ScanResult`). The shared vocabulary of every layer.
- **`safety.py`** — Cross-cutting safety primitives: bounded/encoding-aware file reads, ReDoS-bounded matching, secret redaction, and output-path confinement.
- **`walker.py`** — Eligible-file discovery with `**`-aware globbing, ignore/exclude accounting, and per-file guards. Yields decoded text and coverage outcomes; performs no auth analysis.
- **`rulepack.py`** — Loads, validates, and compiles JSON rule packs into typed `RulePack` objects. The boundary between on-disk data and the engine.
- **`classifier.py`** — The pure decision policy. Contains the fail-safe rule: `EXPOSED` requires high confidence, otherwise it resolves to `UNKNOWN`.
- **`engine.py`** — The orchestrator that applies rule packs to files and emits findings. Mechanical "how"; the policy "meaning" lives in `classifier`.

### Data

- **`rulepacks/*.json`** — Declarative candidate discovery and auth-signal recognition. New syntax may fit a new pack; verified framework semantics usually require an adapter.

### Presentation

- **`reporters/`** — `table` (human), `json` (machine/baseline), `sarif` (GitHub/Azure code scanning). Pure functions mapping `ScanResult -> str`.

### Application

- **`app/config.py`** — The immutable `RunConfig`, optionally merged with a project `.authmap.json`.
- **`app/baseline.py`** — Fingerprinting for incremental adoption (fail only on *new* findings).
- **`app/runner.py`** — The single use-case entry point: load packs → scan → filter (confidence/baseline) → render → write confidential report → compute exit code. Both CLI and TUI call this, so behavior never diverges.

### Interface

- **`cli.py`** — Thin argument parsing (Layer 1). Delegates all work to `Runner`.
- **`tui/`** — Rich terminal UI (Layer 2). Stdlib-only ANSI rendering:
  - `app.py` — `TuiApp` orchestrator (event loop, state, keyboard dispatch).
  - `screen.py` — `ScreenBuffer` + `AnsiBackend`, terminal sizing, Windows VT.
  - `input.py` — Cross-platform raw key reading (`msvcrt` / `termios`).
  - `widgets.py` — Stateless list, detail, status bar, help overlay renderers.
  - `theme.py` — Colorblind-safe palette; honors `NO_COLOR` / `TERM=dumb`.

## Why a modular monolith?

- **Not a single script:** Separation makes the fail-safe policy, safety primitives, and language rules independently auditable and testable — critical for a security tool.
- **Not microservices:** There is no runtime to distribute. A monolith ships as one auditable artifact with zero network surface, which aligns perfectly with a secure, local-analysis posture.

## V2 evidence contracts

`authmapper.core.v2` is an additive production namespace. It does not replace
legacy engine contracts during M2.

```text
adapter artifact (facts, scopes, relations, diagnostics, coverage)
        |
        v
semantic rules (typed evidence meaning)
        |
        v
validated evidence graph
        |
        v
pure resolver (endpoint verdicts and proofs)
        |
        v
evidence JSON / SARIF / explanation clients
```

Adapters cannot emit verdict or severity. Resolver requires associated
enforcement proof for `GUARDED`, complete relevant coverage for `UNGARDED`, and
resolved public-policy proof for `DECLARED_PUBLIC`; ambiguity remains
`UNRESOLVED`. Coverage records never become synthetic endpoints.

Generic subject kinds cover route calls, object properties, handlers, callable
parameters, type annotations, decorators, middleware, policies, and public
declarations. Synthetic challenge tests represent Express composition, Hono
mounted sub-apps, Bun route-map properties, Axum nested layers, and Rocket typed
request guards without framework-named core fields.

Adapter explanation is an inspection view over activation evidence, ownership,
capabilities, applied semantic rules, and diagnostics. It is not another
analysis engine.
