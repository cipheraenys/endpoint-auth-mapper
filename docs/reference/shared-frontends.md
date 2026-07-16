# Shared Frontend Reference

Shared frontends parse source and emit framework-neutral syntax, provenance,
diagnostics, and source-level failure coverage. They do not emit framework
ownership, auth semantics, proof, verdict, severity, suppression, or policy.

## Adapter Protocol

Adapters remain responsible for:

1. Declaring applicability from package/import/symbol provenance.
2. Mapping generic syntax to framework-owned facts and relations.
3. Preserving source spans and derivation IDs.
4. Emitting no verdict or severity.
5. Passing facts to the deterministic v2 resolver.

Use `ApplicabilityResult` for activation and `OwnershipDecision` for declaration
collision decisions. `resolve_ownership()` requires activation evidence, selects
at most one owner per normalized declaration/collision group, and emits explicit
ambiguity when multiple candidates remain. `ClaimRole.METADATA` records runtime
or deployment information but never owns declarations.

## JavaScript Frontend

`JavaScriptFrontend` supports `.js`, `.mjs`, and `.cjs` using pinned Tree-sitter.
It provides:

- nearest `package.json` provenance confined to project root;
- ESM/CJS imports, aliases, direct exports, and re-exports;
- deterministic local-module resolution (`.js`, `.mjs`, `.cjs`, then `index.*`);
- generic call, property, handler, parameter, decorator, and policy syntax;
- explicit diagnostics and failure coverage for parse, unsupported source,
  unresolved import/export, ambiguous binding, resource, and package failures.

TypeScript `.ts`/`.tsx` is unsupported in M5 and emits `UNSUPPORTED` coverage.
No TypeScript framework verdict is available.

## Rust Frontend

`RustFrontend` uses `tree-sitter-rust==0.24.2` and `tomli==2.4.1`. It provides:

- Cargo package/workspace ownership and dependency aliases;
- workspace-inherited dependency provenance;
- `use` and public re-export provenance;
- conventional module path resolution and inline modules;
- generic functions, attributes, macros, calls, fields, parameters, and types;
- explicit diagnostics and failure coverage for malformed manifests, unresolved
  uses/modules, package ambiguity, macros, conditional compilation, and limits.

Cargo, build scripts, procedural macros, crates, target code, and network are
never executed. Macro expansion, `cfg` evaluation, generated code, and custom
`#[path]` resolution remain unsupported and visible.

## Diagnostic Registry

Stable namespaces are `frontend.javascript.*` and `frontend.rust.*`. Every
frontend failure has a paired source-level coverage record with `ERROR` or
`UNSUPPORTED`. Adapters may translate diagnostic codes for a frozen external
contract, as Express does, but may not hide or downgrade failed analysis.

## Dependency Boundary

Runtime pins are listed in `pyproject.toml`. Parser updates require license,
vulnerability, ABI/import smoke, focused corpus, full regression, build, and
supported-platform review. Analysis performs no dependency installation,
package-manager invocation, lifecycle hook, telemetry, or network access.

## Capability Promotion

Frontend extraction quality is not framework quality. A new adapter remains
Discovery/Experimental until it has independent framework applicability,
endpoint, composition, scope, auth-association, public-declaration, coverage,
collision, and policy evidence meeting `quality-evaluation.md` thresholds. Any
false confident guarded result in a supported case is a stop condition.

M5 adds no Hono, Fastify, Axum, or other framework support.
