# Express Evidence Scan

The Express reference adapter is an explicit v2 mode. It does not
replace the legacy default scan or create CI policy decisions.

```console
authmap --project . --evidence-scan express --format json
authmap --project . --evidence-scan express --format sarif
authmap --project . --evidence-scan express --format json --explain-adapter
```

## Supported Envelope

- JavaScript `.js`, `.mjs`, and `.cjs` parsed by pinned Tree-sitter runtime.
- Nearest package declares `express`; source resolves a default ESM import or
  CJS `require("express")` binding.
- Literal app/router declarations, route methods, multiline calls,
  `router.route(path).METHOD`, handler references, local literal mounts, and
  registration order.
- Exact `passport.authenticate("jwt", ...)` enforcement tied to a `passport`
  ESM/CJS binding. OAuth and local login strategies are authentication flows,
  not resource-enforcement proof. Late middleware does not guard earlier routes.
- Source public declarations immediately preceding a route, using
  `// authmap-public-v1 policy=ID owner=ID reason=ID`.
- Exact local custom auth imports declared in source with
  `// authmap-auth-v1 module=./auth.js symbol=requireAuth rule=ID`. The symbol
  must resolve to that package-local module.
- Auth-lifecycle handler members such as logout, token refresh, password reset,
  and email verification remain `UNRESOLVED` when no route enforcement proof is
  available. Handler names can preserve ambiguity but never prove protection.
- V2 JSON/SARIF source spans, derivations, associations, proofs, capability
  provenance, coverage, and deterministic fingerprints.

## Conservative Limits

- TypeScript, JSX, computed paths or prefixes, arrays, spreads, factories,
  conditional assembly, dynamic aliases, and duplicate mounts are unsupported
  or unresolved.
- Supported cross-file composition is limited to a package-local default ESM
  import or CJS `module.exports`/`require` router mount. Named imports/exports,
  re-exports, computed module paths, factories, and broader interprocedural
  composition are unresolved outside supported static forms. Route composition
  and scope resolution are Verified within the supported envelope.
- External declarations have no accepted project policy schema in M3.
  Undeclared auth-looking custom middleware is `UNRESOLVED`. Route names never
  imply publicness.
- Sessions, token parsing, identity use, CORS, logging, and middleware names do
  not prove protection.

Parser, package, source, and resource failures produce diagnostics and never
fall back to legacy regex evidence. The adapter never invokes Node, npm, package
scripts, imports, or target code. Limits are 10,000 source files, 2 MiB per
source file, and 50 MiB total source bytes.

Legacy scan remains unchanged when `--evidence-scan` is absent. Legacy policy,
baseline, AST, and rulepack flags cannot be combined with evidence mode.

The independently labeled M3 corpus covers 49 routes across four pinned projects.
Endpoint discovery, route composition, auth association, scope resolution, and
coverage accounting are Verified with zero false `GUARDED`. Public override
remains Experimental because no independent explicit-public label exists.

CI policy must consume per-capability maturity and must not treat public override
as blocking. Verified maturity applies only to the supported envelope above.
route-population recall and independent positive auth coverage remain incomplete.

## Governance Support

| Capability | Governance maturity |
|---|---|
| Endpoint discovery | Verified within supported envelope |
| Route composition | Verified within supported envelope |
| Scope resolution | Verified within supported envelope |
| Auth association | Verified within supported envelope |
| Coverage accounting | Verified within supported envelope |
| Public override | Experimental, visible, non-blocking |

Default policy blocks only full required Verified evidence. Experimental and
discovery-only output remain advisory.
