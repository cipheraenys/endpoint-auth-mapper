# Express Evidence Scan

The Express reference adapter is an explicit Experimental v2 mode. It does not
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
- V2 JSON/SARIF source spans, derivations, associations, proofs, capability
  provenance, coverage, and deterministic fingerprints.

## Conservative Limits

- TypeScript, JSX, computed paths or prefixes, arrays, spreads, factories,
  conditional assembly, dynamic aliases, and duplicate mounts are unsupported
  or unresolved.
- Supported cross-file composition is limited to a package-local default ESM
  import or CJS `module.exports`/`require` router mount. Named imports/exports,
  re-exports, computed module paths, factories, and broader interprocedural
  composition are unresolved. Route composition and scope resolution remain
  Experimental.
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

The adapter has been exercised against three independent public Express projects,
but those repositories do not provide the labeled endpoint and auth ground truth
needed for capability promotion. Every capability remains Experimental and
non-blocking.

Continuation evaluation adds six audited route labels. Adapter agreement is
`6/6` with zero false `GUARDED`; this is not promotion evidence because labeled
route-population recall and independent positive auth coverage remain incomplete.
