# Legacy Capability Inventory

This page records measured behavior of the default regex scanner. Bundled JSON
packs are compatibility heuristics, not verified framework adapters. Loading or
compiling a pack proves only schema validity.

Status terms:

- **Discovery-only**: heuristic candidate or signal inventory.
- **Legacy shared**: behavior supplied by the legacy engine rather than a pack.
- **Experimental**: opt-in advisory behavior; never part of `--fail-on`.
- **Unavailable**: no usable v2 evidence capability.

No entry below is `Verified`. Default `--fail-on` remains a backwards-compatible
gate over unverified legacy states. Evidence-policy blocking applies only to
reported Verified v2 capabilities; currently that means the documented Express
evidence scan capability envelope.

## Capability Matrix

| Entry | Profile | Applicability | Endpoint discovery | Composition | Scope | Auth association | Public override | Coverage | Lifecycle | Default CI |
|---|---|---|---|---|---|---|---|---|---|---|
| `php-native` | Legacy discovery | File glob | File-as-endpoint, `ANY` | Unavailable | Unavailable | Unavailable | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `node-express` | Legacy discovery | File glob and receiver regex | Literal route-call regex | Unavailable | Same-line lexical only | Discovery-only middleware token | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on`; Express v2 available separately |
| `python-flask` | Legacy discovery | Broad Python glob and receiver regex | Literal decorator regex, method `ANY` | Unavailable | Unavailable | Unavailable | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `python-django` | Legacy discovery | Filename/glob heuristic | Literal URL-call regex, method `ANY` | Unavailable | Unavailable | Unavailable | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `java-spring` | Legacy discovery | Java/Kotlin glob and annotation regex | Literal mapping regex | Unavailable | Unavailable | Unavailable | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `go-nethttp` | Legacy discovery | Go glob and receiver regex | Literal handler/verb regex | Unavailable | Same-line lexical only | Discovery-only middleware token | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `ruby-rails` | Legacy discovery | Broad Ruby glob and call regex | Literal Rails/Sinatra route regex | Unavailable | Unavailable | Unavailable | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `csharp-aspnet` | Legacy discovery | C# glob and attribute/call regex | Literal attribute/minimal-API regex | Unavailable | Same-line lexical only | Discovery-only `RequireAuthorization` token | Legacy shared explicit policy | Legacy shared source coverage | Unavailable for v2 evidence | Unverified `--fail-on` |
| `experimental-ast` | Experimental | Custom grammar/query declaration | Custom AST query only | Unavailable | Query-local only | Advisory query signal | Legacy shared explicit policy | Legacy shared source coverage | Experimental | Never participates in `--fail-on` |

## Known Limitations

| Entry | Evidence and limitation |
|---|---|
| `php-native` | Every matching PHP file is a medium-confidence endpoint. File-wide session/auth tokens cannot produce `PROTECTED`. |
| `node-express` | No package/import provenance, mounts, middleware order, symbol ownership, dynamic paths, or bypass analysis. Same-line names may produce legacy `PROTECTED`; this is not enforcement proof. |
| `python-flask` | No import provenance, blueprint composition, decorator-to-handler association, method extraction, or bypass analysis. |
| `python-django` | No URL include composition, view association, class/viewset permissions, inherited policy, method resolution, or bypass analysis. |
| `java-spring` | No class-prefix or security-chain composition. Security annotations and principal injection are file-wide indicators; `@AuthenticationPrincipal` is not enforcement. |
| `go-nethttp` | No import provenance, wrapping/group composition, middleware order, aliases, or enforcement proof. Receiver names can collide. |
| `ruby-rails` | No routes-to-controller association, namespaces/scopes, filters, inheritance, skip actions, or Sinatra filter semantics. |
| `csharp-aspnet` | No controller-prefix, endpoint-chain, authorization-policy, fallback-policy, `AllowAnonymous`, or inheritance analysis. |
| `experimental-ast` | No bundled pack defines AST queries. Custom queries do not establish framework identity or Verified maturity. |

## Compatibility Boundary

M5 does not delete packs, rename legacy states, change legacy report schemas, or
change legacy exit-code behavior. This inventory corrects support claims. The
only conservative behavior correction is Spring principal injection: it remains
visible as a file-wide indicator but can no longer produce legacy `PROTECTED`.
