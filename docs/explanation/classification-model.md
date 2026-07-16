# Classification Model

The default legacy scanner uses a fail-safe compatibility classifier over regex
matches. Its states remain unverified and must not be treated as v2 verdicts.

The core principle of the model is that **ambiguity resolves to `UNKNOWN`, never to `PROTECTED`.** 

Silence is never treated as safety. If the analyzer cannot confidently determine the state of an endpoint, it will not assume it is secure.

## Confidence and discovery

The engine uses regular expressions and heuristics to analyze the source code. Because static analysis without a full abstract syntax tree (AST) or runtime context is inherently imprecise, every match carries a confidence score: `low`, `medium`, or `high`.

- **High confidence**: The tool is certain about the match (e.g., standard framework route declarations).
- **Medium/Low confidence**: The tool is less certain (e.g., broad catch-all patterns or legacy "file as endpoint" routing like classic PHP).

## State resolution rules

The `classifier.py` module applies the following rules to resolve an endpoint's final auth state:

1. **`PROTECTED`**: The candidate and a same-line auth-looking pattern matched with high confidence. This is lexical association, not enforcement proof.
2. **`EXPOSED`**: The endpoint structure was matched with high confidence, AND no authentication guard pattern was matched.
3. **`UNKNOWN`**: The endpoint structure was matched with medium/low confidence, OR an authentication guard was found but its confidence was medium/low.

By requiring high confidence to declare an endpoint `EXPOSED`, the tool avoids drowning developers in false positive alerts on uncertain code paths. 

Requiring high confidence reduces false legacy `PROTECTED` states, but does not
prove enforcement. Verified protection requires the v2 evidence graph and proof
obligations documented for supported Express capabilities.

Any failure to definitively prove either state results in the `UNKNOWN` classification, signaling that a human should review the code.

Regex rule packs cannot prove controller inheritance, middleware ordering,
router composition, or cross-file scope. A file-wide auth signal therefore
cannot produce `PROTECTED` for route-model endpoints. It is retained as evidence
and lowers the route to `UNKNOWN` unless route-local evidence exists.

Public status also requires evidence. Committed project `public_paths` or an
explicit custom rule-pack `exempt_paths` declaration can produce `PUBLIC`; a
route name alone cannot.
