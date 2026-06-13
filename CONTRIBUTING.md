# Contributing
Project favors small,
auditable changes and keeps a strict **zero runtime dependency** rule.

## Development setup
`ash
# From the project root
python -m pip install -e ".[dev]"     # installs pytest, ruff, mypy (dev only)
`

Run without installation:
`ash
python -m authmapper --project tests/fixtures/node
`

## Running the checks
`ash
pytest            # unit + integration tests
ruff check .      # lint
mypy src          # type-check
`

## Project conventions
- **Runtime code uses the standard library only.** Anything else belongs under
  the dev optional dependencies and must not be imported by src/authmapper.
- **Core stays pure.** core/ must not import from eporters/, pp/,
  cli, or 	ui/. Dependencies point downward only (see
  [docs/explanation/architecture.md](./docs/explanation/architecture.md)).
- **Fail-safe first.** Never let ambiguity classify as PROTECTED. New code that
  touches classification must preserve the invariant tested in
  	ests/test_classifier.py.
- **No network, ever.** Do not add sockets, HTTP clients, or URL inputs.
- **Docstrings explain "why", comments explain intent** — not restating code.

## Commit style
Use [Conventional Commits](https://www.conventionalcommits.org/).
Format: <type>[optional scope]: <description>

Types:
- eat: New feature
- ix: Bug fix
- docs: Documentation updates
- style: Formatting, whitespace (no code change)
- `refactor:` Code rewrite (no bug fix or feature)
- perf: Performance improvements
- 	est: Add/update tests
- chore: Build config, tooling, dependencies

Example: eat(core): add AST fallback

## Documentation style
- Start with the reader's task, not the implementation.
- Prefer a command, example, or failure mode over a general claim.
- Keep usage docs focused on what users run and what output means.
- Put design rationale in architecture docs only when it explains a tradeoff.
- Avoid filler words and marketing adjectives such as "robust," "seamless,"
  and "powerful."
- Do not restate code. Document behavior, constraints, and edge cases.
- Use tables only when comparing values is easier than reading prose.

## Adding a language (most common contribution)
1. Create src/authmapper/rulepacks/<lang>.json per
   [docs/reference/rulepack-schema.md](./docs/reference/rulepack-schema.md).
2. Add a fixture pair under 	ests/fixtures/<lang>/ (one vulnerable, one secure).
3. Add a golden assertion to 	ests/test_engine_integration.py.