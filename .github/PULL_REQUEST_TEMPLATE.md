## Summary

<!-- What and why, one short paragraph. -->

## Type of change

- [ ] `feat`: new functionality
- [ ] `fix`: bug fix
- [ ] `docs`: documentation only
- [ ] `refactor`: no behavior change
- [ ] `test`: tests only
- [ ] `chore`: tooling, dependencies, config

## Checklist

- [ ] `pytest`, `ruff check .`, and `mypy src` pass locally
- [ ] Runtime dependencies stay explicit, pinned, audited, and justified
- [ ] `core/` still imports nothing from `reporters/`, `app/`, `cli/`, or `tui/`
- [ ] Classification stays fail-safe (ambiguity never classifies as PROTECTED)
- [ ] CHANGELOG has an entry under [Unreleased] for user-visible changes
