# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-13

### Added
- Experimental AST-based analysis engine via `tree-sitter`.

### Changed
- Standardized documentation formatting.
- Removed unused development artifacts.

## [0.1.0] - 2026-07-12

### Added
- Initial release of Endpoint & Auth Mapper.
- Language-agnostic analysis engine driven by JSON rule packs.
- Fail-safe classification model: `PROTECTED` / `EXPOSED` / `UNKNOWN` / `PUBLIC`
  with confidence and severity.
- Bundled rule packs: PHP (native), Node/Express, Python/Flask, Python/Django,
  Java/Kotlin Spring, Go (net/http, chi, gin, mux), Ruby on Rails/Sinatra,
  C#/ASP.NET Core.
- Reporters: human table, JSON, and SARIF 2.1.0.
- **Layer 1** batch CLI with CI-friendly exit codes and `--fail-on` gating.
- **Layer 2** rich terminal UI (`--interactive`): stdlib-only ANSI rendering
  with a scrollable findings list, detail pane, state/severity filters, sort
  modes, fuzzy search, in-TUI export, and a help overlay. Falls back to the
  table report when the terminal cannot render ANSI.
- **Layer 3** CI templates: GitHub Action, GitLab CI, and a pre-commit hook.
- Baseline support for incremental adoption on legacy codebases.
- Inline `authmap:ignore` suppression with recorded reasons.
- Safety primitives: ReDoS-bounded matching, secret redaction, output-path
  confinement, and bounded/encoding-aware file reads.
- `**`-aware glob matching that works identically across operating systems.
- Test suite with per-language fixtures and golden assertions.
- Documentation: README, SECURITY (dual-use statement), ARCHITECTURE,
  RULEPACK_SCHEMA, USAGE, and CONTRIBUTING.

[0.1.0]: https://example.invalid/endpoint-auth-mapper/releases/tag/v0.1.0
