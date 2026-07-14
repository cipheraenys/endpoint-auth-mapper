# Command-Line Interface

## Syntax

```text
authmap [--project PATH] [--format {table,json,sarif}] [--output STEM]
        [--report-dir DIR] [--fail-on LEVEL] [--min-confidence {low,medium,high}]
        [--exclude NAMES] [--rulepacks DIRS] [--baseline PATH]
        [--write-baseline PATH] [--regex-timeout SECONDS]
        [--interactive] [--experimental-ast] [--strict-coverage] [--quiet] [--version]
```

## Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--project PATH` | `-p` | `.` | Path to the project root to analyze. |
| `--format FORMAT` | `-f` | `table` | Output format: `table`, `json`, or `sarif`. |
| `--output STEM` | `-o` | — | Write the report under the report dir with this stem (implies file output). |
| `--report-dir DIR` | | `.security-reports` | Directory for confidential reports. |
| `--fail-on LEVEL` | | — | Exit `1` when findings at/above LEVEL exist. Accepts a state (`EXPOSED`, `UNKNOWN`) or severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`). Unknown values are rejected. |
| `--min-confidence` | | `medium` | Minimum confidence for a finding to count toward `--fail-on`. One of `low`, `medium`, `high`. |
| `--exclude NAMES` | | — | Comma-separated directory names to exclude in addition to defaults. |
| `--rulepacks DIRS` | | — | Comma-separated extra rule-pack directories to load. |
| `--baseline PATH` | | — | Path to a baseline JSON; findings present in it do not fail the run. |
| `--write-baseline PATH` | | — | Write a baseline of current findings to PATH and exit 0. |
| `--regex-timeout SECONDS` | | `1.0` | Positive, finite per-regex wall-clock budget in seconds (ReDoS guard). |
| `--interactive` | `-i` | off | Open the interactive terminal UI (Layer 2) after scanning. |
| `--experimental-ast` | | off | Enable experimental AST-based analysis (requires `tree-sitter`). |
| `--strict-coverage` | | off | Exit `2` when eligible source is unsupported, skipped, or errors. |
| `--quiet` | `-q` | off | Suppress the rendered report on stdout. |
| `--version` | | — | Print the version and exit. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` (or `--fail-on` not set). |
| `1` | One or more findings at or above `--fail-on` are present. |
| `2` | Tool/setup error, analysis error, or strict-coverage violation. |

`--write-baseline` cannot be combined with `--baseline`, `--fail-on`, or
`--interactive`. An explicitly supplied baseline path must exist and contain
baseline version `1.0` plus a string `fingerprints` array.

Experimental AST findings are advisory and cannot trigger `--fail-on`. Baseline
writing refuses any incomplete scan, regardless of strict coverage mode.

## Examples

```bash
# Human-readable table to stdout
authmap --project .

# Machine-readable JSON, written to .security-reports/authmap.json
authmap --project . --format json --output authmap

# SARIF for GitHub code scanning
authmap --project . --format sarif --output authmap

# Interactive terminal UI
authmap --project . --interactive

# CI gate: fail on new high-confidence exposed endpoints
authmap --project . --fail-on EXPOSED --min-confidence high \
        --baseline .authmap-baseline.json --quiet

# Generate baseline for legacy codebase adoption
authmap --project . --write-baseline .authmap-baseline.json
```
