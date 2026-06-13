# Command-Line Interface

## Syntax

```text
authmap [--project PATH] [--format {table,json,sarif}] [--output STEM]
        [--report-dir DIR] [--fail-on LEVEL] [--min-confidence {low,medium,high}]
        [--exclude NAMES] [--rulepacks DIRS] [--baseline PATH]
        [--write-baseline PATH] [--regex-timeout SECONDS]
        [--interactive] [--quiet] [--version]
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--project`, `-p` | `.` | Project root directory to analyze. |
| `--format`, `-f` | `table` | Output format: `table`, `json`, `sarif`. |
| `--output`, `-o` | — | Report file stem; presence enables file output in the report directory. |
| `--report-dir` | `.security-reports` | Directory for confidential reports. |
| `--fail-on` | — | Exit non-zero at or above a level: `EXPOSED`, `UNKNOWN`, or a severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `--min-confidence` | `medium` | Minimum confidence a finding needs to count toward `--fail-on`. |
| `--exclude` | — | Comma-separated directory names to skip (added to default skips). |
| `--rulepacks` | — | Comma-separated extra rule-pack directories to load. |
| `--baseline` | — | Path to a baseline JSON file; findings in it do not fail the run. |
| `--write-baseline` | — | Write a baseline of current findings to the specified path and exit `0`. |
| `--regex-timeout` | `1.0` | Per-regex wall-clock budget in seconds (ReDoS guard). |
| `--interactive`, `-i` | — | Open the rich terminal UI after scanning. |
| `--quiet`, `-q` | — | Suppress the rendered report on stdout. |
| `--version` | — | Show the version and exit. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No gating findings. |
| `1` | Gating findings present (>= `--fail-on`). |
| `2` | Tool/setup error (e.g. bad path, rule-pack error). |

## Interactive mode (`--interactive`)

### Keybindings

| Key | Action |
|---|---|
| `j`, `k`, `↓`, `↑` | Navigate the list |
| `PageUp`, `PageDown` | Scroll a page |
| `Home`, `End` | Jump to top/bottom |
| `/` | Search by route/file/method |
| `Esc` | Cancel search / close overlay |
| `f` | Cycle state filter (`EXPOSED`/`UNKNOWN`/`PROTECTED`/`PUBLIC`) |
| `v` | Cycle severity filter |
| `s` | Cycle sort mode (`severity`/`file`/`route`/`state`) |
| `o` | Export the current view (`json`/`sarif`/`table`) |
| `?`, `h` | Toggle the help overlay |
| `q`, `Ctrl+C` | Quit |

### Terminal behavior

- The interactive view works without color. Set `NO_COLOR=1` or use `TERM=dumb` to disable ANSI color output.
- The list does not rely on color alone. Each row prints the auth state and severity as text (`EXPOSED`, `HIGH`), and the selected row starts with `>`.
- The default color palette is tuned for dark terminal themes. If selected rows are hard to read on a light background, use `NO_COLOR=1` or switch to a dark profile.