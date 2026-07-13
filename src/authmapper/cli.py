"""Command-line interface (Layer 1).

Thin, declarative argument parsing that delegates all real work to the
application :class:`Runner`. Keeping the CLI thin means the same behaviour is
reachable programmatically and from the TUI.

Exit codes (CI contract):
    0  no gating findings
    1  gating findings present (>= --fail-on)
    2  tool/setup error
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .app.baseline import build_baseline
from .app.config import ConfigError, RunConfig
from .app.runner import EXIT_ERROR, Runner, RunnerError
from .core.walker import resolve_project_root

_DEFAULT_REPORT_DIR = ".security-reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authmap",
        description=(
            "Universal, offline static analyzer that maps HTTP endpoints and "
            "classifies their authentication posture (PROTECTED/EXPOSED/UNKNOWN/PUBLIC). "
            "Run only on code you own or are authorized to audit."
        ),
        epilog="This tool performs no network activity and never executes target code.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--project", "-p", default=".", help="Path to the project root to analyze (default: .)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=("table", "json", "sarif"),
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write the report under the report dir with this stem (implies file output).",
    )
    parser.add_argument(
        "--report-dir",
        default=_DEFAULT_REPORT_DIR,
        help=f"Directory for confidential reports (default: {_DEFAULT_REPORT_DIR}).",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        metavar="LEVEL",
        help="Exit non-zero when findings at/above LEVEL exist "
        "(EXPOSED, UNKNOWN, or a severity: CRITICAL/HIGH/MEDIUM/LOW).",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        default="medium",
        help="Minimum confidence for a finding to count toward --fail-on (default: medium).",
    )
    parser.add_argument(
        "--exclude",
        default="",
        help="Comma-separated directory names to exclude in addition to defaults.",
    )
    parser.add_argument(
        "--rulepacks",
        default="",
        help="Comma-separated extra rule-pack directories to load.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Path to a baseline JSON; findings present in it do not fail the run.",
    )
    parser.add_argument(
        "--write-baseline",
        default=None,
        metavar="PATH",
        help="Write a baseline of current findings to PATH and exit 0.",
    )
    parser.add_argument(
        "--regex-timeout",
        type=float,
        default=1.0,
        help="Per-regex wall-clock budget in seconds (ReDoS guard, default: 1.0).",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Open the local interactive browser (Layer 2) after scanning.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress the rendered report on stdout."
    )
    return parser


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _build_config(args: argparse.Namespace) -> RunConfig:
    root = resolve_project_root(args.project)
    report_dir = (root / args.report_dir).resolve()
    extra_dirs = tuple(Path(p).expanduser().resolve() for p in _split_csv(args.rulepacks))
    return RunConfig(
        project_root=root,
        report_dir=report_dir,
        output_stem=args.output or "authmap",
        output_format=args.format,
        fail_on=args.fail_on,
        min_confidence=args.min_confidence,
        excludes=_split_csv(args.exclude),
        extra_rulepack_dirs=extra_dirs,
        baseline_path=Path(args.baseline).expanduser().resolve() if args.baseline else None,
        regex_timeout_seconds=args.regex_timeout,
        write_report=args.output is not None,
        quiet=args.quiet,
    ).merged_with_file()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = _build_config(args)
    except (FileNotFoundError, NotADirectoryError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        runner = Runner(config)
        outcome = runner.run()
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Optional: write a baseline snapshot and exit cleanly.
    if args.write_baseline:
        baseline_doc = build_baseline(outcome.result.sorted_findings())
        Path(args.write_baseline).write_text(baseline_doc, encoding="utf-8")
        print(f"baseline written: {args.write_baseline}", file=sys.stderr)
        return 0

    if args.interactive:
        from .tui import TuiApp, UnsupportedTerminalError

        try:
            TuiApp(outcome.result, config.report_dir).run()
        except UnsupportedTerminalError:
            print(
                "warning: terminal does not support the rich TUI; "
                "printing the table report instead.",
                file=sys.stderr,
            )
            print(outcome.rendered)
        return outcome.exit_code

    if not config.quiet:
        print(outcome.rendered)
    if outcome.report_path is not None:
        print(f"report written: {outcome.report_path}", file=sys.stderr)

    return outcome.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
