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
import json
import math
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .app.baseline import build_baseline
from .app.config import ConfigError, RunConfig
from .app.evidence_gate import evaluate_evidence_gate
from .app.evidence_runner import run_express_evidence_scan
from .app.runner import EXIT_ERROR, Runner, RunnerError
from .core.v2 import (
    EvidencePolicyError,
    explain_adapter_document,
    load_evidence_policy,
)
from .core.walker import resolve_project_root
from .reporters.v2_json_reporter import render_evidence_json
from .reporters.v2_sarif_reporter import render_evidence_sarif

_DEFAULT_REPORT_DIR = ".security-reports"
_FAIL_ON_VALUES = ("EXPOSED", "UNKNOWN", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authmap",
        description=(
            "Offline static analyzer that maps candidate HTTP endpoints and "
            "classifies their authentication posture (PROTECTED/EXPOSED/UNKNOWN/PUBLIC). "
            "Run only on code you own or are authorized to audit."
        ),
        epilog="This tool performs no network activity and never executes target code.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--evidence-scan", choices=("express",), help="run explicit v2 parser-backed evidence scan")
    parser.add_argument("--evidence-policy", metavar="PATH", help="apply a versioned policy to an evidence scan")
    parser.add_argument("--explain-adapter", action="store_true", help="include adapter explanation in v2 JSON")
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
        choices=_FAIL_ON_VALUES,
        default=None,
        metavar="LEVEL",
        help="Exit non-zero when findings at/above LEVEL exist "
        "(EXPOSED, UNKNOWN, or a severity: CRITICAL/HIGH/MEDIUM/LOW/INFO).",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        default=None,
        help="Minimum confidence for a finding to count toward --fail-on (default: medium).",
    )
    parser.add_argument(
        "--exclude",
        default=None,
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
        type=_positive_float,
        default=1.0,
        help="Per-regex wall-clock budget in seconds (ReDoS guard, default: 1.0).",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Open the local interactive browser (Layer 2) after scanning.",
    )
    parser.add_argument(
        "--experimental-ast",
        action="store_true",
        default=None,
        help="Enable experimental AST-based analysis (requires tree-sitter).",
    )
    parser.add_argument(
        "--strict-coverage",
        action="store_true",
        default=None,
        help="Exit 2 when eligible source is unsupported, skipped, or errors.",
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
    cli_overrides = frozenset(
        field_name
        for field_name, value in (
            ("excludes", args.exclude),
            ("experimental_ast", args.experimental_ast),
            ("fail_on", args.fail_on),
            ("min_confidence", args.min_confidence),
            ("strict_coverage", args.strict_coverage),
        )
        if value is not None
    )
    return RunConfig(
        project_root=root,
        report_dir=report_dir,
        output_stem=args.output or "authmap",
        output_format=args.format,
        fail_on=args.fail_on,
        min_confidence=args.min_confidence or "medium",
        excludes=_split_csv(args.exclude or ""),
        extra_rulepack_dirs=extra_dirs,
        baseline_path=Path(args.baseline).expanduser().resolve() if args.baseline else None,
        regex_timeout_seconds=args.regex_timeout,
        write_report=args.output is not None,
        quiet=args.quiet,
        experimental_ast=bool(args.experimental_ast),
        strict_coverage=bool(args.strict_coverage),
        cli_overrides=cli_overrides,
    ).merged_with_file()


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.explain_adapter and not args.evidence_scan:
        parser.error("--explain-adapter requires --evidence-scan")
    if args.evidence_policy and not args.evidence_scan:
        parser.error("--evidence-policy requires --evidence-scan")
    if args.evidence_scan:
        incompatible = (args.fail_on, args.baseline, args.write_baseline, args.experimental_ast, args.rulepacks)
        if any(bool(value) for value in incompatible):
            parser.error(
                "--evidence-scan cannot be combined with legacy policy, baseline, AST, or rulepack flags"
            )
        if args.format == "table":
            parser.error("--evidence-scan requires --format json or --format sarif")
    if args.write_baseline is None:
        return
    conflicts = [
        option
        for option, active in (
            ("--baseline", args.baseline is not None),
            ("--fail-on", args.fail_on is not None),
            ("--interactive", bool(args.interactive)),
        )
        if active
    ]
    if conflicts:
        parser.error(f"--write-baseline cannot be combined with {', '.join(conflicts)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    if args.evidence_scan == "express":
        try:
            result = run_express_evidence_scan(
                Path(args.project), tuple(["authmap", *(argv if argv is not None else sys.argv[1:])])
            )
            exit_code = 0
            if args.evidence_policy:
                policy = load_evidence_policy(Path(args.evidence_policy).expanduser().resolve())
                gate_run = evaluate_evidence_gate(result.report, policy)
                exit_code = gate_run.exit_class.code
            if args.format == "sarif":
                if args.explain_adapter:
                    parser.error("--explain-adapter is supported only with --format json")
                output = render_evidence_sarif(result.report)
            elif args.explain_adapter:
                output = json.dumps(
                    {
                        "adapter_explanation": explain_adapter_document(result.explanation),
                        "evidence_report": json.loads(render_evidence_json(result.report)),
                    },
                    indent=2,
                    sort_keys=True,
                )
            else:
                output = render_evidence_json(result.report)
            if args.output:
                Path(args.output).write_text(output + "\n", encoding="utf-8")
            if not args.quiet:
                print(output)
            return exit_code
        except (EvidencePolicyError, OSError, ValueError) as exc:
            print(f"authmap: evidence scan failed: {exc}", file=sys.stderr)
            return EXIT_ERROR

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
        if outcome.result.incomplete_coverage():
            print(
                "authmap: error: refusing to write a baseline from incomplete coverage",
                file=sys.stderr,
            )
            return EXIT_ERROR
        baseline_doc = build_baseline(outcome.result.sorted_findings())
        baseline_path = Path(args.write_baseline).expanduser().resolve()
        try:
            baseline_path.write_text(baseline_doc, encoding="utf-8")
        except OSError as exc:
            print(f"authmap: error: could not write baseline '{baseline_path}': {exc}", file=sys.stderr)
            return EXIT_ERROR
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
