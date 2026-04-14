"""End-to-end CLI tests, including the exit-code contract used by CI."""

from __future__ import annotations

from pathlib import Path

from authmapper.cli import main


def test_cli_table_runs_clean_exit(fixtures_dir: Path, capsys):
    code = main(["--project", str(fixtures_dir / "php"), "--format", "table"])
    out = capsys.readouterr().out
    assert code == 0  # no --fail-on -> always 0
    assert "Endpoint & Auth Mapper" in out


def test_cli_fail_on_exposed_trips_gate(fixtures_dir: Path):
    # The node fixture contains a high-confidence EXPOSED admin route.
    code = main(
        [
            "--project",
            str(fixtures_dir / "node"),
            "--fail-on",
            "EXPOSED",
            "--min-confidence",
            "high",
            "--quiet",
        ]
    )
    assert code == 1


def test_cli_json_output_is_valid(fixtures_dir: Path, capsys):
    import json

    main(["--project", str(fixtures_dir / "node"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "endpoint-auth-mapper"
    assert "summary" in payload


def test_cli_write_baseline_then_pass(fixtures_dir: Path, tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    # First: record everything as accepted.
    assert main(
        ["--project", str(fixtures_dir / "node"), "--write-baseline", str(baseline)]
    ) == 0
    assert baseline.exists()
    # Then: with the baseline applied, the same findings no longer fail.
    code = main(
        [
            "--project",
            str(fixtures_dir / "node"),
            "--fail-on",
            "EXPOSED",
            "--min-confidence",
            "high",
            "--baseline",
            str(baseline),
            "--quiet",
        ]
    )
    assert code == 0


def test_cli_interactive_falls_back_to_table_when_not_a_tty(fixtures_dir: Path, capsys):
    # In a test environment stdout is not a TTY, so the rich TUI is
    # unavailable and the CLI must fall back to the table report.
    code = main(["--project", str(fixtures_dir / "php"), "--interactive"])
    captured = capsys.readouterr()
    assert code == 0
    assert "rich TUI" in captured.err or "table report" in captured.err
    # The fallback table report is printed to stdout.
    assert "Endpoint & Auth Mapper" in captured.out
