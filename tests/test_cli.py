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


# -- fail-closed input validation -------------------------------------------


def test_cli_exit_2_on_malformed_config(tmp_path: Path):
    cfg = tmp_path / ".authmap.json"
    cfg.write_text("{invalid json", encoding="utf-8")
    # Place a dummy source file so project root resolves.
    (tmp_path / "dummy.js").write_text("// empty", encoding="utf-8")
    code = main(["--project", str(tmp_path)])
    assert code == 2


def test_cli_exit_2_on_non_object_config(tmp_path: Path):
    cfg = tmp_path / ".authmap.json"
    cfg.write_text('"just a string"', encoding="utf-8")
    (tmp_path / "dummy.js").write_text("// empty", encoding="utf-8")
    code = main(["--project", str(tmp_path)])
    assert code == 2


def test_cli_missing_config_is_ok(fixtures_dir: Path):
    # No .authmap.json — should run fine.
    code = main(["--project", str(fixtures_dir / "php"), "--quiet"])
    assert code == 0


def test_cli_exit_2_on_malformed_baseline(fixtures_dir: Path, tmp_path: Path):
    baseline = tmp_path / "bad-baseline.json"
    baseline.write_text("{not valid}", encoding="utf-8")
    code = main([
        "--project", str(fixtures_dir / "node"),
        "--fail-on", "EXPOSED",
        "--baseline", str(baseline),
        "--quiet",
    ])
    assert code == 2


def test_cli_exit_2_on_non_object_baseline(fixtures_dir: Path, tmp_path: Path):
    baseline = tmp_path / "bad-baseline.json"
    baseline.write_text("[1, 2, 3]", encoding="utf-8")
    code = main([
        "--project", str(fixtures_dir / "node"),
        "--fail-on", "EXPOSED",
        "--baseline", str(baseline),
        "--quiet",
    ])
    assert code == 2


def test_cli_missing_baseline_is_ok(fixtures_dir: Path):
    code = main([
        "--project", str(fixtures_dir / "node"),
        "--fail-on", "EXPOSED",
        "--baseline", "/nonexistent/path/baseline.json",
        "--quiet",
    ])
    # Missing baseline = empty set, so EXPOSED findings will trip the gate (exit 1)
    assert code == 1
