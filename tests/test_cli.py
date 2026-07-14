"""End-to-end CLI tests, including the exit-code contract used by CI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import authmapper.cli as cli
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
    main(["--project", str(fixtures_dir / "node"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "endpoint-auth-mapper"
    assert payload["schema_version"] == "1.1"
    assert payload["coverage"][0]["status"] == "ANALYZED"
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


def test_cli_unknown_config_error_is_actionable_before_scan(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / ".authmap.json").write_text(
        '{"schema_version":"1.0","min_confidnce":"high"}', encoding="utf-8"
    )

    def unexpected_scan(_self):
        raise AssertionError("scan must not run")

    monkeypatch.setattr(cli.Runner, "run", unexpected_scan)

    assert main(["--project", str(tmp_path), "--quiet"]) == 2
    assert "unknown field(s): min_confidnce" in capsys.readouterr().err


@pytest.mark.parametrize(
    "config",
    [
        {"schema_version": "1.0", "unknown": True},
        {"schema_version": "2.0"},
        {"schema_version": "1.0", "min_confidence": "certain"},
        {"schema_version": "1.0", "fail_on": "SAFE"},
        {"schema_version": "1.0", "excludes": ["valid", 7]},
        {"schema_version": "1.0", "experimental_ast": "yes"},
        {"schema_version": "1.0", "public_paths": ["health"]},
        {"schema_version": "1.0", "strict_coverage": "yes"},
        {"schema_version": "1.0", "fail_on": None},
    ],
)
def test_cli_exit_2_on_invalid_project_config_before_scan(
    tmp_path: Path, monkeypatch, config: dict[str, object]
):
    (tmp_path / ".authmap.json").write_text(json.dumps(config), encoding="utf-8")

    def unexpected_scan(_self):
        raise AssertionError("scan must not run")

    monkeypatch.setattr(cli.Runner, "run", unexpected_scan)

    assert main(["--project", str(tmp_path), "--quiet"]) == 2


def test_project_config_applies_public_declaration(tmp_path: Path, capsys):
    (tmp_path / "route.js").write_text('app.get("/health", handler)\n', encoding="utf-8")
    (tmp_path / ".authmap.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "fail_on": "EXPOSED",
                "min_confidence": "high",
                "public_paths": ["/health"],
            }
        ),
        encoding="utf-8",
    )

    assert main(["--project", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["auth_state"] == "PUBLIC"


def test_cli_rejects_invalid_fail_on():
    with pytest.raises(SystemExit) as exc:
        main(["--fail-on", "SAFE"])
    assert exc.value.code == 2


def test_cli_rejects_non_positive_regex_timeout():
    with pytest.raises(SystemExit) as exc:
        main(["--regex-timeout", "0"])
    assert exc.value.code == 2


def test_cli_rejects_write_baseline_conflict(tmp_path: Path):
    with pytest.raises(SystemExit) as exc:
        main(["--write-baseline", str(tmp_path / "base.json"), "--fail-on", "EXPOSED"])
    assert exc.value.code == 2


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


def test_cli_exit_2_on_missing_baseline(fixtures_dir: Path):
    code = main([
        "--project", str(fixtures_dir / "node"),
        "--fail-on", "EXPOSED",
        "--baseline", "/nonexistent/path/baseline.json",
        "--quiet",
    ])
    assert code == 2


def test_cli_unsupported_source_is_reported_and_fails_scan_health(tmp_path: Path, capsys):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    code = main(["--project", str(tmp_path), "--format", "json", "--strict-coverage"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["coverage"] == [
        {
            "file": "main.rs",
            "reason": "no loaded rule pack supports .rs",
            "rulepacks": [],
            "status": "UNSUPPORTED",
        }
    ]


def test_cli_unsupported_source_is_advisory_without_strict_coverage(tmp_path: Path):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    assert main(["--project", str(tmp_path), "--quiet"]) == 0


def test_cli_refuses_baseline_from_incomplete_scan(tmp_path: Path):
    (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    assert main(["--project", str(tmp_path), "--write-baseline", str(baseline)]) == 2
    assert not baseline.exists()


def test_experimental_ast_cannot_block_ci(fixtures_dir: Path):
    code = main(
        [
            "--project",
            str(fixtures_dir / "node"),
            "--experimental-ast",
            "--fail-on",
            "EXPOSED",
            "--quiet",
        ]
    )

    assert code == 0
