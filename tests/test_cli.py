"""Command-line behaviour: help, argument handling, path validation and exit codes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reposentinel import __version__, cli
from reposentinel.checks import all_rules
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan
from tests.test_engine import ExplodingCheck

runner = CliRunner()


def invoke(*args: str | Path):
    return runner.invoke(cli.app, [str(arg) for arg in args])


# Typer forces coloured help output when it detects CI (GITHUB_ACTIONS,
# FORCE_COLOR or PY_COLORS), and colour codes can split an option name such as
# "--format" into styled pieces. Help assertions compare the plain text.
_ANSI_CODES = re.compile("\x1b" + r"\[[0-9;]*m")


def plain(text: str) -> str:
    return _ANSI_CODES.sub("", text)


# --- help, version, rules ------------------------------------------------------


def test_help_lists_commands() -> None:
    result = invoke("--help")
    assert result.exit_code == 0
    assert "scan" in plain(result.stdout) and "rules" in plain(result.stdout)


def test_no_arguments_shows_help() -> None:
    result = invoke()
    assert "Usage" in plain(result.output)


def test_scan_help_documents_options() -> None:
    result = invoke("scan", "--help")
    assert result.exit_code == 0
    for option in ("--format", "--output", "--fail-on", "--max-file-size-kb", "--max-files"):
        assert option in plain(result.stdout)


def test_plain_strips_forced_colour() -> None:
    # Guard for the helper above: coloured output must reduce to the plain words.
    assert plain("\x1b[1;36m-\x1b[0m\x1b[1;36m-format\x1b[0m") == "--format"


def test_version() -> None:
    result = invoke("--version")
    assert (result.exit_code, result.stdout.strip()) == (0, f"reposentinel {__version__}")


def test_rules_lists_every_rule() -> None:
    result = invoke("rules")
    assert result.exit_code == 0
    for rule in all_rules():
        assert rule.id in result.stdout


def test_python_dash_m_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "reposentinel", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"reposentinel {__version__}"


# --- path validation -------------------------------------------------------------


def test_missing_path_is_a_usage_error(tmp_path: Path) -> None:
    result = invoke("scan", tmp_path / "does-not-exist")
    assert result.exit_code == 2
    assert "path not found" in result.stderr


def test_file_path_is_a_usage_error(tmp_path: Path) -> None:
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")
    result = invoke("scan", file)
    assert result.exit_code == 2
    assert "not a directory" in result.stderr


def test_inaccessible_directory_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "scandir", deny)
    result = invoke("scan", tmp_path)
    assert result.exit_code == 2
    assert "permission denied" in result.stderr


def test_nonexistent_path_argument(tmp_path: Path) -> None:
    # Without a path, scan uses the current directory (see
    # test_scan_defaults_to_the_current_directory); a wrong path is still a usage error.
    result = invoke("scan", str(tmp_path / "does-not-exist"))
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "args",
    [
        ("--format", "xml"),
        ("--fail-on", "critical"),
        ("--max-files", "0"),
        ("--max-file-size-kb", "-5"),
        ("--unknown-option",),
    ],
)
def test_invalid_options_are_usage_errors(tmp_path: Path, args: tuple[str, ...]) -> None:
    assert invoke("scan", tmp_path, *args).exit_code == 2


# --- scanning and exit codes -------------------------------------------------------


def test_clean_repository_exits_zero(make_repo: RepoFactory) -> None:
    result = invoke("scan", make_repo({"README.md": "# hello"}))
    assert result.exit_code == 0
    assert "CLEAN" in result.stdout
    assert "Exit code 0" in result.stdout


def test_empty_directory_exits_zero(tmp_path: Path) -> None:
    result = invoke("scan", tmp_path)
    assert result.exit_code == 0
    assert "Files in scope: 0" in result.stdout


def test_findings_exit_one(make_repo: RepoFactory) -> None:
    result = invoke("scan", make_repo({"app.py": f"t = '{synthetic.GITHUB_TOKEN}'"}))
    assert result.exit_code == 1
    assert "RS-SEC-004" in result.stdout
    assert synthetic.GITHUB_TOKEN not in result.output


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [("never", 0), ("high", 0), ("medium", 1), ("low", 1), ("MEDIUM", 1)],
)
def test_fail_on_threshold(make_repo: RepoFactory, fail_on: str, expected: int) -> None:
    root = make_repo({".env": "X=1"})  # one medium finding
    assert invoke("scan", root, "--fail-on", fail_on).exit_code == expected


def test_info_findings_do_not_fail_by_default(make_repo: RepoFactory) -> None:
    root = make_repo({".gitignore": ".env\n", ".env": "X=1"})  # info severity
    assert invoke("scan", root).exit_code == 0
    assert invoke("scan", root, "--fail-on", "info").exit_code == 1


def test_file_limit_makes_scan_incomplete(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "", "b.txt": "", "c.txt": ""})
    result = invoke("scan", root, "--max-files", "2")
    assert result.exit_code == 3
    assert "INCOMPLETE" in result.stdout


def test_size_limit_is_reported_but_not_a_failure(make_repo: RepoFactory) -> None:
    root = make_repo({"big.txt": "x" * 3000})
    result = invoke("scan", root, "--max-file-size-kb", "1")
    assert result.exit_code == 0
    assert "too large 1" in result.stdout


def test_failing_check_exits_three(make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: [ExplodingCheck()])
    result = invoke("scan", make_repo({"a.txt": ""}))
    assert result.exit_code == 3
    assert "failed" in result.stdout
    assert synthetic.GITHUB_TOKEN not in result.output


def test_internal_error_exits_three_without_traceback(
    make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args, **kwargs):
        raise RuntimeError(f"boom near {synthetic.GITHUB_TOKEN}")

    monkeypatch.setattr(cli, "run_scan", broken)
    result = invoke("scan", make_repo({"a.txt": ""}))
    assert result.exit_code == 3
    assert "internal error" in result.stderr
    assert "Traceback" not in result.output
    assert synthetic.GITHUB_TOKEN not in result.output


# --- output formats and files -------------------------------------------------------


def test_json_to_stdout_is_pure_json(make_repo: RepoFactory) -> None:
    result = invoke("scan", make_repo({".env": "X=1"}), "--format", "json")
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["summary"]["by_rule"] == {"RS-HYG-001": 1}


def test_html_to_stdout(make_repo: RepoFactory) -> None:
    result = invoke("scan", make_repo({"README.md": "x"}), "-f", "html")
    assert result.exit_code == 0
    assert result.stdout.startswith("<!doctype html>")


@pytest.mark.parametrize("fmt", ["json", "html", "text"])
def test_output_file(make_repo: RepoFactory, tmp_path: Path, fmt: str) -> None:
    root = make_repo({".env": "X=1"})
    output = tmp_path / f"reposentinel-report.{fmt}"
    result = invoke("scan", root, "--format", fmt, "--output", output)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert f"Wrote {fmt} report to" in result.stderr
    content = output.read_text(encoding="utf-8")
    assert "RS-HYG-001" in content
    assert "\x1b" not in content  # no colour codes in files
    if fmt == "json":
        json.loads(content)


def test_output_into_missing_folder_is_a_usage_error(
    make_repo: RepoFactory, tmp_path: Path
) -> None:
    result = invoke("scan", make_repo({}), "-o", tmp_path / "missing" / "r.json")
    assert result.exit_code == 2
    assert "does not exist" in result.stderr


def test_output_pointing_at_directory_is_a_usage_error(
    make_repo: RepoFactory, tmp_path: Path
) -> None:
    result = invoke("scan", make_repo({}), "-o", tmp_path)
    assert result.exit_code == 2


def test_report_inside_target_gets_a_note(make_repo: RepoFactory) -> None:
    root = make_repo({"README.md": "x"})
    result = invoke("scan", root, "-f", "json", "-o", root / "audit.json")
    assert "inside the scanned directory" in result.stderr
    # The default report name is excluded from later scans, so no note is needed.
    result = invoke("scan", root, "-f", "json", "-o", root / "reposentinel-report.json")
    assert "inside the scanned directory" not in result.stderr


def test_report_write_failure_exits_three(
    make_repo: RepoFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "write_text", deny)
    result = invoke("scan", make_repo({}), "-f", "json", "-o", tmp_path / "report.json")
    assert result.exit_code == 3
    assert "could not write the report" in result.stderr
    assert "Permission denied" in result.stderr


def test_demo_command_creates_the_synthetic_repository(tmp_path: Path) -> None:
    target = tmp_path / "demo"
    result = runner.invoke(cli.app, ["demo", str(target)])
    assert result.exit_code == 0, result.output
    assert "fake" in result.output.lower()
    assert len(scan(target).findings) > 0
    again = runner.invoke(cli.app, ["demo", str(target)])
    assert again.exit_code == 2  # never writes into a folder that has files


def test_scan_defaults_to_the_current_directory(
    make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo({".env": "A=1", "app.py": "x = 1"})
    monkeypatch.chdir(root)
    result = runner.invoke(cli.app, ["scan", "--no-color"])
    assert result.exit_code == 1, result.output
    assert "RS-HYG-001" in result.output


def test_package_metadata_version_matches_the_code() -> None:
    import importlib.metadata

    assert importlib.metadata.version("reposentinel") == __version__


def test_an_interrupted_scan_says_so_and_writes_no_report(
    make_repo: RepoFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo({"app.py": "x = 1"})
    out = tmp_path / "report.json"

    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_scan", interrupted)
    result = invoke("scan", root, "-f", "json", "-o", out)
    assert result.exit_code == 130
    assert "interrupted" in result.stderr and "no report was written" in result.stderr
    assert not out.exists()
