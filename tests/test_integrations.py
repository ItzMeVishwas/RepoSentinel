"""Gitleaks adapter and the process helpers, tested without a real Gitleaks binary.

A fake runner stands in for Gitleaks and writes the report file the real tool
would write. These tests verify RepoSentinel's side of the contract (command
line, error handling, parsing, redaction); they cannot prove that a real
Gitleaks release behaves as documented (see docs/integrations.md).
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reposentinel import cli
from reposentinel.engine import run_scan
from reposentinel.integrations.gitleaks import (
    CONFIG_EXTENDING_DEFAULTS,
    LEAKS_EXIT_CODE,
    GitleaksCheck,
    build_command,
    parse_version,
    relative_path,
)
from reposentinel.integrations.process import ProcessResult, find_executable, run_process
from reposentinel.models import CheckStatus, Outcome, ScanReport, Severity
from reposentinel.reporting import render_json
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import create_junction

FAKE_EXE = Path("/opt/tools/gitleaks")


def leak(file: str, line: int = 3, rule: str = "github-pat") -> dict[str, Any]:
    """A result shaped like Gitleaks' JSON report, deliberately *not* redacted."""
    return {
        "RuleID": rule,
        "Description": "Identified a GitHub Personal Access Token",
        "File": file,
        "StartLine": line,
        "Secret": synthetic.GITHUB_TOKEN,
        "Match": f"token = {synthetic.GITHUB_TOKEN}",
        "Fingerprint": f"{file}:{rule}:{line}",
    }


class FakeGitleaks:
    """Records the call and writes a canned report, like Gitleaks would."""

    def __init__(
        self,
        returncode: int = LEAKS_EXIT_CODE,
        report: Any = None,
        stderr: str = "",
        version_output: str = "8.28.0\n",
    ) -> None:
        self.returncode = returncode
        self.report = report
        self.stderr = stderr
        self.version_output = version_output
        self.calls: list[tuple[list[str], Path, float]] = []  # scan calls only
        self.version_calls: list[list[str]] = []
        self.config_text = ""

    def __call__(self, argv: list[str], cwd: Path, timeout: float) -> ProcessResult:
        if argv[1:] == ["version"]:
            self.version_calls.append(argv)
            return ProcessResult(0, "", self.version_output)
        self.calls.append((argv, cwd, timeout))
        self.config_text = Path(argv[argv.index("--config") + 1]).read_text(encoding="utf-8")
        if self.report is not None:
            report_path = Path(argv[argv.index("--report-path") + 1])
            text = self.report if isinstance(self.report, str) else json.dumps(self.report)
            report_path.write_text(text, encoding="utf-8")
        return ProcessResult(self.returncode, self.stderr)


def gitleaks_scan(root: Path, runner: Callable[..., ProcessResult]) -> ScanReport:
    check = GitleaksCheck(finder=lambda name, forbidden: FAKE_EXE, runner=runner)
    return run_scan(root, [check])


# --- successful runs --------------------------------------------------------------


def test_results_become_findings_without_secret_values(make_repo: RepoFactory) -> None:
    root = make_repo({"src/config.py": "x\n" * 5})
    fake = FakeGitleaks(report=[leak(str(root / "src" / "config.py"))])
    report = gitleaks_scan(root, fake)

    (finding,) = report.findings
    assert finding.rule_id == "gitleaks:github-pat"
    assert (finding.path, finding.line, finding.severity) == ("src/config.py", 3, Severity.HIGH)
    assert finding.check_id == "gitleaks"
    assert synthetic.GITHUB_TOKEN not in render_json(report)
    (check,) = report.checks
    assert check.status is CheckStatus.COMPLETED
    assert check.examined is None  # Gitleaks does not report a file count


def test_report_shape_observed_from_gitleaks_8_30_1(make_repo: RepoFactory) -> None:
    # The fields Gitleaks 8.30.1 wrote in directory mode with --redact=100,
    # recorded on Windows: File is absolute with '/' separators even there.
    root = make_repo({"sub dir/app.py": "x\n" * 3})
    observed = {
        "RuleID": "github-pat",
        "Description": "Uncovered a GitHub Personal Access Token",
        "StartLine": 3,
        "EndLine": 3,
        "StartColumn": 10,
        "EndColumn": 49,
        "Match": "REDACTED",
        "Secret": "REDACTED",
        "File": (root / "sub dir" / "app.py").as_posix(),
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 3.9,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": [],
        "Fingerprint": (root / "sub dir" / "app.py").as_posix() + ":github-pat:3",
    }
    report = gitleaks_scan(root, FakeGitleaks(report=[observed]))
    assert [(f.rule_id, f.path, f.line) for f in report.findings] == [
        ("gitleaks:github-pat", "sub dir/app.py", 3)
    ]


def test_relative_paths_are_resolved_against_the_root(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "x"})
    report = gitleaks_scan(root, FakeGitleaks(report=[leak("a.txt", line=1)]))
    assert [f.path for f in report.findings] == ["a.txt"]


def test_results_outside_scan_scope_are_ignored(make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"a.txt": "x", "node_modules/lib.js": "x"})
    entries = [
        leak(str(root / "a.txt")),
        leak(str(root / "node_modules" / "lib.js")),  # excluded by RepoSentinel
        leak(str(tmp_path / "elsewhere.txt")),  # outside the root entirely
    ]
    report = gitleaks_scan(root, FakeGitleaks(report=entries))
    assert [f.path for f in report.findings] == ["a.txt"]
    assert "2 outside RepoSentinel's scan scope were ignored" in report.checks[0].message


@pytest.mark.parametrize("empty_report", [[], "null"])
def test_no_leaks(make_repo: RepoFactory, empty_report: Any) -> None:
    report = gitleaks_scan(make_repo({"a.txt": "x"}), FakeGitleaks(0, report=empty_report))
    assert report.findings == ()
    assert report.outcome is Outcome.CLEAN


def test_invalid_line_numbers_are_dropped(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "x"})
    entries = [leak("a.txt", line=0, rule="r1"), {**leak("a.txt", rule="r2"), "StartLine": "7"}]
    report = gitleaks_scan(root, FakeGitleaks(report=entries))
    assert [f.line for f in report.findings] == [None, None]


def test_command_line_is_hardened(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "x"})
    fake = FakeGitleaks(0, report=[])
    gitleaks_scan(root, fake)
    ((argv, cwd, timeout),) = fake.calls
    assert argv[:3] == [str(FAKE_EXE), "dir", str(root)]  # files only, never `git` mode
    for flag in ("--redact=100", "--ignore-gitleaks-allow", "--no-banner"):
        assert flag in argv
    assert argv[argv.index("--exit-code") + 1] == str(LEAKS_EXIT_CODE)
    assert argv[argv.index("--report-format") + 1] == "json"
    assert not cwd.resolve().is_relative_to(root)  # never run inside the scanned repository
    assert fake.config_text == CONFIG_EXTENDING_DEFAULTS  # repo .gitleaks.toml is not used
    assert timeout > 0


@pytest.mark.parametrize(
    ("size", "expected"), [(1, "1"), (1024 * 1024, "1"), (5 * 1024 * 1024 + 1, "6")]
)
def test_size_limit_is_passed_in_megabytes(size: int, expected: str) -> None:
    argv = build_command(FAKE_EXE, Path("/repo").resolve(), Path("r.json"), Path("c.toml"), size)
    assert argv[argv.index("--max-target-megabytes") + 1] == expected


# --- failures -----------------------------------------------------------------------


def test_missing_gitleaks_is_skipped_and_scan_incomplete(make_repo: RepoFactory) -> None:
    check = GitleaksCheck(finder=lambda name, forbidden: None, runner=FakeGitleaks())
    report = run_scan(make_repo({"a.txt": "x"}), [check])
    (result,) = report.checks
    assert result.status is CheckStatus.SKIPPED
    assert "not found on PATH" in result.message
    assert report.outcome is Outcome.INCOMPLETE


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (
            FakeGitleaks(1, stderr=f"fatal: bad thing {synthetic.GITHUB_TOKEN}"),
            "exited with code 1",
        ),
        (FakeGitleaks(126), "8.19 or newer"),
        (FakeGitleaks(2, stderr=""), "no error output"),
        (FakeGitleaks(LEAKS_EXIT_CODE, report=None), "did not write a report"),
        (FakeGitleaks(LEAKS_EXIT_CODE, report="{not json"), "not valid JSON"),
        (FakeGitleaks(LEAKS_EXIT_CODE, report={"a": 1}), "expected a list"),
        (FakeGitleaks(LEAKS_EXIT_CODE, report=["text"]), "not an object"),
        (FakeGitleaks(LEAKS_EXIT_CODE, report=[{"File": "a.txt"}]), "missing RuleID"),
        (FakeGitleaks(0, report=[leak("a.txt")]), "reported no leaks but"),
    ],
)
def test_tool_failures_fail_the_check(
    make_repo: RepoFactory, fake: FakeGitleaks, message: str
) -> None:
    report = gitleaks_scan(make_repo({"a.txt": "x"}), fake)
    (result,) = report.checks
    assert result.status is CheckStatus.FAILED
    assert message in result.message
    assert synthetic.GITHUB_TOKEN not in result.message
    assert "bad thing" not in result.message  # the tool's own output is never shown
    assert report.outcome is Outcome.INCOMPLETE


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (subprocess.TimeoutExpired(cmd="gitleaks", timeout=1), "did not finish within"),
        (PermissionError(13, "Permission denied"), "could not start gitleaks: Permission denied"),
    ],
)
def test_timeouts_and_start_errors(make_repo: RepoFactory, error: Exception, message: str) -> None:
    def runner(argv: list[str], cwd: Path, timeout: float) -> ProcessResult:
        raise error

    report = gitleaks_scan(make_repo({"a.txt": "x"}), runner)
    assert report.checks[0].status is CheckStatus.FAILED
    assert message in report.checks[0].message


def test_cli_integration_without_gitleaks_exits_three(
    make_repo: RepoFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    result = CliRunner().invoke(
        cli.app, ["scan", str(make_repo({"a.txt": "x"})), "--integration", "gitleaks"]
    )
    assert result.exit_code == 3
    output = " ".join(result.stdout.split())  # table cells wrap at the terminal width
    assert "skipped" in output
    assert "not found on PATH" in output


# --- process helpers -----------------------------------------------------------------

EXE_NAME = "gitleaks.exe" if sys.platform == "win32" else "gitleaks"


def make_fake_executable(directory: Path, name: str = EXE_NAME) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"not a real program; never executed by these tests")
    path.chmod(0o755)
    return path


def test_find_executable_uses_absolute_path_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = make_fake_executable(tmp_path / "bin")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert find_executable("gitleaks", tmp_path / "repo") == tool.resolve()


def test_find_executable_ignores_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    make_fake_executable(repo)  # planted by a hostile repository
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", "." + ";" if sys.platform == "win32" else ".:")
    assert find_executable("gitleaks", tmp_path / "other") is None


def test_find_executable_rejects_tools_inside_scanned_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    make_fake_executable(repo / "tools")
    monkeypatch.setenv("PATH", str(repo / "tools"))
    assert find_executable("gitleaks", repo) is None


@pytest.mark.skipif(sys.platform != "win32", reason="batch files are a Windows concern")
def test_find_executable_ignores_batch_file_shims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_fake_executable(tmp_path / "bin", "gitleaks.cmd")
    make_fake_executable(tmp_path / "bin", "gitleaks.bat")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert find_executable("gitleaks", tmp_path / "repo") is None


def test_run_process_captures_exit_code_and_stderr(tmp_path: Path) -> None:
    code = "import sys; sys.stderr.write('problem'); sys.exit(3)"
    result = run_process([sys.executable, "-c", code], tmp_path, timeout=60)
    assert (result.returncode, result.stderr) == (3, "problem")


def test_run_process_enforces_timeout(tmp_path: Path) -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        run_process([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, timeout=0.5)


@pytest.mark.parametrize(
    ("reported", "expected"),
    [("src/a.py", "src/a.py"), ("../outside.txt", None), (".", None)],
)
def test_relative_path(tmp_path: Path, reported: str, expected: str | None) -> None:
    assert relative_path(reported, tmp_path.resolve()) == expected


@pytest.mark.skipif(sys.platform != "win32", reason="Windows paths are case-insensitive")
def test_relative_path_is_case_insensitive_on_windows(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    assert relative_path(str(root).upper() + "\\Src\\A.py", root) == "Src/A.py"


def test_find_executable_rejects_path_folder_inside_repository_even_if_linked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Found in the audit: a PATH folder inside the scanned repository that is a
    # link to an outside folder was accepted, because only the resolved
    # program location was checked.
    outside_bin = tmp_path / "outside-bin"
    make_fake_executable(outside_bin)
    repo = tmp_path / "repo"
    repo.mkdir()
    if sys.platform == "win32":
        create_junction(outside_bin, repo / "tools")
    else:
        (repo / "tools").symlink_to(outside_bin, target_is_directory=True)
    monkeypatch.setenv("PATH", str(repo / "tools"))
    assert find_executable("gitleaks", repo) is None
    # The same program is accepted when PATH points at it directly.
    monkeypatch.setenv("PATH", str(outside_bin))
    assert find_executable("gitleaks", repo) == (outside_bin / EXE_NAME).resolve()


# --- version check (added in the October 2026 security audit) ----------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("8.28.0\n", (8, 28, 0)),
        ("v8.19.0", (8, 19, 0)),
        ("gitleaks version 10.0.1", (10, 0, 1)),
        ("version is set by build process", None),  # source builds print a placeholder
        ("", None),
    ],
)
def test_parse_version(output: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_version(output) == expected


def test_too_old_gitleaks_is_skipped(make_repo: RepoFactory) -> None:
    fake = FakeGitleaks(0, report=[], version_output="8.18.4\n")
    report = gitleaks_scan(make_repo({"a.txt": "x"}), fake)
    (result,) = report.checks
    assert result.status is CheckStatus.SKIPPED
    assert "8.18.4 is too old" in result.message and "8.19.0 or newer" in result.message
    assert fake.calls == []  # the scan itself is never attempted
    assert report.outcome is Outcome.INCOMPLETE


def test_minimum_version_is_accepted_and_reported(make_repo: RepoFactory) -> None:
    fake = FakeGitleaks(0, report=[], version_output="v8.19.0\n")
    report = gitleaks_scan(make_repo({"a.txt": "x"}), fake)
    assert report.checks[0].status is CheckStatus.COMPLETED
    assert report.checks[0].message.startswith("Gitleaks 8.19.0: 0 result(s)")


@pytest.mark.parametrize("version_output", ["version is set by build process", ""])
def test_unknown_version_still_runs_and_says_so(
    make_repo: RepoFactory, version_output: str
) -> None:
    fake = FakeGitleaks(0, report=[], version_output=version_output)
    report = gitleaks_scan(make_repo({"a.txt": "x"}), fake)
    assert report.checks[0].status is CheckStatus.COMPLETED
    assert "version unknown" in report.checks[0].message
    assert len(fake.calls) == 1


def test_version_command_runs_from_temporary_directory(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "x"})
    seen: list[tuple[list[str], Path]] = []

    def runner(argv: list[str], cwd: Path, timeout: float) -> ProcessResult:
        seen.append((argv, cwd))
        if argv[1:] == ["version"]:
            return ProcessResult(0, "", "8.28.0")
        Path(argv[argv.index("--report-path") + 1]).write_text("[]", encoding="utf-8")
        return ProcessResult(0, "")

    gitleaks_scan(root, runner)
    assert [argv[1] for argv, _ in seen] == ["version", "dir"]
    assert all(not cwd.resolve().is_relative_to(root) for _, cwd in seen)


def test_run_process_captures_stdout(tmp_path: Path) -> None:
    result = run_process([sys.executable, "-c", "print('8.28.0')"], tmp_path, timeout=60)
    assert result.stdout.strip() == "8.28.0"
