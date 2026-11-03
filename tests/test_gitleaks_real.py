"""The Gitleaks integration against a real Gitleaks release.

These tests run only when REPOSENTINEL_GITLEAKS_DIR names a folder that
contains a Gitleaks executable obtained with scripts/fetch_gitleaks.py (a
pinned release whose SHA-256 is checked). Otherwise they are skipped, unless
REPOSENTINEL_REQUIRE_GITLEAKS_TESTS=1 (set in CI), which makes a missing
binary a failure. They check what tests/test_integrations.py can only
simulate: the real command line, report format, paths, line numbers,
redaction and exit codes.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from reposentinel.engine import run_scan
from reposentinel.integrations.gitleaks import MINIMUM_VERSION, GitleaksCheck, parse_version
from reposentinel.integrations.process import run_process
from reposentinel.models import CheckStatus, Outcome, ScanReport
from reposentinel.reporting import render_json
from tests import synthetic
from tests.conftest import RepoFactory

TOOL_DIR = os.environ.get("REPOSENTINEL_GITLEAKS_DIR", "")
REQUIRED = os.environ.get("REPOSENTINEL_REQUIRE_GITLEAKS_TESTS") == "1"
EXECUTABLE = Path(TOOL_DIR) / ("gitleaks.exe" if sys.platform == "win32" else "gitleaks")

if not (TOOL_DIR and EXECUTABLE.is_file()):
    if REQUIRED:
        raise RuntimeError(
            "REPOSENTINEL_REQUIRE_GITLEAKS_TESTS=1 but REPOSENTINEL_GITLEAKS_DIR does not "
            "contain a gitleaks executable (run scripts/fetch_gitleaks.py)"
        )
    pytest.skip("no real Gitleaks (set REPOSENTINEL_GITLEAKS_DIR)", allow_module_level=True)

TOKEN = synthetic.GITLEAKS_GITHUB_TOKEN


@pytest.fixture(autouse=True)
def gitleaks_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(EXECUTABLE.parent.resolve()))


def gitleaks_report(root: Path) -> ScanReport:
    return run_scan(root, [GitleaksCheck()])


def leak_files() -> dict[str, str | bytes]:
    return {
        "sub dir/app.py": f'# line 1\n# line 2\nTOKEN = "{TOKEN}"\n',
        "crlf.py": f'# 1\r\n# 2\r\n# 3\r\nTOKEN = "{TOKEN}"\r\n'.encode(),
        "allow.py": f'TOKEN = "{TOKEN}"  # gitleaks:allow\n',
        # A scanned repository's own configuration must not switch rules off.
        ".gitleaks.toml": '[extend]\nuseDefault = true\n[allowlist]\npaths = [".*"]\n',
    }


def test_version_output_is_understood() -> None:
    result = run_process([str(EXECUTABLE), "version"], EXECUTABLE.parent, 30)
    assert result.returncode == 0
    version = parse_version(result.stdout)
    assert version is not None and version >= MINIMUM_VERSION


def test_results_are_imported_with_relative_paths_and_lines(make_repo: RepoFactory) -> None:
    report = gitleaks_report(make_repo(leak_files()))
    (check,) = report.checks
    assert check.status is CheckStatus.COMPLETED, check.message
    assert check.message.startswith("Gitleaks 8.") and "3 result(s) imported" in check.message
    # Relative POSIX paths even on Windows (Gitleaks writes absolute paths
    # with '/'), the 1-based line numbers Gitleaks reports (CRLF included),
    # gitleaks:allow ignored and the repository's .gitleaks.toml not used.
    assert sorted((f.rule_id, f.path, f.line) for f in report.findings) == [
        ("gitleaks:github-pat", "allow.py", 1),
        ("gitleaks:github-pat", "crlf.py", 4),
        ("gitleaks:github-pat", "sub dir/app.py", 3),
    ]
    output = render_json(report)
    assert TOKEN not in output
    assert TOKEN[4:12] not in output  # not even part of the random section


def test_clean_folder_is_a_clean_scan(make_repo: RepoFactory) -> None:
    report = gitleaks_report(make_repo({"app.py": "print('hello')\n"}))
    (check,) = report.checks
    assert check.status is CheckStatus.COMPLETED, check.message
    assert "0 result(s) imported" in check.message
    assert report.outcome is Outcome.CLEAN


def test_gitleaks_inside_the_scanned_folder_is_never_run(
    make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo({"app.py": f'TOKEN = "{TOKEN}"\n'})
    planted = root / "bin"
    planted.mkdir()
    shutil.copy2(EXECUTABLE, planted / EXECUTABLE.name)
    monkeypatch.setenv("PATH", str(planted))
    (check,) = gitleaks_report(root).checks
    assert check.status is CheckStatus.SKIPPED


def test_repository_gitleaksignore_needs_the_absolute_scan_path(make_repo: RepoFactory) -> None:
    # Observed with Gitleaks 8.30.1 (docs/integrations.md, "Known gaps"): in
    # directory mode a .gitleaksignore inside the scanned folder is honoured,
    # but its entries must name the absolute path the folder is scanned from.
    root = make_repo(leak_files())
    (root / ".gitleaksignore").write_text(
        "sub dir/app.py:github-pat:3\ngithub-pat\n", encoding="utf-8"
    )
    assert len(gitleaks_report(root).findings) == 3  # relative entries do nothing
    absolute = (root / "sub dir" / "app.py").resolve().as_posix()
    (root / ".gitleaksignore").write_text(f"{absolute}:github-pat:3\n", encoding="utf-8")
    assert sorted(str(f.path) for f in gitleaks_report(root).findings) == ["allow.py", "crlf.py"]


def test_exit_codes_match_the_adapter(tmp_path: Path) -> None:
    def gitleaks(*args: str) -> int:
        return run_process([str(EXECUTABLE), *args], tmp_path, 120).returncode

    (tmp_path / "clean").mkdir()
    (tmp_path / "clean" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    report = tmp_path / "clean.json"
    common = ["--report-format", "json", "--exit-code", "42", "--no-banner", "--no-color"]
    assert gitleaks("dir", str(tmp_path / "clean"), "--report-path", str(report), *common) == 0
    assert json.loads(report.read_text(encoding="utf-8")) in ([], None)
    assert gitleaks("dir", str(tmp_path / "clean"), "--no-such-option") == 126
    missing = tmp_path / "missing.json"
    assert (
        gitleaks("dir", str(tmp_path / "does-not-exist"), "--report-path", str(missing), *common)
        == 1
    )
