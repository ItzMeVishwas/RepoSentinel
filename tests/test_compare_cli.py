"""``reposentinel compare``: the full journey through the CLI (AC-14, AC-17, AC-20).

Reports are made with the real ``scan`` command, saved as JSON, and compared
with the real ``compare`` command, the way a user would do it.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reposentinel import cli, report_loader
from reposentinel.compare import CREDENTIAL_REMINDER, SCOPE_STATEMENT
from reposentinel.reporting.compare_common import (
    SECTION_DETECTED,
    SECTION_NO_LONGER,
    SECTION_NOT_EXAMINED,
    SECTION_REMINDERS,
    SECTION_UNKNOWN,
)
from tests import synthetic
from tests.conftest import RepoFactory
from tests.test_cli import plain

runner = CliRunner()
SECTIONS: tuple[str, ...] = (SECTION_DETECTED, SECTION_UNKNOWN, SECTION_NOT_EXAMINED)
SECTIONS += (SECTION_REMINDERS, SECTION_NO_LONGER, "Checks", "Summary")
TOKEN_LINE = f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n'
ESC = chr(0x1B)


def invoke(*args: str | Path):
    return runner.invoke(cli.app, [str(arg) for arg in args])


def flat(text: str) -> str:
    """Terminal output with Rich's line wrapping undone, for phrase checks."""
    return " ".join(text.split())


def save_scan(root: Path, report: Path, *extra: str) -> None:
    result = invoke("scan", root, "--format", "json", "--output", report, *extra)
    assert result.exit_code in (0, 1, 3), result.output
    assert report.is_file()


@pytest.fixture
def journey(make_repo: RepoFactory, tmp_path: Path) -> tuple[Path, Path]:
    """Before: two tokens, an .env file and a workflow. After: one token fixed,
    .env deleted, one token still there, and a new token added."""
    root = make_repo(
        {
            "config.py": TOKEN_LINE,
            "keep.py": f'AWS = "{synthetic.AWS_KEY_ID}"\n',
            ".env": "A=1\n",
        }
    )
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    save_scan(root, before)
    (root / "config.py").write_text("TOKEN = load_from_environment()\n")
    (root / ".env").unlink()
    (root / "new.py").write_text(TOKEN_LINE)
    save_scan(root, after)
    return before, after


# --- the user journey -----------------------------------------------------------


def test_help_lists_compare_and_its_options() -> None:
    # A fixed width: in very narrow terminals Rich shortens long option names.
    wide = {"COLUMNS": "120"}
    assert "compare" in plain(runner.invoke(cli.app, ["--help"], env=wide).stdout)
    text = plain(runner.invoke(cli.app, ["compare", "--help"], env=wide).stdout)
    for option in ("--format", "--output", "--fail-on", "--different-roots", "--no-color"):
        assert option in text


def test_text_comparison(journey: tuple[Path, Path]) -> None:
    before, after = journey
    result = invoke("compare", before, after, "--no-color")
    assert result.exit_code == 1  # a token is still detected and one is new
    out = flat(result.stdout)
    for section in SECTIONS:
        assert section in out
    assert "2 findings are no longer detected, 2 remain, 0 unknown." in out
    assert SCOPE_STATEMENT in out
    assert "Not detected on re-check" in out and "Not detected: file removed" in out
    assert "[New]" in out and "[Still detected]" in out
    assert "If this was a real credential, treat it as compromised" in out
    assert "Of 3 tracked findings in before.json" in out
    assert "Exit code 1" in out
    for value in synthetic.SECRET_VALUES:
        assert value not in out


def test_fail_on_threshold_and_never(journey: tuple[Path, Path]) -> None:
    before, after = journey
    assert invoke("compare", before, after, "--fail-on", "high").exit_code == 1  # new token
    assert invoke("compare", before, after, "--fail-on", "never").exit_code == 0


def test_only_lower_severity_left_gives_zero(make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "keep.py": f'AWS = "{synthetic.AWS_KEY_ID}"\n'})
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    save_scan(root, before)
    (root / "config.py").write_text("x = 1\n")
    save_scan(root, after)
    assert invoke("compare", before, after, "--fail-on", "high").exit_code == 0
    assert invoke("compare", before, after, "--fail-on", "medium").exit_code == 1


def test_unknown_wins_over_findings_and_never(make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "keep.py": f'AWS = "{synthetic.AWS_KEY_ID}"\n'})
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    save_scan(root, before, "--max-file-size-kb", "1")
    (root / "config.py").write_text(TOKEN_LINE + "#" * 2000 + "\n")  # now too large
    save_scan(root, after, "--max-file-size-kb", "1")
    for fail_on in ("low", "high", "never"):
        result = invoke("compare", before, after, "--fail-on", fail_on, "--no-color")
        assert result.exit_code == 3, fail_on
    assert "Not re-checked" in flat(result.stdout)
    assert "larger than the size limit" in flat(result.stdout)


def test_skipped_integration_in_new_scan_gives_three(
    make_repo: RepoFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No Gitleaks binary is downloaded or run: PATH is emptied, so the
    # integration is skipped ("not found on PATH") in the new scan.
    monkeypatch.setenv("PATH", "")
    root = make_repo({"config.py": "x = 1\n"})
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    save_scan(root, before)
    save_scan(root, after, "--integration", "gitleaks")
    result = invoke("compare", before, after, "--no-color")
    assert result.exit_code == 3
    assert "skipped in the new scan" in flat(result.stdout)


def test_json_and_html_formats(journey: tuple[Path, Path], tmp_path: Path) -> None:
    before, after = journey
    data = json.loads(invoke("compare", before, after, "--format", "json").stdout)
    assert data["comparison_schema_version"] == "1.0"
    assert data["scope"] == SCOPE_STATEMENT
    assert data["exit_code"] == 1
    assert data["counts"]["not_detected_on_recheck"] == 1
    reminders = [f for f in data["findings"] if f["credential_reminder"]]
    assert reminders and reminders[0]["credential_reminder"] == CREDENTIAL_REMINDER

    page = tmp_path / "comparison.html"
    result = invoke("compare", before, after, "--format", "html", "--output", page)
    assert result.exit_code == 1
    assert result.stdout == ""  # written to the file only
    # The terminal message is wrapped at the console width; compare it unwrapped.
    assert "Wrote html comparison" in flat(result.stderr)
    assert SCOPE_STATEMENT in flat(result.stderr)
    html = page.read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    for section in SECTIONS:
        assert section in html
    assert "<script" not in html.lower() and "href=" not in html.lower()
    assert "http://" not in html and "https://" not in html


@pytest.mark.parametrize("columns", ["40", "80", "200"])
def test_written_message_keeps_the_whole_scope_at_any_width(
    journey: tuple[Path, Path], tmp_path: Path, columns: str
) -> None:
    # Regression: the scope statement is wrapped with the rest of the message,
    # so where the line breaks fall depends on the width and on the length of
    # the output path; nothing of it may be lost or cut.
    before, after = journey
    page = tmp_path / "comparison.html"
    result = runner.invoke(
        cli.app,
        ["compare", str(before), str(after), "--format", "html", "--output", str(page)],
        env={"COLUMNS": columns},
    )
    assert result.exit_code == 1
    message = flat(result.stderr)
    assert SCOPE_STATEMENT in message
    assert message.startswith("Wrote html comparison to")


def test_fix_text_is_shown_once_per_rule(make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"a.py": TOKEN_LINE, "b.py": TOKEN_LINE})
    report = tmp_path / "r.json"
    save_scan(root, report)
    page = tmp_path / "r.html"
    invoke("compare", report, report, "--format", "html", "--output", page)
    for output in (flat(invoke("compare", report, report).stdout), page.read_text("utf-8")):
        assert output.count("Revoke the token in GitHub") == 1
        assert output.count("RS-SEC-004</code> above.") + output.count("RS-SEC-004 above.") == 1


def test_text_output_file(journey: tuple[Path, Path], tmp_path: Path) -> None:
    before, after = journey
    target = tmp_path / "comparison.txt"
    assert invoke("compare", before, after, "--output", target).exit_code == 1
    text = target.read_text(encoding="utf-8")
    assert ESC not in text  # no colour codes in files
    assert SCOPE_STATEMENT in flat(text) and "Exit code 1" in text


def test_compare_writes_nothing_without_output(journey: tuple[Path, Path]) -> None:
    before, after = journey
    folder = before.parent
    listing = sorted(p.name for p in folder.iterdir())
    for fmt in ("text", "json", "html"):
        invoke("compare", before, after, "--format", fmt)
    assert sorted(p.name for p in folder.iterdir()) == listing


def test_compare_makes_no_network_connections(
    journey: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("RepoSentinel attempted a network operation")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, no_network)
    before, after = journey
    for fmt in ("text", "json", "html"):
        assert invoke("compare", before, after, "--format", fmt).exit_code == 1


def test_compare_runs_as_a_module(journey: tuple[Path, Path]) -> None:
    before, after = journey
    completed = subprocess.run(  # noqa: S603 - fixed arguments, this interpreter
        [sys.executable, "-m", "reposentinel", "compare", str(before), str(after), "--no-color"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 1
    assert SCOPE_STATEMENT in flat(completed.stdout)


# --- invalid input: exit code 2 and no comparison output (AC-14, AC-20 g) --------


def _break(report: Path, change: dict[str, Any]) -> Path:
    data = json.loads(report.read_text(encoding="utf-8"))
    data.update(change)
    broken = report.with_name("broken.json")
    broken.write_text(json.dumps(data), encoding="utf-8")
    return broken


@pytest.mark.parametrize(
    "case",
    ["missing", "folder", "not-json", "schema-1.0", "schema-9.0", "wrong-tool", "bad-finding"],
)
def test_invalid_reports_give_two_and_no_output(journey: tuple[Path, Path], case: str) -> None:
    before, after = journey
    bad = {
        "missing": before.with_name("missing.json"),
        "folder": before.parent,
        "schema-1.0": _break(before, {"schema_version": "1.0"}),
        "schema-9.0": _break(before, {"schema_version": "9.0"}),
        "wrong-tool": _break(before, {"tool": {"name": "other", "version": "1"}}),
        "bad-finding": _break(before, {"findings": [{"rule_id": "x"}]}),
    }.get(case)
    if case == "not-json":
        bad = before.with_name("not.json")
        bad.write_text("{ not json", encoding="utf-8")
    assert bad is not None
    for args in ((bad, after), (before, bad)):
        result = invoke("compare", *args, "--format", "json")
        assert result.exit_code == 2, (case, result.output)
        assert result.stdout == ""
        assert result.stderr.startswith("Error: ")


def test_oversized_report_gives_two(
    journey: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_loader, "MAX_REPORT_BYTES", 100)
    before, after = journey
    result = invoke("compare", before, after)
    assert result.exit_code == 2
    assert "larger than" in flat(result.stderr) and result.stdout == ""


def test_different_roots(make_repo: RepoFactory, tmp_path: Path) -> None:
    first = make_repo({"config.py": TOKEN_LINE})
    second = tmp_path / "copy"
    second.mkdir()
    (second / "config.py").write_text(TOKEN_LINE)
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    save_scan(first, before)
    save_scan(second, after)
    refused = invoke("compare", before, after)
    assert refused.exit_code == 2 and refused.stdout == ""
    assert "--different-roots" in refused.stderr
    accepted = invoke("compare", before, after, "--different-roots", "--no-color")
    assert accepted.exit_code == 1
    assert "Declared the same repository by you" in flat(accepted.stdout)
    assert "RepoSentinel cannot confirm this" in flat(accepted.stdout)


def test_output_must_not_overwrite_an_input(journey: tuple[Path, Path]) -> None:
    before, after = journey
    original = before.read_bytes()
    for target in (before, after):
        result = invoke("compare", before, after, "--output", target)
        assert result.exit_code == 2
        assert "overwrite the input report" in result.stderr
    assert before.read_bytes() == original


def test_output_to_a_folder_gives_two(journey: tuple[Path, Path]) -> None:
    before, after = journey
    assert invoke("compare", before, after, "--output", before.parent).exit_code == 2


def test_error_messages_from_reports_are_sanitised(journey: tuple[Path, Path]) -> None:
    before, after = journey
    data = json.loads(before.read_text(encoding="utf-8"))
    hostile = f"{ESC}[31m{synthetic.GITHUB_TOKEN}"
    data["scan_config"]["rule_versions"][hostile] = 0  # invalid, and quoted in the error
    broken = before.with_name("hostile.json")
    broken.write_text(json.dumps(data), encoding="utf-8")
    result = invoke("compare", broken, after)
    assert result.exit_code == 2
    assert ESC not in result.stderr
    assert synthetic.GITHUB_TOKEN not in result.stderr


# --- hostile content in a report is displayed safely ----------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>" + ESC + "]0;pwn" + chr(7)


def _hostile_pair(journey: tuple[Path, Path]) -> tuple[Path, Path]:
    """Inject hostile text and a fake credential into every displayed field."""
    before, after = journey
    pair = []
    for report in (before, after):
        data = json.loads(report.read_text(encoding="utf-8"))
        for finding in data["findings"]:
            for key in ("title", "summary", "evidence", "remediation"):
                finding[key] = f"{HOSTILE} {synthetic.GITHUB_TOKEN}"
        for check in data["checks"]:
            check["name"] = HOSTILE
        hostile = report.with_name("hostile-" + report.name)
        hostile.write_text(json.dumps(data), encoding="utf-8")
        pair.append(hostile)
    return pair[0], pair[1]


def test_hostile_text_is_escaped_in_html(journey: tuple[Path, Path], tmp_path: Path) -> None:
    before, after = _hostile_pair(journey)
    page = tmp_path / "hostile.html"
    assert invoke("compare", before, after, "--format", "html", "-o", page).exit_code == 1
    html = page.read_text(encoding="utf-8")
    assert "<script" not in html.lower() and "<img" not in html.lower()
    assert "&lt;script&gt;" in html
    assert ESC not in html and chr(7) not in html
    assert synthetic.GITHUB_TOKEN not in html


def test_hostile_text_is_neutralised_in_text_and_json(journey: tuple[Path, Path]) -> None:
    before, after = _hostile_pair(journey)
    text = invoke("compare", before, after, "--no-color").stdout
    assert ESC not in text and chr(7) not in text
    assert synthetic.GITHUB_TOKEN not in text
    raw = invoke("compare", before, after, "--format", "json").stdout
    # JSON keeps strings as data (escaped, like the scan report); the file itself
    # is plain ASCII with no raw control characters, and nothing is unredacted.
    assert raw.isascii() and synthetic.GITHUB_TOKEN not in raw
    assert not re.search(r"[\x00-\x08\x0b-\x1f]", raw)
