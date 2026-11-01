"""Regression tests for repository text leaking into reports.

Before the fix, GitHub Actions step names, job IDs, expression text and YAML
values were copied into finding summaries and evidence, so a credential that
the redaction patterns do not recognise (an unknown format, or a known token
glued to other text) appeared in scan reports. The rule now is: finding text
is built only from RepoSentinel's vocabulary, positions and line numbers.

Every test runs the real CLI and inspects the terminal, JSON and HTML output.
All values are synthetic and assembled at run time.
"""

from __future__ import annotations

import json
import string
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reposentinel import cli
from reposentinel.engine import describe_exception
from tests import synthetic
from tests.conftest import RepoFactory

runner = CliRunner()
BACKSLASH = chr(92)
TOKEN = synthetic.GITHUB_TOKEN  # a recognised format
# An unrecognised credential format: no pattern can know it is secret.
UNKNOWN = "Kq7-" + "unrecognised" + "-Pw9"
GLUED = "x" + TOKEN  # a known token glued to a word character: no word boundary
STEP_NAME_MARKER = "deploy" + "-with-pw"
HTML_PROBE = "<script>alert(1)</script>"


def yaml_escape(code_point: int) -> str:
    """A YAML double-quoted escape such as \\u202e, built without a literal backslash."""
    return f"{BACKSLASH}u{code_point:04x}"


# A step name carrying every kind of hostile text: a known token, an unknown
# credential, a glued token, HTML, a terminal escape (ESC), a bidi override
# (U+202E) and a zero-width space (U+200B).
STEP_NAME = (
    f"{STEP_NAME_MARKER} {UNKNOWN} {GLUED} {TOKEN} {HTML_PROBE} & 'q' "
    f"{yaml_escape(0x1B)}[31m {yaml_escape(0x202E)} {yaml_escape(0x200B)}"
)
JOB_ID = f"build-{UNKNOWN}-{GLUED}"

WORKFLOW = f"""\
on: [issues, pull_request_target]
permissions: write-all
jobs:
  "{JOB_ID}":
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - name: "{STEP_NAME}"
        uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}-{UNKNOWN}
      - name: "{STEP_NAME}"
        uses: some-org/deploy-action@{UNKNOWN}
      - name: "{STEP_NAME}"
        run: |
          echo "${{{{ github.event.issue.title || {UNKNOWN} }}}}"
          echo "${{{{ github.event.commits[{UNKNOWN}].message }}}}"
"""
# Undefined YAML aliases make PyYAML quote the alias name in its error text.
BROKEN_WORKFLOW = f"on: push\njobs: *{UNKNOWN}\nother: *{GLUED}\n"

# Strings that must never appear in any output.
FORBIDDEN = (TOKEN, UNKNOWN, STEP_NAME_MARKER, "alert(1)", "build-Kq7")
RAW_CONTROLS = (chr(0x1B), chr(0x202E), chr(0x200B), chr(7))


def invoke(*args: str | Path):
    return runner.invoke(cli.app, [str(arg) for arg in args])


@pytest.fixture
def hostile_repo(make_repo: RepoFactory) -> Path:
    return make_repo(
        {
            ".github/workflows/ci.yml": WORKFLOW,
            ".github/workflows/broken.yml": BROKEN_WORKFLOW,
            "app.py": "x = 1\n",
        }
    )


def scan_outputs(root: Path, tmp_path: Path, name: str) -> dict[str, str]:
    """Run the real CLI in every format; return {format: output}."""
    json_path, html_path = tmp_path / f"{name}.json", tmp_path / f"{name}.html"
    text = invoke("scan", root, "--no-color")
    assert text.exit_code == 3, text.output  # the broken workflow makes the scan incomplete
    assert invoke("scan", root, "-f", "json", "-o", json_path).exit_code == 3
    assert invoke("scan", root, "-f", "html", "-o", html_path).exit_code == 3
    return {
        "text": text.output,
        "json": json_path.read_text(encoding="utf-8"),
        "html": html_path.read_text(encoding="utf-8"),
    }


def assert_no_leak(outputs: dict[str, str]) -> None:
    for fmt, output in outputs.items():
        for value in FORBIDDEN:
            assert value not in output, (fmt, value)
        for control in RAW_CONTROLS:
            assert control not in output, (fmt, hex(ord(control)))


def test_findings_are_still_detected(hostile_repo: Path, tmp_path: Path) -> None:
    outputs = scan_outputs(hostile_repo, tmp_path, "scan")
    report = json.loads(outputs["json"])
    rules = sorted(f["rule_id"] for f in report["findings"])
    assert rules == [
        "RS-GHA-001",  # github.event.issue.title
        "RS-GHA-001",  # github.event.commits[*].message
        "RS-GHA-002",
        "RS-GHA-003",
        "RS-GHA-004",  # workflow level
        "RS-GHA-004",  # job level
        "RS-SEC-004",  # the recognised token, in each of the three step-name lines
        "RS-SEC-004",
        "RS-SEC-004",
    ]
    by_rule = {f["rule_id"]: f for f in report["findings"]}
    assert by_rule["RS-GHA-002"]["evidence"] == "ref: refers to github.event.pull_request.head.*"
    assert (
        by_rule["RS-GHA-003"]["evidence"]
        == "uses: some-org/deploy-action@<tag or branch not shown>"
    )
    assert by_rule["RS-SEC-004"]["evidence"] == "ghp_[REDACTED]"
    summaries = {f["summary"] for f in report["findings"] if f["rule_id"] == "RS-GHA-001"}
    assert summaries == {
        "Job 1, step 3: github.event.issue.title is expanded directly into a shell script.",
        "Job 1, step 3: github.event.commits[*].message is expanded directly into a shell script.",
    }
    evidence = {f["evidence"] for f in report["findings"] if f["rule_id"] == "RS-GHA-001"}
    assert evidence == {
        "${{ ... github.event.issue.title ... }}",
        "${{ github.event.commits[*].message }}",
    }


def test_no_repository_text_leaks_from_a_scan(hostile_repo: Path, tmp_path: Path) -> None:
    outputs = scan_outputs(hostile_repo, tmp_path, "scan")
    assert_no_leak(outputs)
    # The broken workflow is reported with its line, without the alias names.
    coverage = json.loads(outputs["json"])["coverage"]
    (broken,) = [c for c in coverage if c["path"] == ".github/workflows/broken.yml"]
    assert broken["reason"] == "unparseable"
    assert broken["detail"].startswith("invalid YAML at line ")
    assert "'...'" in broken["detail"]


def test_no_repository_text_leaks_from_a_comparison(hostile_repo: Path, tmp_path: Path) -> None:
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    invoke("scan", hostile_repo, "-f", "json", "-o", before)
    workflow = hostile_repo / ".github/workflows/ci.yml"
    workflow.write_text(WORKFLOW.replace("permissions: write-all\njobs", "jobs"), "utf-8")
    invoke("scan", hostile_repo, "-f", "json", "-o", after)
    page = tmp_path / "comparison.html"
    outputs = {
        "text": invoke("compare", before, after, "--no-color").output,
        "json": invoke("compare", before, after, "-f", "json").output,
    }
    assert invoke("compare", before, after, "-f", "html", "-o", page).exit_code == 3
    outputs["html"] = page.read_text(encoding="utf-8")
    assert "Not detected on re-check" in outputs["text"]  # the workflow-level write-all
    assert_no_leak(outputs)


def test_compare_shows_trusted_rule_text_not_report_text(
    hostile_repo: Path, tmp_path: Path
) -> None:
    # A report edited (or produced) by something else: an unrecognised secret in
    # the free-text fields of a known rule. compare shows RepoSentinel's own title
    # and fix text for known rules, and never shows summaries.
    report = tmp_path / "report.json"
    invoke("scan", hostile_repo, "-f", "json", "-o", report)
    data = json.loads(report.read_text(encoding="utf-8"))
    for finding in data["findings"]:
        for key in ("title", "summary", "remediation"):
            finding[key] = f"{key} {UNKNOWN}"
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(data), encoding="utf-8")
    page = tmp_path / "edited.html"
    outputs = {
        "text": invoke("compare", edited, edited, "--no-color").output,
        "json": invoke("compare", edited, edited, "-f", "json").output,
    }
    invoke("compare", edited, edited, "-f", "html", "-o", page)
    outputs["html"] = page.read_text(encoding="utf-8")
    assert_no_leak(outputs)
    assert "Untrusted input expanded inside a script" in outputs["json"]


def test_exception_text_is_never_reported() -> None:
    text = describe_exception(RuntimeError(f"could not parse {UNKNOWN} {GLUED}"))
    assert text.startswith("RuntimeError (details withheld")
    assert UNKNOWN not in text and TOKEN not in text
    assert describe_exception(PermissionError(13, "Permission denied", UNKNOWN)).startswith(
        "PermissionError (Permission denied)"
    )


def test_step_names_with_only_safe_text_are_not_shown_either(make_repo: RepoFactory) -> None:
    # The rule is structural, not a guess about what looks secret: even a
    # harmless name is not copied. Positions and the line locate the step.
    plain = "Greet the " + string.ascii_lowercase[:5]
    workflow = WORKFLOW.replace(f'"{STEP_NAME}"', f'"{plain}"')
    result = invoke("scan", make_repo({".github/workflows/ci.yml": workflow}), "--no-color")
    assert plain not in result.output
    assert "Job 1, step 3" in " ".join(result.output.split())


# --- file content and names: what is hidden, and what stays visible ------------


def test_url_credentials_and_hostile_names_across_outputs(
    make_repo: RepoFactory, tmp_path: Path
) -> None:
    internal_host = "billing-db." + "corp" + ".internal"
    user, password = "svc_" + "billing", "Zx9" + "-pw-" + "Qm2"
    odd_scheme = "corp" + "vault"
    hostile_name = f"notes {chr(0x202E)}gpj.env"  # bidi override in a file name
    root = make_repo(
        {
            "config.ini": (
                f"db = postgres://{user}:{password}@{internal_host}:5432/app\n"
                f"vault = {odd_scheme}://{user}:{password}@{internal_host}/\n"
                f"glued = x{TOKEN}\n"  # glued token: not detected, and never echoed
                f"other = {UNKNOWN}\n"  # unknown format: not detected, and never echoed
            ),
            hostile_name: "A=1\n",
        }
    )
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    outputs = scan_outputs_ok(root, tmp_path)
    invoke("scan", root, "-f", "json", "-o", before)
    (root / "config.ini").write_text("db = env\n", encoding="utf-8")
    invoke("scan", root, "-f", "json", "-o", after)
    page = tmp_path / "comparison.html"
    invoke("compare", before, after, "-f", "html", "-o", page)
    outputs["compare-text"] = invoke("compare", before, after, "--no-color").output
    outputs["compare-json"] = invoke("compare", before, after, "-f", "json").output
    outputs["compare-html"] = page.read_text(encoding="utf-8")
    outputs["error"] = invoke("compare", before, root / "config.ini").output  # invalid input

    for fmt, output in outputs.items():
        for hidden in (internal_host, "corp.internal", user, password, odd_scheme, TOKEN, UNKNOWN):
            assert hidden not in output, (fmt, hidden)
        assert chr(0x202E) not in output, fmt  # never a raw bidi override
    report = json.loads(before.read_text(encoding="utf-8"))
    rules = sorted(f["rule_id"] for f in report["findings"])
    assert rules == ["RS-HYG-001", "RS-SEC-005", "RS-SEC-005"]  # still detected
    evidence = sorted(f["evidence"] for f in report["findings"] if f["rule_id"] == "RS-SEC-005")
    assert evidence == ["[REDACTED]://[REDACTED]@[REDACTED]", "postgres://[REDACTED]@[REDACTED]"]
    # Intentionally visible: the location. The file name is shown (as a visible
    # code in text and HTML; exactly, JSON-escaped, in the JSON report).
    shown = "notes " + BACKSLASH + "u202egpj.env"  # the visible code, not the character
    text = " ".join(outputs["text"].split())  # undo terminal line wrapping
    assert shown in text and "config.ini" in text
    assert shown in outputs["html"]


def scan_outputs_ok(root: Path, tmp_path: Path) -> dict[str, str]:
    json_path, html_path = tmp_path / "s.json", tmp_path / "s.html"
    text = invoke("scan", root, "--no-color")
    assert text.exit_code == 1, text.output
    invoke("scan", root, "-f", "json", "-o", json_path)
    invoke("scan", root, "-f", "html", "-o", html_path)
    return {
        "text": text.output,
        "json": json_path.read_text(encoding="utf-8"),
        "html": html_path.read_text(encoding="utf-8"),
    }
