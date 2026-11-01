"""Engine behaviour: isolation of failing checks, outcomes, ordering and exit codes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest

from reposentinel.checks import Check, CheckOutput, CheckSkipped, default_checks
from reposentinel.context import ScanContext
from reposentinel.engine import ExitCode, exit_code_for, run_scan
from reposentinel.models import (
    SEVERITY_ORDER,
    CheckResult,
    CheckStatus,
    Confidence,
    CoverageIssue,
    CoverageReason,
    Finding,
    Outcome,
    Rule,
    ScanReport,
    Severity,
)
from reposentinel.redact import REDACTED
from reposentinel.reporting import render_html, render_json, report_to_dict
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan

TEST_RULE = Rule(
    id="RS-TST-001",
    title="Test rule",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="d",
    severity_rationale="r",
    remediation="fix it",
    limitations="l",
)


class ExplodingCheck(Check):
    id = "exploding"
    name = "Exploding check"
    description = "Always fails, with a secret in its error message."
    rules: ClassVar[tuple[Rule, ...]] = (TEST_RULE,)

    def run(self, context: ScanContext) -> CheckOutput:
        raise RuntimeError(f"could not parse token {synthetic.GITHUB_TOKEN}")


class SkippingCheck(Check):
    id = "skipping"
    name = "Skipping check"
    description = "Cannot run."
    rules: ClassVar[tuple[Rule, ...]] = (TEST_RULE,)

    def run(self, context: ScanContext) -> CheckOutput:
        raise CheckSkipped("example-tool was not found on PATH")


class DuplicateCheck(Check):
    id = "duplicate"
    name = "Duplicate check"
    description = "Reports the same finding twice."
    rules: ClassVar[tuple[Rule, ...]] = (TEST_RULE,)

    def run(self, context: ScanContext) -> CheckOutput:
        finding = self.finding(TEST_RULE, summary="s", evidence="e", path="a.txt", line=1)
        return CheckOutput(findings=[finding, finding], examined=1)


def make_finding(severity: Severity, path: str | None = "a.txt", line: int | None = 1) -> Finding:
    return Finding(
        rule_id=f"RS-TST-{severity.rank}",
        title="t",
        severity=severity,
        confidence=Confidence.HIGH,
        summary="s",
        evidence="e",
        remediation="r",
        check_id="test",
        path=path,
        line=line,
    )


def make_report(
    findings: tuple[Finding, ...] = (),
    statuses: tuple[CheckStatus, ...] = (CheckStatus.COMPLETED,),
    coverage: tuple[CoverageIssue, ...] = (),
) -> ScanReport:
    return ScanReport(
        target="/repo",
        tool_version="0.0.0",
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        files_in_scope=1,
        checks=tuple(CheckResult(f"c{i}", f"C{i}", s) for i, s in enumerate(statuses)),
        findings=findings,
        coverage=coverage,
    )


# --- check isolation -------------------------------------------------------------


def test_failing_check_is_isolated_and_its_message_redacted(make_repo: RepoFactory) -> None:
    root = make_repo({".env": "X=1\n"})
    report = run_scan(root, [ExplodingCheck(), *default_checks()])
    failed, *others = report.checks
    assert failed.status is CheckStatus.FAILED
    # Only the exception type: its message may quote repository content that
    # redaction cannot recognise, so none of it is reported (not even redacted).
    assert failed.message.startswith("RuntimeError (details withheld")
    assert synthetic.GITHUB_TOKEN not in failed.message and REDACTED not in failed.message
    assert "could not parse" not in failed.message
    assert all(check.status is CheckStatus.COMPLETED for check in others)
    assert [f.rule_id for f in report.findings] == ["RS-HYG-001"]  # other checks still ran
    assert report.outcome is Outcome.INCOMPLETE
    assert exit_code_for(report, Severity.LOW) is ExitCode.INCOMPLETE


def test_skipped_check_makes_scan_incomplete(tmp_path: Path) -> None:
    report = run_scan(tmp_path, [SkippingCheck()])
    (result,) = report.checks
    assert (result.status, result.message) == (
        CheckStatus.SKIPPED,
        "example-tool was not found on PATH",
    )
    assert report.outcome is Outcome.INCOMPLETE
    assert exit_code_for(report, None) is ExitCode.INCOMPLETE


def test_no_checks_is_never_clean(tmp_path: Path) -> None:
    assert run_scan(tmp_path, []).outcome is Outcome.INCOMPLETE


def test_identical_findings_are_deduplicated(tmp_path: Path) -> None:
    report = run_scan(tmp_path, [DuplicateCheck()])
    assert len(report.findings) == 1
    assert report.checks[0].finding_count == 1


def test_finding_rejects_rule_not_declared_by_check() -> None:
    other = Rule("RS-TST-999", "x", Severity.LOW, Confidence.LOW, "d", "r", "f", "l")
    with pytest.raises(ValueError, match="not declared"):
        DuplicateCheck().finding(other, summary="s", evidence="e")


# --- outcomes, counts and ordering --------------------------------------------------


def test_clean_repository(make_repo: RepoFactory) -> None:
    report = scan(make_repo({"README.md": "# hello\n", "src/app.py": "print('hi')\n"}))
    assert report.findings == ()
    assert report.outcome is Outcome.CLEAN
    assert exit_code_for(report, Severity.INFO) is ExitCode.OK


def test_empty_repository_is_clean(tmp_path: Path) -> None:
    report = scan(tmp_path)
    assert (report.files_in_scope, report.outcome) == (0, Outcome.CLEAN)


def test_coverage_error_makes_outcome_incomplete() -> None:
    issue = CoverageIssue("a.txt", CoverageReason.UNREADABLE, "Permission denied")
    assert make_report(coverage=(issue,)).outcome is Outcome.INCOMPLETE


def test_policy_skips_do_not_make_outcome_incomplete() -> None:
    issues = (
        CoverageIssue(".git", CoverageReason.EXCLUDED),
        CoverageIssue("big.bin", CoverageReason.TOO_LARGE),
        CoverageIssue("img.png", CoverageReason.BINARY),
        CoverageIssue("link", CoverageReason.SYMLINK),
    )
    assert make_report(coverage=issues).outcome is Outcome.CLEAN


def test_severity_and_rule_counts() -> None:
    report = make_report(
        findings=(make_finding(Severity.HIGH), make_finding(Severity.INFO, line=2)),
    )
    assert list(report.severity_counts()) == list(SEVERITY_ORDER)
    assert report.severity_counts() == {
        Severity.HIGH: 1,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 1,
    }
    assert report.rule_counts() == {"RS-TST-0": 1, "RS-TST-3": 1}


def test_findings_are_sorted_by_severity_then_location() -> None:
    findings = [
        make_finding(Severity.LOW, "b.txt", 1),
        make_finding(Severity.HIGH, "z.txt", 9),
        make_finding(Severity.LOW, "a.txt", 10),
        make_finding(Severity.LOW, "a.txt", 2),
        make_finding(Severity.MEDIUM, None, None),
    ]
    ordered = sorted(findings, key=Finding.sort_key)
    assert [(f.severity.value, f.path, f.line) for f in ordered] == [
        ("high", "z.txt", 9),
        ("medium", None, None),
        ("low", "a.txt", 2),
        ("low", "a.txt", 10),
        ("low", "b.txt", 1),
    ]


def test_scans_are_deterministic(make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "z/settings.py": synthetic.credential_file(),
            "a/.env": "X=1",
            ".github/workflows/ci.yml": "on: push\npermissions: write-all\njobs: {}\n",
        }
    )
    first, second = report_to_dict(scan(root)), report_to_dict(scan(root))
    first.pop("scanned_at")
    second.pop("scanned_at")
    assert json.dumps(first) == json.dumps(second)


@pytest.mark.parametrize(
    ("line", "path", "message"),
    [(0, "a.txt", "1-based"), (1, None, "requires"), (None, None, None)],
)
def test_finding_validation(line: int | None, path: str | None, message: str | None) -> None:
    def build() -> Finding:
        return Finding("RS-X", "t", Severity.LOW, Confidence.LOW, "s", "e", "r", "c", path, line)

    if message is None:
        assert build().location == "(repository)"
    else:
        with pytest.raises(ValueError, match=message):
            build()


def test_finding_requires_rule_id() -> None:
    with pytest.raises(ValueError, match="rule_id"):
        Finding("", "t", Severity.LOW, Confidence.LOW, "s", "e", "r", "c")


# --- exit codes ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severities", "fail_on", "expected"),
    [
        ((), Severity.INFO, ExitCode.OK),
        ((Severity.LOW,), Severity.LOW, ExitCode.FINDINGS),
        ((Severity.MEDIUM,), Severity.HIGH, ExitCode.OK),
        ((Severity.MEDIUM, Severity.HIGH), Severity.HIGH, ExitCode.FINDINGS),
        ((Severity.INFO,), Severity.LOW, ExitCode.OK),
        ((Severity.INFO,), Severity.INFO, ExitCode.FINDINGS),
        ((Severity.HIGH,), None, ExitCode.OK),
    ],
)
def test_exit_code_thresholds(
    severities: tuple[Severity, ...], fail_on: Severity | None, expected: ExitCode
) -> None:
    findings = tuple(make_finding(s, line=i + 1) for i, s in enumerate(severities))
    assert exit_code_for(make_report(findings), fail_on) is expected


def test_incomplete_takes_priority_over_findings() -> None:
    report = make_report(
        findings=(make_finding(Severity.HIGH),),
        statuses=(CheckStatus.COMPLETED, CheckStatus.FAILED),
    )
    assert exit_code_for(report, Severity.LOW) is ExitCode.INCOMPLETE


# --- regressions found in the October 2026 security audit --------------------


class ChattyCheck(Check):
    """Copies repository text containing a credential into every text field."""

    id = "chatty"
    name = "Chatty check"
    description = "Puts a fake token in its note, finding and coverage detail."
    rules: ClassVar[tuple[Rule, ...]] = (TEST_RULE,)

    def run(self, context: ScanContext) -> CheckOutput:
        token = synthetic.GITHUB_TOKEN
        context.record_issue("a.txt", CoverageReason.UNPARSEABLE, f"bad value {token}")
        finding = self.finding(
            TEST_RULE, summary=f"step 'deploy {token}'", evidence=f"uses: x@{token}", path="a.txt"
        )
        return CheckOutput(findings=[finding], examined=1, message=f"note {token}")


def test_engine_redacts_every_text_field(tmp_path: Path) -> None:
    report = run_scan(tmp_path, [ChattyCheck()])
    (finding,) = report.findings
    assert finding.summary == f"step 'deploy {REDACTED}'"
    assert finding.evidence == f"uses: x@{REDACTED}"
    assert report.checks[0].message == f"note {REDACTED}"
    assert report.coverage[0].detail == f"bad value {REDACTED}"
    assert synthetic.GITHUB_TOKEN not in render_json(report)


def test_workflow_step_name_with_token_does_not_leak(make_repo: RepoFactory) -> None:
    # Found in the audit: RS-GHA-001 copied the step name into its summary.
    workflow = (
        "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - name: deploy {synthetic.GITHUB_TOKEN}\n"
        '        run: echo "${{ github.event.issue.title }}"\n'
    )
    report = scan(make_repo({".github/workflows/ci.yml": workflow}))
    assert {f.rule_id for f in report.findings} >= {"RS-GHA-001"}
    for output in (render_json(report), render_html(report)):
        assert synthetic.GITHUB_TOKEN not in output
