"""The comparison logic (product strategy sections 5.1 to 5.5; AC-01 to AC-11, AC-16, AC-20).

Most tests scan a real temporary repository twice, with a change in between,
and compare the two reports. Situations that cannot be produced on every
platform (unreadable folders, links, failed checks, other rule versions) are
built by editing a real report with ``dataclasses.replace``.
"""

from __future__ import annotations

import dataclasses
import json
import textwrap
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from reposentinel.checks import Check, CheckOutput, CheckSkipped, default_checks
from reposentinel.compare import (
    CREDENTIAL_REMINDER,
    SCOPE_STATEMENT,
    ComparisonError,
    ComparisonResult,
    ComparisonStatus,
    TrackedComparison,
    compare_reports,
    headline,
    is_credential_rule,
    summary_sentences,
)
from reposentinel.context import ScanContext
from reposentinel.engine import ExitCode, run_scan
from reposentinel.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    CoverageIssue,
    CoverageReason,
    Finding,
    Rule,
    ScanReport,
    Severity,
)
from reposentinel.reporting.compare_common import status_text
from reposentinel.reporting.compare_json import comparison_to_dict
from reposentinel.walker import ScanLimits
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan

S = ComparisonStatus
TOKEN_LINE = f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n'
AWS_LINE = f'AWS = "{synthetic.AWS_KEY_ID}"\n'
INJECTION_WORKFLOW = textwrap.dedent(
    """\
    on: issues
    jobs:
      greet:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ github.event.issue.title }}"
    """
)


def compare(old: ScanReport, new: ScanReport, **options: object) -> ComparisonResult:
    return compare_reports(old, new, **options)  # type: ignore[arg-type]


def only(result: ComparisonResult, rule_id: str) -> TrackedComparison:
    (finding,) = [f for f in result.findings if f.rule_id == rule_id]
    return finding


def statuses(result: ComparisonResult) -> list[tuple[str, str | None, ComparisonStatus]]:
    return sorted((f.rule_id, f.path, f.status) for f in result.findings)


def replace_check(report: ScanReport, check_id: str, **changes: object) -> ScanReport:
    checks = tuple(
        dataclasses.replace(c, **changes) if c.check_id == check_id else c  # type: ignore[arg-type]
        for c in report.checks
    )
    return dataclasses.replace(report, checks=checks)


def add_coverage(report: ScanReport, *issues: CoverageIssue) -> ScanReport:
    coverage = tuple(sorted((*report.coverage, *issues), key=lambda i: (i.path, i.reason)))
    return dataclasses.replace(report, coverage=coverage)


def with_rule_versions(report: ScanReport, **versions: int) -> ScanReport:
    assert report.scan_config is not None
    mapping = {key.replace("_", "-"): value for key, value in versions.items()}
    config = dataclasses.replace(
        report.scan_config, rule_versions={**report.scan_config.rule_versions, **mapping}
    )
    findings = tuple(
        dataclasses.replace(f, rule_version=mapping.get(f.rule_id, f.rule_version))
        for f in report.findings
    )
    return dataclasses.replace(report, scan_config=config, findings=findings)


# --- still detected (AC-01 to AC-05) -------------------------------------------


def test_unchanged_repository_is_still_detected(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": synthetic.credential_file(), ".env": "A=1\n"})
    result = compare(scan(root), scan(root))
    assert result.findings
    assert {f.status for f in result.findings} == {S.STILL_DETECTED}
    assert not any(f.credential_reminder for f in result.findings)
    assert result.exit_code is ExitCode.FINDINGS
    assert compare(scan(root), scan(root), fail_on=None).exit_code is ExitCode.OK


def test_inserted_lines_are_still_detected_with_new_lines(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    (root / "config.py").write_text("# moved\n\n" + TOKEN_LINE)
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.STILL_DETECTED
    assert (finding.old_lines, finding.new_lines) == ((1,), (3,))


def test_one_of_two_occurrences_removed(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE + TOKEN_LINE.replace("TOKEN", "OTHER")})
    old = scan(root)
    (root / "config.py").write_text(TOKEN_LINE)
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.STILL_DETECTED
    assert (finding.old_count, finding.new_count) == (2, 1)
    assert status_text(finding) == "Still detected (2 to 1)"
    assert finding.credential_reminder  # a removed credential may still be valid


# --- not detected on re-check / file removed (AC-06, AC-10) ---------------------


def test_removed_occurrence_in_an_examined_file(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "keep.py": "x = 1\n"})
    old = scan(root)
    (root / "config.py").write_text("TOKEN = load_from_environment()\n")
    result = compare(old, scan(root))
    finding = only(result, "RS-SEC-004")
    assert finding.status is S.NOT_DETECTED_ON_RECHECK
    for part in ("Hard-coded credential patterns", "RS-SEC-004", "version 1", "config.py"):
        assert part in finding.explanation
    assert finding.credential_reminder
    assert "split" in finding.recheck_limits  # the rule's own "does not show" text
    assert result.exit_code is ExitCode.OK


def test_deleted_file_with_complete_listing(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE, ".env": "A=1\n"})
    old = scan(root)
    (root / "config.py").unlink()
    (root / ".env").unlink()
    result = compare(old, scan(root))
    assert {f.status for f in result.findings} == {S.NOT_DETECTED_FILE_REMOVED}
    assert all(f.credential_reminder for f in result.findings)
    assert result.exit_code is ExitCode.OK


def test_deleting_the_only_workflow(make_repo: RepoFactory) -> None:
    # With no workflow files left, the check still records that it examined
    # nothing, so the deleted file can be shown as removed.
    root = make_repo({".github/workflows/ci.yml": INJECTION_WORKFLOW, "a.py": "1\n"})
    old = scan(root)
    (root / ".github/workflows/ci.yml").unlink()
    result = compare(old, scan(root))
    assert only(result, "RS-GHA-001").status is S.NOT_DETECTED_FILE_REMOVED
    assert result.exit_code is ExitCode.OK


def test_renamed_file_is_removed_plus_new(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    (root / "config.py").rename(root / "settings.py")
    result = compare(old, scan(root))
    assert statuses(result) == [
        ("RS-SEC-004", "config.py", S.NOT_DETECTED_FILE_REMOVED),
        ("RS-SEC-004", "settings.py", S.NEW),
    ]


def test_deleted_file_when_new_scan_reached_the_file_limit(make_repo: RepoFactory) -> None:
    limits = ScanLimits(max_files=3)
    root = make_repo({"a.py": TOKEN_LINE, "b.py": "1\n"})
    old = scan(root, limits)
    (root / "a.py").unlink()
    for name in ("c.py", "d.py", "e.py", "f.py"):
        (root / name).write_text("1\n")
    result = compare(old, scan(root, limits))
    finding = only(result, "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "stopped early" in finding.explanation
    assert result.exit_code is ExitCode.INCOMPLETE


def test_deleted_file_inside_a_folder_that_is_now_excluded(make_repo: RepoFactory) -> None:
    # A pattern can disappear without the risk disappearing: the folder that
    # holds the token is now treated as a virtual environment and not listed.
    root = make_repo({"tools/config.py": TOKEN_LINE})
    old = scan(root)
    (root / "tools" / "pyvenv.cfg").write_text("home = x\n")
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "The folder tools was not fully listed" in finding.explanation


def test_deleted_file_inside_an_unreadable_folder(make_repo: RepoFactory) -> None:
    root = make_repo({"deep/config.py": TOKEN_LINE})
    old = scan(root)
    (root / "deep" / "config.py").unlink()
    new = add_coverage(
        scan(root), CoverageIssue("deep", CoverageReason.UNREADABLE, "access denied")
    )
    finding = only(compare(old, new), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "could not be read" in finding.explanation


# --- not re-checked: the file was not examined (AC-07) --------------------------


def test_file_now_too_large(make_repo: RepoFactory) -> None:
    limits = ScanLimits(max_file_size=200)
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root, limits)
    (root / "config.py").write_text(TOKEN_LINE + "#" * 300 + "\n")
    finding = only(compare(old, scan(root, limits)), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "larger than the size limit" in finding.explanation
    assert not finding.credential_reminder  # only for findings that are no longer detected


def test_file_now_binary(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    (root / "config.py").write_bytes(b"\x00\x01" + TOKEN_LINE.encode())
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "binary data" in finding.explanation


def test_workflow_now_unparseable(make_repo: RepoFactory) -> None:
    root = make_repo({".github/workflows/ci.yml": INJECTION_WORKFLOW})
    old = scan(root)
    (root / ".github/workflows/ci.yml").write_text(INJECTION_WORKFLOW + "  bad: [\n")
    result = compare(old, scan(root))
    finding = only(result, "RS-GHA-001")
    assert finding.status is S.NOT_RECHECKED
    assert "could not be parsed" in finding.explanation
    assert result.exit_code is ExitCode.INCOMPLETE  # the parse error is a coverage error


@pytest.mark.parametrize(
    ("reason", "words"),
    [
        (CoverageReason.SYMLINK, "a link"),
        (CoverageReason.UNREADABLE, "could not be read"),
        (CoverageReason.EXCLUDED, "excluded"),
    ],
)
def test_file_now_a_link_unreadable_or_excluded(
    make_repo: RepoFactory, reason: CoverageReason, words: str
) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "other.py": "1\n"})
    old = scan(root)
    (root / "config.py").unlink()  # the new scan did not list it, for the reason below
    new = add_coverage(scan(root), CoverageIssue("config.py", reason, "detail text"))
    finding = only(compare(old, new), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert words in finding.explanation


def test_file_listed_but_not_examined_by_the_check(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    new = replace_check(scan(root), "secrets", examined_paths=())
    new = dataclasses.replace(new, findings=())
    finding = only(compare(old, new), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "did not examine it" in finding.explanation


# --- not re-checked: the check did not complete (AC-08) -------------------------


class ExternalCheck(Check):
    """Behaves like an integration: no examined-paths record."""

    id = "external"
    name = "External tool"
    description = "test double"
    rules: ClassVar[tuple[Rule, ...]] = ()

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def run(self, context: ScanContext) -> CheckOutput:
        if self.mode == "skip":
            raise CheckSkipped("external-tool was not found on PATH.")  # ends with a full stop
        if self.mode == "fail":
            raise RuntimeError("boom")
        findings = []
        if self.mode == "finding":
            findings.append(
                Finding(
                    rule_id="gitleaks:test-rule",
                    title="External finding",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    summary="s",
                    evidence="e",
                    remediation="r",
                    check_id=self.id,
                    path="config.py",
                    line=1,
                )
            )
        return CheckOutput(findings=findings, examined=None)


def scan_with_external(root: Path, mode: str) -> ScanReport:
    return run_scan(root, [*default_checks(), ExternalCheck(mode)])


@pytest.mark.parametrize(("mode", "word"), [("skip", "was skipped"), ("fail", "failed")])
def test_check_skipped_or_failed_in_new_scan(make_repo: RepoFactory, mode: str, word: str) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    result = compare(scan_with_external(root, "finding"), scan_with_external(root, mode))
    finding = only(result, "gitleaks:test-rule")
    assert finding.status is S.NOT_RECHECKED
    assert f"check {word} in the new scan" in finding.explanation
    assert any(word in problem for problem in result.check_problems)
    assert ".." not in finding.explanation and ".." not in result.check_problems[0]
    assert result.exit_code is ExitCode.INCOMPLETE


def test_check_not_run_in_new_scan(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    result = compare(scan_with_external(root, "finding"), scan(root))
    finding = only(result, "gitleaks:test-rule")
    assert finding.status is S.NOT_RECHECKED
    assert "did not run in the new scan" in finding.explanation
    assert "--integration" in finding.explanation
    assert result.check_problems
    assert result.exit_code is ExitCode.INCOMPLETE


def test_integration_without_examined_paths_is_never_not_detected(
    make_repo: RepoFactory,
) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    result = compare(scan_with_external(root, "finding"), scan_with_external(root, "clean"))
    finding = only(result, "gitleaks:test-rule")
    assert finding.status is S.NOT_RECHECKED
    assert "does not record which files it examined" in finding.explanation
    assert result.exit_code is ExitCode.INCOMPLETE


def test_native_check_failed_in_new_scan(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    new = replace_check(
        dataclasses.replace(scan(root), findings=()),
        "secrets",
        status=CheckStatus.FAILED,
        examined=None,
        examined_paths=None,
        message="RuntimeError: boom",
    )
    finding = only(compare(old, new), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "RuntimeError: boom" in finding.explanation


# --- not comparable (AC-09) -----------------------------------------------------


def test_rule_version_changed(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "aws.py": AWS_LINE})
    old = scan(root)
    (root / "config.py").write_text("x = 1\n")
    new = with_rule_versions(scan(root), RS_SEC_004=2, RS_SEC_002=2)
    result = compare(old, new)
    token = only(result, "RS-SEC-004")
    assert token.status is S.NOT_COMPARABLE
    assert "version 1 to version 2" in token.explanation
    assert only(result, "RS-SEC-002").status is S.STILL_DETECTED  # detected in both
    assert result.exit_code is ExitCode.INCOMPLETE


def test_new_finding_after_rule_version_change(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    old = scan(root)
    (root / "config.py").write_text(TOKEN_LINE)
    finding = only(compare(old, with_rule_versions(scan(root), RS_SEC_004=2)), "RS-SEC-004")
    assert finding.status is S.NOT_COMPARABLE
    assert "only now detected" in finding.explanation


def test_scan_limits_changed(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE, "new.py": "1\n"})
    old = scan(root, ScanLimits(max_file_size=10_000))
    (root / "config.py").write_text("x = 1\n")
    (root / "new.py").write_text(AWS_LINE)
    result = compare(old, scan(root, ScanLimits(max_file_size=20_000)))
    assert result.config_differences == ("file size limit (bytes): 10000 before, 20000 after",)
    assert {f.status for f in result.findings} == {S.NOT_COMPARABLE}
    assert "file size limit" in only(result, "RS-SEC-004").explanation
    assert result.exit_code is ExitCode.INCOMPLETE


def test_exclusion_lists_changed(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    (root / "config.py").write_text("x = 1\n")
    new = scan(root)
    assert new.scan_config is not None
    config = dataclasses.replace(new.scan_config, exclusions={"dirs": (".git",)})
    result = compare(old, dataclasses.replace(new, scan_config=config))
    assert only(result, "RS-SEC-004").status is S.NOT_COMPARABLE
    assert "exclusion lists differ" in result.config_differences[0]


def test_rule_only_in_old_scan_is_not_rechecked(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    old = scan(root)
    (root / "config.py").write_text("x = 1\n")
    new = scan(root)
    assert new.scan_config is not None
    versions = {k: v for k, v in new.scan_config.rule_versions.items() if k != "RS-SEC-004"}
    new = dataclasses.replace(
        new, scan_config=dataclasses.replace(new.scan_config, rule_versions=versions)
    )
    finding = only(compare(old, new), "RS-SEC-004")
    assert finding.status is S.NOT_RECHECKED
    assert "not part of the new scan" in finding.explanation


def test_rule_only_in_new_scan_is_new_not_examined_before(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    old = scan(root)
    assert old.scan_config is not None
    versions = {k: v for k, v in old.scan_config.rule_versions.items() if k != "RS-SEC-004"}
    old = dataclasses.replace(
        old, scan_config=dataclasses.replace(old.scan_config, rule_versions=versions)
    )
    (root / "config.py").write_text(TOKEN_LINE)
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.NEW_NOT_EXAMINED_BEFORE
    assert "not part of the old scan" in finding.explanation


# --- new and new (not examined before) (AC-11) ----------------------------------


def test_new_finding_in_an_examined_file(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    old = scan(root)
    (root / "config.py").write_text(TOKEN_LINE)
    result = compare(old, scan(root))
    finding = only(result, "RS-SEC-004")
    assert finding.status is S.NEW
    assert "examined config.py in the old scan" in finding.explanation
    assert result.exit_code is ExitCode.FINDINGS


def test_new_file(make_repo: RepoFactory) -> None:
    root = make_repo({"other.py": "1\n"})
    old = scan(root)
    (root / "config.py").write_text(TOKEN_LINE)
    finding = only(compare(old, scan(root)), "RS-SEC-004")
    assert finding.status is S.NEW
    assert "was not in the old scan" in finding.explanation


def test_file_too_large_in_old_scan(make_repo: RepoFactory) -> None:
    limits = ScanLimits(max_file_size=200)
    root = make_repo({"config.py": TOKEN_LINE + "#" * 300 + "\n"})
    old = scan(root, limits)
    (root / "config.py").write_text(TOKEN_LINE)
    finding = only(compare(old, scan(root, limits)), "RS-SEC-004")
    assert finding.status is S.NEW_NOT_EXAMINED_BEFORE
    assert "larger than the size limit" in finding.explanation


def test_new_file_when_old_scan_reached_the_limit(make_repo: RepoFactory) -> None:
    limits = ScanLimits(max_files=2)
    root = make_repo({"a.py": "1\n", "b.py": "1\n", "c.py": "1\n"})
    old = scan(root, limits)
    for name in ("a.py", "b.py", "c.py"):
        (root / name).unlink()
    (root / "z.py").write_text(TOKEN_LINE)
    finding = only(compare(old, scan(root, limits)), "RS-SEC-004")
    assert finding.status is S.NEW_NOT_EXAMINED_BEFORE
    assert "old scan stopped early" in finding.explanation


@pytest.mark.parametrize("mode", ["skip", "fail"])
def test_check_not_completed_in_old_scan(make_repo: RepoFactory, mode: str) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    result = compare(scan_with_external(root, mode), scan_with_external(root, "finding"))
    finding = only(result, "gitleaks:test-rule")
    assert finding.status is S.NEW_NOT_EXAMINED_BEFORE
    # The old scan's completeness affects statuses, never the exit code directly.
    assert result.exit_code is ExitCode.FINDINGS


def test_check_only_in_new_scan(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": "x = 1\n"})
    result = compare(scan(root), scan_with_external(root, "finding"))
    assert only(result, "gitleaks:test-rule").status is S.NEW_NOT_EXAMINED_BEFORE
    assert any("ran only in the new scan" in note for note in result.notes)


# --- different roots, order and determinism (AC-14, section 5.5) ----------------


def test_different_targets_need_the_explicit_flag(make_repo: RepoFactory, tmp_path: Path) -> None:
    first = make_repo({"config.py": TOKEN_LINE})
    second = tmp_path / "elsewhere"
    second.mkdir()
    (second / "config.py").write_text(TOKEN_LINE)
    with pytest.raises(ComparisonError, match="--different-roots"):
        compare(scan(first), scan(second))
    result = compare(scan(first), scan(second), different_roots_declared=True)
    assert result.different_roots_declared and not result.targets_match
    assert any("cannot confirm" in note for note in result.notes)
    assert only(result, "RS-SEC-004").status is S.STILL_DETECTED


def test_same_target_ignores_the_flag(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    result = compare(scan(root), scan(root), different_roots_declared=True)
    assert result.targets_match and not result.different_roots_declared


def test_reports_given_in_reverse_order_get_a_note(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    new = scan(root)
    old = dataclasses.replace(new, scanned_at=new.scanned_at + timedelta(days=1))
    assert any("older than the first" in note for note in compare(old, new).notes)


def test_comparison_is_deterministic(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": synthetic.credential_file(), ".env": "A=1\n"})
    old = scan(root)
    (root / ".env").unlink()
    new = scan(root)
    first = json.dumps(comparison_to_dict(compare(old, new)))
    assert first == json.dumps(comparison_to_dict(compare(old, new)))


def test_report_without_scan_config_is_refused(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": TOKEN_LINE})
    report = dataclasses.replace(scan(root), scan_config=None)
    with pytest.raises(ComparisonError):
        compare(report, report)


def test_credential_rules() -> None:
    assert is_credential_rule("RS-SEC-001") and is_credential_rule("RS-HYG-003")
    assert is_credential_rule("gitleaks:aws-access-token")
    assert not is_credential_rule("RS-GHA-001")


# --- exit-code precedence (AC-20) -----------------------------------------------


def _tracked(status: ComparisonStatus, severity: Severity) -> TrackedComparison:
    return TrackedComparison(
        fingerprint="rs1:" + "0" * 64,
        status=status,
        explanation="",
        rule_id="RS-TST-001",
        title="t",
        check_id="c",
        path="a.txt",
        severity=severity,
        confidence=Confidence.HIGH,
        summary="",
        evidence="",
        remediation="",
        old_lines=(),
        new_lines=(),
        old_count=1,
        new_count=1,
        recheck_limits="",
        credential_reminder=False,
    )


@pytest.fixture
def base_result(make_repo: RepoFactory) -> ComparisonResult:
    root = make_repo({"a.txt": "1\n"})
    return compare(scan(root), scan(root))


HIGH, LOW = Severity.HIGH, Severity.LOW
PRECEDENCE = {
    "a-high-still-plus-low-not-rechecked": (
        [(S.STILL_DETECTED, HIGH), (S.NOT_RECHECKED, LOW)],
        [],
        [],
        Severity.LOW,
        3,
    ),
    "b-still-detected-at-threshold": ([(S.STILL_DETECTED, HIGH)], [], [], Severity.HIGH, 1),
    "c-only-below-threshold": ([(S.STILL_DETECTED, LOW), (S.NEW, LOW)], [], [], HIGH, 0),
    "d-only-not-comparable": ([(S.NOT_COMPARABLE, LOW)], [], [], Severity.LOW, 3),
    "e-check-skipped-in-new-scan": ([], ["The X check skipped in the new scan."], [], LOW, 3),
    "f-never-with-still-detected": ([(S.STILL_DETECTED, HIGH)], [], [], None, 0),
    "f-never-with-unknown": ([(S.STILL_DETECTED, HIGH), (S.NOT_RECHECKED, LOW)], [], [], None, 3),
    "coverage-error-only": (
        [],
        [],
        [CoverageIssue("x", CoverageReason.UNREADABLE, "denied")],
        LOW,
        3,
    ),
    "new-not-examined-before-counts": ([(S.NEW_NOT_EXAMINED_BEFORE, HIGH)], [], [], HIGH, 1),
    "new-at-threshold": ([(S.NEW, Severity.MEDIUM)], [], [], Severity.MEDIUM, 1),
    "no-longer-detected-only": (
        [(S.NOT_DETECTED_ON_RECHECK, HIGH), (S.NOT_DETECTED_FILE_REMOVED, HIGH)],
        [],
        [],
        Severity.INFO,
        0,
    ),
    "nothing-at-all": ([], [], [], Severity.INFO, 0),
}


@pytest.mark.parametrize(
    ("findings", "problems", "coverage", "fail_on", "expected"),
    PRECEDENCE.values(),
    ids=PRECEDENCE.keys(),
)
def test_exit_code_precedence(
    base_result: ComparisonResult,
    findings: list[tuple[ComparisonStatus, Severity]],
    problems: list[str],
    coverage: list[CoverageIssue],
    fail_on: Severity | None,
    expected: int,
) -> None:
    result = dataclasses.replace(
        base_result,
        findings=tuple(_tracked(status, severity) for status, severity in findings),
        check_problems=tuple(problems),
        coverage_errors=tuple(coverage),
        fail_on=fail_on,
    )
    assert int(result.exit_code) == expected


# --- scoped wording (AC-16) -----------------------------------------------------

FORBIDDEN = (
    "is secure",
    "are secure",
    "no vulnerabilities",
    "safe to publish",
    "ready to publish",
    "all clear",
    "fixed",
    "resolved",
    "score",
    "grade",
)


def _scoped_texts(result: ComparisonResult) -> list[str]:
    """Every sentence RepoSentinel writes about the comparison (not rule fix guidance)."""
    data = comparison_to_dict(result)
    texts = [data["headline"], data["scope"], data["disclaimer"], data["exit_explanation"]]
    texts += data["summary"] + data["notes"] + data["check_problems"]
    for finding in data["findings"]:
        texts += [finding["explanation"], finding["recheck_limits"], finding["status_text"]]
        texts.append(finding["credential_reminder"] or "")
    return texts


def test_summary_carries_scope_and_no_unsupported_claims(make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "config.py": TOKEN_LINE,
            ".env": "A=1\n",
            ".github/workflows/ci.yml": INJECTION_WORKFLOW,
        }
    )
    old = scan(root)
    (root / "config.py").write_text("x = 1\n")
    (root / ".env").unlink()
    (root / ".github/workflows/ci.yml").write_text("on: push\njobs: {}\n")
    result = compare(old, scan(root), old_label="before.json")
    assert result.findings and {f.status for f in result.findings} <= {
        S.NOT_DETECTED_ON_RECHECK,
        S.NOT_DETECTED_FILE_REMOVED,
    }
    for text in _scoped_texts(result):
        for claim in FORBIDDEN:
            assert claim not in text.lower(), (claim, text)
    sentences = " ".join(summary_sentences(result))
    for required in (
        "Of 3 tracked findings in before.json",
        "Checks completed in the new scan: 3 of 3",
        "Files examined:",
        "Unknowns: 0",
        "Git history was not scanned",
    ):
        assert required in sentences
    assert headline(result) == "3 findings are no longer detected, 0 remain, 0 unknown."
    assert SCOPE_STATEMENT == "Checked: current files only. Git history was not scanned."
    assert "Git history" in CREDENTIAL_REMINDER and "cannot confirm" in CREDENTIAL_REMINDER


def test_headline_counts(base_result: ComparisonResult) -> None:
    result = dataclasses.replace(
        base_result,
        findings=(
            _tracked(S.NOT_DETECTED_ON_RECHECK, HIGH),
            _tracked(S.STILL_DETECTED, HIGH),
            _tracked(S.NOT_RECHECKED, LOW),
        ),
    )
    assert headline(result) == "1 finding is no longer detected, 1 remains, 1 unknown."


def test_check_result_examined_paths_default_is_unknown() -> None:
    # A check that says nothing about examined files can never support
    # "not detected on re-check".
    assert CheckResult("x", "X", CheckStatus.COMPLETED).examined_paths is None
