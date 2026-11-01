"""Compare two scan reports: what is still detected, what is not, what is unknown.

This module is pure: it takes two ``ScanReport`` objects (normally loaded with
``report_loader``) and returns a ``ComparisonResult``. It reads no files,
touches no repository and makes no network calls, so it can be tested in
isolation. The rules it applies are those of docs/product-strategy.md
(revision 3, sections 5.1 to 5.5):

* Findings are compared as *tracked findings*: all occurrences sharing one
  fingerprint.
* "Not detected on re-check" is the strongest positive statement. It needs
  evidence recorded in the new report: the owning check completed, it
  examined the file, the rule version is unchanged, and the scan settings
  that decide what could be seen are unchanged.
* "Not detected: file removed" needs the new scan to have listed the
  repository completely around that path.
* Anything else that is missing is "Not re-checked" or "Not comparable",
  with a reason. Missing evidence is never treated as good news.

No status here means "fixed" or "secure". The result also always carries the
statement that Git history was not scanned.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from reposentinel.checks import all_rules
from reposentinel.engine import ExitCode
from reposentinel.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    CoverageIssue,
    CoverageReason,
    Finding,
    Outcome,
    Rule,
    ScanConfig,
    ScanReport,
    Severity,
)

SCOPE_STATEMENT = "Checked: current files only. Git history was not scanned."
CREDENTIAL_REMINDER = (
    "If this was a real credential, treat it as compromised: rotate or revoke it. If it was "
    "ever committed, it is still in Git history. RepoSentinel cannot confirm either step."
)
GENERIC_RECHECK_LIMITS = (
    "This only shows that the rule no longer matches in the files the check examined; the "
    "underlying problem may remain."
)

# Rules whose findings concern credentials. Decided from RepoSentinel's own
# vocabulary, never from text in a report.
_CREDENTIAL_RULES = frozenset(
    {
        "RS-SEC-001",
        "RS-SEC-002",
        "RS-SEC-003",
        "RS-SEC-004",
        "RS-SEC-005",
        "RS-HYG-001",
        "RS-HYG-002",
        "RS-HYG-003",
    }
)

# Coverage reasons that, on a file, mean "this file was not examined".
_FILE_NOT_EXAMINED = frozenset(
    {
        CoverageReason.TOO_LARGE,
        CoverageReason.BINARY,
        CoverageReason.UNREADABLE,
        CoverageReason.UNPARSEABLE,
        CoverageReason.SYMLINK,
        CoverageReason.EXCLUDED,
    }
)
# Coverage reasons that, on a folder, mean "what is inside was not listed".
_FOLDER_NOT_LISTED = frozenset(
    {
        CoverageReason.EXCLUDED,
        CoverageReason.SYMLINK,
        CoverageReason.UNREADABLE,
        CoverageReason.LIMIT_REACHED,
    }
)

_REASON_WORDS: dict[CoverageReason, str] = {
    CoverageReason.EXCLUDED: "excluded",
    CoverageReason.SYMLINK: "a link, which is never followed",
    CoverageReason.TOO_LARGE: "larger than the size limit",
    CoverageReason.BINARY: "binary data",
    CoverageReason.UNREADABLE: "could not be read",
    CoverageReason.UNPARSEABLE: "could not be parsed",
    CoverageReason.LIMIT_REACHED: "beyond a scan limit",
}


_CHECK_STATUS_WORDS: dict[CheckStatus, str] = {
    CheckStatus.COMPLETED: "completed",
    CheckStatus.FAILED: "failed",
    CheckStatus.SKIPPED: "was skipped",
}


def _not_completed(name: str, status: CheckStatus, which: str, message: str = "") -> str:
    """For example "The X check was skipped in the new scan: <reason>." (one full stop)."""
    text = f"The {name} check {_CHECK_STATUS_WORDS[status]} in the {which} scan"
    reason = message.strip().rstrip(".")
    return text + (f": {reason}." if reason else ".")


def is_credential_rule(rule_id: str) -> bool:
    return rule_id in _CREDENTIAL_RULES or rule_id.startswith("gitleaks:")


class ComparisonStatus(enum.StrEnum):
    NEW = "new"
    NEW_NOT_EXAMINED_BEFORE = "new_not_examined_before"
    STILL_DETECTED = "still_detected"
    NOT_DETECTED_ON_RECHECK = "not_detected_on_recheck"
    NOT_DETECTED_FILE_REMOVED = "not_detected_file_removed"
    NOT_RECHECKED = "not_rechecked"
    NOT_COMPARABLE = "not_comparable"

    @property
    def label(self) -> str:
        return _STATUS_LABELS[self]


_STATUS_LABELS: dict[ComparisonStatus, str] = {
    ComparisonStatus.NEW: "New",
    ComparisonStatus.NEW_NOT_EXAMINED_BEFORE: "New (not examined before)",
    ComparisonStatus.STILL_DETECTED: "Still detected",
    ComparisonStatus.NOT_DETECTED_ON_RECHECK: "Not detected on re-check",
    ComparisonStatus.NOT_DETECTED_FILE_REMOVED: "Not detected: file removed",
    ComparisonStatus.NOT_RECHECKED: "Not re-checked",
    ComparisonStatus.NOT_COMPARABLE: "Not comparable",
}

DETECTED = frozenset(
    {
        ComparisonStatus.NEW,
        ComparisonStatus.NEW_NOT_EXAMINED_BEFORE,
        ComparisonStatus.STILL_DETECTED,
    }
)
NO_LONGER_DETECTED = frozenset(
    {ComparisonStatus.NOT_DETECTED_ON_RECHECK, ComparisonStatus.NOT_DETECTED_FILE_REMOVED}
)
UNKNOWN = frozenset({ComparisonStatus.NOT_RECHECKED, ComparisonStatus.NOT_COMPARABLE})

# Display order: what needs attention first, then unknowns, then the rest.
_STATUS_ORDER = (
    ComparisonStatus.STILL_DETECTED,
    ComparisonStatus.NEW,
    ComparisonStatus.NEW_NOT_EXAMINED_BEFORE,
    ComparisonStatus.NOT_RECHECKED,
    ComparisonStatus.NOT_COMPARABLE,
    ComparisonStatus.NOT_DETECTED_ON_RECHECK,
    ComparisonStatus.NOT_DETECTED_FILE_REMOVED,
)


@dataclass(frozen=True, slots=True)
class ReportInfo:
    label: str  # how the user named the report file, e.g. "before.json"
    target: str
    scanned_at: datetime
    tool_version: str
    outcome: Outcome
    files_in_scope: int


@dataclass(frozen=True, slots=True)
class TrackedComparison:
    """One tracked finding across the two reports."""

    fingerprint: str
    status: ComparisonStatus
    explanation: str  # the evidence or the reason, in plain language
    rule_id: str
    title: str
    check_id: str
    path: str | None
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: str  # redacted, from the most recent report that has the finding
    remediation: str
    old_lines: tuple[int, ...]
    new_lines: tuple[int, ...]
    old_count: int
    new_count: int
    recheck_limits: str  # shown with "no longer detected" results
    credential_reminder: bool

    @property
    def location(self) -> str:
        return self.path if self.path is not None else "(repository)"


@dataclass(frozen=True, slots=True)
class CheckComparison:
    check_id: str
    name: str
    old_status: CheckStatus | None  # None: the check did not run in that scan
    new_status: CheckStatus | None
    old_examined: int | None
    new_examined: int | None
    new_message: str


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    old: ReportInfo
    new: ReportInfo
    targets_match: bool
    different_roots_declared: bool
    findings: tuple[TrackedComparison, ...]
    checks: tuple[CheckComparison, ...]
    check_problems: tuple[str, ...]  # checks that failed, were skipped or did not run
    coverage_errors: tuple[CoverageIssue, ...]  # new scan: unreadable, unparseable, limits
    not_examined: tuple[CoverageIssue, ...]  # new scan: skipped by policy
    config_differences: tuple[str, ...]
    notes: tuple[str, ...]
    fail_on: Severity | None
    files_examined: int  # distinct files examined by at least one check in the new scan

    def with_status(self, *statuses: ComparisonStatus) -> list[TrackedComparison]:
        wanted = set(statuses)
        return [finding for finding in self.findings if finding.status in wanted]

    def count(self, status: ComparisonStatus) -> int:
        return sum(1 for finding in self.findings if finding.status is status)

    @property
    def unknown_count(self) -> int:
        """Unknown findings, plus check problems and coverage errors in the new scan."""
        return (
            len(self.with_status(*UNKNOWN)) + len(self.check_problems) + len(self.coverage_errors)
        )

    @property
    def has_unknowns(self) -> bool:
        return self.unknown_count > 0

    @property
    def detected_at_threshold(self) -> list[TrackedComparison]:
        if self.fail_on is None:
            return []
        threshold = self.fail_on.rank
        return [
            finding
            for finding in self.findings
            if finding.status in DETECTED and finding.severity.rank >= threshold
        ]

    @property
    def exit_code(self) -> ExitCode:
        """Revision 3 precedence. (Exit code 2, invalid input, is decided before this.)"""
        if self.has_unknowns:
            return ExitCode.INCOMPLETE
        if self.detected_at_threshold:
            return ExitCode.FINDINGS
        return ExitCode.OK

    @property
    def old_tracked(self) -> int:
        return sum(1 for finding in self.findings if finding.old_count)

    @property
    def new_tracked(self) -> int:
        return sum(1 for finding in self.findings if finding.new_count)


class ComparisonError(ValueError):
    """The two reports cannot be compared as given (for example different roots)."""


# --- helpers -----------------------------------------------------------------


def targets_match(old: ScanReport, new: ScanReport) -> bool:
    """Same scanned folder path? (Case-insensitive on Windows.)"""
    return os.path.normcase(old.target) == os.path.normcase(new.target)


def _group(report: ScanReport) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {}
    for finding in report.findings:
        groups.setdefault(finding.fingerprint, []).append(finding)
    for occurrences in groups.values():
        occurrences.sort(key=lambda f: (f.line or 0, f.evidence))
    return groups


def _ancestors(path: str) -> list[str]:
    parts = path.split("/")
    return ["."] + ["/".join(parts[:index]) for index in range(1, len(parts))]


def _config(report: ScanReport) -> ScanConfig:
    if report.scan_config is None:  # the loader guarantees it; hand-built reports may not
        raise ComparisonError("a report has no scan configuration record")
    return report.scan_config


def _config_differences(old: ScanConfig, new: ScanConfig) -> list[str]:
    differences: list[str] = []
    labels = {
        "max_file_size": "file size limit (bytes)",
        "max_files": "file count limit",
        "max_depth": "folder depth limit",
    }
    for key in sorted(set(old.limits) | set(new.limits)):
        if old.limits.get(key) != new.limits.get(key):
            label = labels.get(key, key)
            differences.append(
                f"{label}: {old.limits.get(key)} before, {new.limits.get(key)} after"
            )
    if dict(old.exclusions) != dict(new.exclusions):
        differences.append("the default exclusion lists differ (different RepoSentinel versions)")
    return differences


def _rule_version_change(rule_id: str, old: ScanConfig, new: ScanConfig) -> tuple[int, int] | None:
    before, after = old.rule_versions.get(rule_id), new.rule_versions.get(rule_id)
    if before is not None and after is not None and before != after:
        return before, after
    return None


@dataclass(frozen=True, slots=True)
class _ScanView:
    """Lookups over one report, built once so classification stays linear."""

    report: ScanReport
    which: str  # "old" or "new", for explanations
    config: ScanConfig
    checks: dict[str, CheckResult]
    examined: dict[str, frozenset[str] | None]  # check ID -> examined paths
    files: frozenset[str]
    file_issues: dict[str, CoverageIssue]  # path -> why that file was not examined
    folder_issues: dict[str, CoverageIssue]  # path -> why that folder was not listed
    limit_issue: CoverageIssue | None  # any scan limit reached

    @classmethod
    def build(cls, report: ScanReport, which: str) -> _ScanView:
        file_issues: dict[str, CoverageIssue] = {}
        folder_issues: dict[str, CoverageIssue] = {}
        for issue in report.coverage:  # sorted by path and reason: first one wins
            if issue.reason in _FILE_NOT_EXAMINED:
                file_issues.setdefault(issue.path, issue)
            if issue.reason in _FOLDER_NOT_LISTED:
                folder_issues.setdefault(issue.path, issue)
        limits = [i for i in report.coverage if i.reason is CoverageReason.LIMIT_REACHED]
        return cls(
            report=report,
            which=which,
            config=_config(report),
            checks={check.check_id: check for check in report.checks},
            examined={
                check.check_id: (
                    None if check.examined_paths is None else frozenset(check.examined_paths)
                )
                for check in report.checks
            },
            files=frozenset(report.files),
            file_issues=file_issues,
            folder_issues=folder_issues,
            limit_issue=limits[0] if limits else None,
        )

    def location_blocker(self, path: str) -> str | None:
        """Why this scan cannot show that ``path`` did not exist, or None if it can."""
        for ancestor in _ancestors(path):
            issue = self.folder_issues.get(ancestor)
            if issue is not None:
                where = "The scanned folder" if ancestor == "." else f"The folder {ancestor}"
                return (
                    f"{where} was not fully listed in the {self.which} scan "
                    f"({_REASON_WORDS[issue.reason]}: {issue.detail}), so it cannot show "
                    f"whether {path} existed."
                )
        if self.limit_issue is not None:
            return (
                f"The {self.which} scan stopped early ({self.limit_issue.detail}), so it cannot "
                f"show whether {path} existed."
            )
        return None


def _lines(occurrences: Iterable[Finding]) -> tuple[int, ...]:
    return tuple(sorted(f.line for f in occurrences if f.line is not None))


def _recheck_limits(rule_id: str, catalogue: Mapping[str, Rule]) -> str:
    rule = catalogue.get(rule_id)
    return (rule.recheck_limits if rule is not None else "") or GENERIC_RECHECK_LIMITS


# --- classification ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Context:
    old: _ScanView
    new: _ScanView
    config_differences: tuple[str, ...]


def _check_name(ctx: _Context, check_id: str) -> str:
    check = ctx.new.checks.get(check_id) or ctx.old.checks.get(check_id)
    return check.name if check is not None else check_id


def _only_in(view: _ScanView, other: _ScanView, rule_id: str) -> bool:
    """A RepoSentinel rule that ``view`` ran and ``other`` did not have at all."""
    return rule_id in view.config.rule_versions and rule_id not in other.config.rule_versions


def _not_comparable_reason(ctx: _Context, rule_id: str) -> str | None:
    change = _rule_version_change(rule_id, ctx.old.config, ctx.new.config)
    if change is not None:
        return (
            f"Rule {rule_id} changed from version {change[0]} to version {change[1]} between "
            "the scans, so a difference may come from the rule change rather than from the "
            "repository. Compare two reports made with the same rule version."
        )
    if ctx.config_differences:
        return (
            "The scan settings differ ("
            + "; ".join(ctx.config_differences)
            + "), so the scans could see different files. Compare two reports made with the "
            "same settings."
        )
    return None


def _classify_new(ctx: _Context, sample: Finding) -> tuple[ComparisonStatus, str]:
    reason = _not_comparable_reason(ctx, sample.rule_id)
    if reason is not None:
        return ComparisonStatus.NOT_COMPARABLE, (
            reason + " This may be an existing problem that is only now detected."
        )
    name = _check_name(ctx, sample.check_id)
    may_not_be_new = ", so this may not be new."
    old_check = ctx.old.checks.get(sample.check_id)
    if old_check is None:
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            f"The {name} check did not run in the old scan{may_not_be_new}"
        )
    if old_check.status is not CheckStatus.COMPLETED:
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            _not_completed(name, old_check.status, "old") + " This may not be new."
        )
    if _only_in(ctx.new, ctx.old, sample.rule_id):
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            f"Rule {sample.rule_id} was not part of the old scan (it is newer than the "
            f"RepoSentinel that made the old report){may_not_be_new}"
        )
    examined = ctx.old.examined[sample.check_id]
    if examined is None:
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            f"The {name} check does not record which files it examined, so it is unknown "
            "whether the old scan looked at this file."
        )
    path = sample.path
    if path is None:
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            f"This finding has no file location, so the old scan's file records cannot "
            f"show whether it was examined{may_not_be_new}"
        )
    if path in examined:
        return ComparisonStatus.NEW, (
            f"The {name} check examined {path} in the old scan and did not detect this there."
        )
    old_issue = ctx.old.file_issues.get(path)
    if old_issue is not None:
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
            f"{path} was not examined in the old scan ({_REASON_WORDS[old_issue.reason]}: "
            f"{old_issue.detail}){may_not_be_new}"
        )
    if path not in ctx.old.files:
        blocker = ctx.old.location_blocker(path)
        if blocker is None:
            return ComparisonStatus.NEW, (
                f"{path} was not in the old scan, which listed the repository completely, so "
                "the file is new."
            )
        return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, blocker + " This may not be new."
    return ComparisonStatus.NEW_NOT_EXAMINED_BEFORE, (
        f"The old scan did not examine {path} with the {name} check{may_not_be_new}"
    )


def _classify_absent(ctx: _Context, sample: Finding) -> tuple[ComparisonStatus, str]:
    name = _check_name(ctx, sample.check_id)
    rescan = "Fix the cause and scan again to re-check this."
    new_check = ctx.new.checks.get(sample.check_id)
    if new_check is None:
        return ComparisonStatus.NOT_RECHECKED, (
            f"The {name} check did not run in the new scan. Scan again with the same options "
            "(for example the same --integration flags) to re-check this."
        )
    if new_check.status is not CheckStatus.COMPLETED:
        return ComparisonStatus.NOT_RECHECKED, (
            _not_completed(name, new_check.status, "new", new_check.message) + " " + rescan
        )
    if _only_in(ctx.old, ctx.new, sample.rule_id):
        return ComparisonStatus.NOT_RECHECKED, (
            f"Rule {sample.rule_id} is not part of the new scan (the RepoSentinel that made the "
            "new report does not have it), so nothing looked for this."
        )
    reason = _not_comparable_reason(ctx, sample.rule_id)
    if reason is not None:
        return ComparisonStatus.NOT_COMPARABLE, reason
    examined = ctx.new.examined[sample.check_id]
    if examined is None:
        return ComparisonStatus.NOT_RECHECKED, (
            f"The {name} check does not record which files it examined, so RepoSentinel cannot "
            "confirm that this was re-checked."
        )
    path = sample.path
    if path is None:
        return ComparisonStatus.NOT_RECHECKED, (
            "This finding has no file location, so there is no file record to re-check it with."
        )
    if path in examined:
        version = f", version {sample.rule_version}" if sample.rule_version is not None else ""
        return ComparisonStatus.NOT_DETECTED_ON_RECHECK, (
            f"The {name} check (rule {sample.rule_id}{version}) examined {path} in the new "
            "scan and did not detect this."
        )
    issue = ctx.new.file_issues.get(path)
    if issue is not None:
        return ComparisonStatus.NOT_RECHECKED, (
            f"{path} was not examined in the new scan ({_REASON_WORDS[issue.reason]}: "
            f"{issue.detail}). {rescan}"
        )
    if path in ctx.new.files:
        return ComparisonStatus.NOT_RECHECKED, (
            f"{path} is in the new scan, but the {name} check did not examine it."
        )
    blocker = ctx.new.location_blocker(path)
    if blocker is not None:
        return ComparisonStatus.NOT_RECHECKED, blocker
    return ComparisonStatus.NOT_DETECTED_FILE_REMOVED, (
        f"{path} is not in the new scan, which listed the repository completely (no limit "
        "reached, no parent folder skipped)."
    )


def _tracked(
    ctx: _Context,
    fingerprint: str,
    old_occurrences: list[Finding],
    new_occurrences: list[Finding],
    catalogue: Mapping[str, Rule],
) -> TrackedComparison:
    current = new_occurrences or old_occurrences
    sample = current[0]
    known = catalogue.get(sample.rule_id)
    if old_occurrences and new_occurrences:
        status = ComparisonStatus.STILL_DETECTED
        explanation = (
            f"Detected in both scans: {_n(len(old_occurrences), 'occurrence', 'occurrences')} "
            f"before, {len(new_occurrences)} now."
        )
    elif new_occurrences:
        status, explanation = _classify_new(ctx, sample)
    else:
        status, explanation = _classify_absent(ctx, sample)
    fewer = len(new_occurrences) < len(old_occurrences)
    reminder = is_credential_rule(sample.rule_id) and (
        status in NO_LONGER_DETECTED or (status is ComparisonStatus.STILL_DETECTED and fewer)
    )
    return TrackedComparison(
        fingerprint=fingerprint,
        status=status,
        explanation=explanation,
        rule_id=sample.rule_id,
        # Known rules use RepoSentinel's own text, not what a report file says.
        title=known.title if known is not None else sample.title,
        check_id=sample.check_id,
        path=sample.path,
        severity=max((f.severity for f in current), key=lambda s: s.rank),
        confidence=sample.confidence,
        summary=sample.summary,
        evidence=sample.evidence,
        remediation=known.remediation if known is not None else sample.remediation,
        old_lines=_lines(old_occurrences),
        new_lines=_lines(new_occurrences),
        old_count=len(old_occurrences),
        new_count=len(new_occurrences),
        recheck_limits=_recheck_limits(sample.rule_id, catalogue),
        credential_reminder=reminder,
    )


def _sort_key(finding: TrackedComparison) -> tuple[int, int, str, str, str]:
    return (
        _STATUS_ORDER.index(finding.status),
        -finding.severity.rank,
        finding.path or "",
        finding.rule_id,
        finding.fingerprint,
    )


def _info(report: ScanReport, label: str) -> ReportInfo:
    return ReportInfo(
        label=label,
        target=report.target,
        scanned_at=report.scanned_at,
        tool_version=report.tool_version,
        outcome=report.outcome,
        files_in_scope=report.files_in_scope,
    )


def compare_reports(
    old: ScanReport,
    new: ScanReport,
    *,
    fail_on: Severity | None = Severity.LOW,
    different_roots_declared: bool = False,
    old_label: str = "old report",
    new_label: str = "new report",
) -> ComparisonResult:
    """Compare ``old`` (before) with ``new`` (after). Deterministic and side-effect free."""
    same_target = targets_match(old, new)
    if not same_target and not different_roots_declared:
        raise ComparisonError(
            "the reports were made from different folder paths; confirm they describe the "
            "same repository with --different-roots"
        )
    old_view, new_view = _ScanView.build(old, "old"), _ScanView.build(new, "new")
    ctx = _Context(
        old=old_view,
        new=new_view,
        config_differences=tuple(_config_differences(old_view.config, new_view.config)),
    )
    catalogue = {rule.id: rule for rule in all_rules()}
    old_groups, new_groups = _group(old), _group(new)
    tracked = [
        _tracked(ctx, fp, old_groups.get(fp, []), new_groups.get(fp, []), catalogue)
        for fp in sorted(set(old_groups) | set(new_groups))
    ]

    check_ids = [check.check_id for check in new.checks]
    check_ids += [check.check_id for check in old.checks if check.check_id not in new_view.checks]
    checks: list[CheckComparison] = []
    for check_id in check_ids:
        before, after = old_view.checks.get(check_id), new_view.checks.get(check_id)
        checks.append(
            CheckComparison(
                check_id=check_id,
                name=_check_name(ctx, check_id),
                old_status=before.status if before is not None else None,
                new_status=after.status if after is not None else None,
                old_examined=before.examined if before is not None else None,
                new_examined=after.examined if after is not None else None,
                new_message=after.message if after is not None else "",
            )
        )
    problems: list[str] = []
    for check in checks:
        if check.new_status is None:
            problems.append(
                f"The {check.name} check ran in the old scan but not in the new one, so its "
                "results in the new scan are unknown."
            )
        elif check.new_status is not CheckStatus.COMPLETED:
            problems.append(_not_completed(check.name, check.new_status, "new", check.new_message))
    examined: set[str] = set()
    for result in new.checks:
        if result.status is CheckStatus.COMPLETED and result.examined_paths is not None:
            examined.update(result.examined_paths)

    notes: list[str] = []
    only_new = [check.name for check in checks if check.old_status is None]
    if only_new:
        notes.append(
            "Checks that ran only in the new scan: "
            + ", ".join(only_new)
            + ". Their findings are shown as 'new (not examined before)'."
        )
    if not same_target:
        notes.append(
            f"The reports were made from different folder paths ({old.target} and {new.target}). "
            "You stated with --different-roots that they describe the same repository; "
            "RepoSentinel cannot confirm this."
        )
    if old.tool_version != new.tool_version:
        notes.append(
            f"The reports were made by different RepoSentinel versions ({old.tool_version} and "
            f"{new.tool_version})."
        )
    if new.scanned_at < old.scanned_at:
        notes.append(
            "The second report is older than the first. The comparison treats the first report "
            "as 'before' and the second as 'after'."
        )

    return ComparisonResult(
        old=_info(old, old_label),
        new=_info(new, new_label),
        targets_match=same_target,
        different_roots_declared=different_roots_declared and not same_target,
        findings=tuple(sorted(tracked, key=_sort_key)),
        checks=tuple(checks),
        check_problems=tuple(problems),
        coverage_errors=new.coverage_errors,
        not_examined=tuple(issue for issue in new.coverage if not issue.reason.is_error),
        config_differences=ctx.config_differences,
        notes=tuple(notes),
        fail_on=fail_on,
        files_examined=len(examined),
    )


# --- plain-language summary (shared by every output format) ------------------


def _n(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def headline(result: ComparisonResult) -> str:
    """One line: no longer detected, remaining, unknown. Always shown with the scope."""
    no_longer = len(result.with_status(*NO_LONGER_DETECTED))
    remaining = len(result.with_status(*DETECTED))
    return (
        f"{_n(no_longer, 'finding is', 'findings are')} no longer detected, "
        f"{_n(remaining, 'remains', 'remain')}, {result.unknown_count} unknown."
    )


def summary_sentences(result: ComparisonResult) -> list[str]:
    """The scoped "what is left" summary (docs/product-strategy.md, section 7.2)."""
    s = ComparisonStatus
    old_not_comparable = sum(1 for f in result.with_status(s.NOT_COMPARABLE) if f.old_count)
    new_not_comparable = result.count(s.NOT_COMPARABLE) - old_not_comparable
    completed = sum(1 for check in result.checks if check.new_status is CheckStatus.COMPLETED)
    return [
        f"Of {_n(result.old_tracked, 'tracked finding', 'tracked findings')} in "
        f"{result.old.label}, {result.count(s.NOT_DETECTED_ON_RECHECK)} not detected on "
        f"re-check, {result.count(s.NOT_DETECTED_FILE_REMOVED)} not detected because the file "
        f"was removed, {result.count(s.STILL_DETECTED)} still detected, "
        f"{result.count(s.NOT_RECHECKED)} could not be re-checked and {old_not_comparable} "
        "not comparable.",
        f"{result.new.label} adds {result.count(s.NEW)} new, "
        f"{result.count(s.NEW_NOT_EXAMINED_BEFORE)} new (not examined before) and "
        f"{new_not_comparable} not comparable.",
        f"Checks completed in the new scan: {completed} of {len(result.checks)}. Files examined: "
        f"{result.files_examined}. Unknowns: {result.unknown_count}.",
        "This describes these checks on the current files only; Git history was not scanned.",
    ]


def exit_explanation(result: ComparisonResult) -> str:
    code = result.exit_code
    threshold = result.fail_on.value if result.fail_on is not None else "never"
    if code is ExitCode.INCOMPLETE:
        return "Exit code 3: some results are unknown (not re-checked, not comparable, incomplete)."
    if code is ExitCode.FINDINGS:
        return f"Exit code 1: findings still detected or new at or above --fail-on={threshold}."
    return f"Exit code 0: nothing detected at or above --fail-on={threshold}, nothing unknown."


__all__ = [
    "CREDENTIAL_REMINDER",
    "DETECTED",
    "NO_LONGER_DETECTED",
    "SCOPE_STATEMENT",
    "UNKNOWN",
    "CheckComparison",
    "ComparisonError",
    "ComparisonResult",
    "ComparisonStatus",
    "ReportInfo",
    "TrackedComparison",
    "compare_reports",
    "exit_explanation",
    "headline",
    "is_credential_rule",
    "summary_sentences",
    "targets_match",
]
