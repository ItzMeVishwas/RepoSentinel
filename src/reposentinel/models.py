"""Core data model shared by every check, the scan engine, and every report.

Every check, native or external, produces the same ``Finding`` type, so the
reports never need to know which check found something. All classes here are
frozen (immutable) dataclasses: once a finding is created it cannot be
modified by accident, for example by a report that "tidies up" its text.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime


class CheckError(Exception):
    """A check failure whose message RepoSentinel wrote itself.

    The engine shows the message of this exception (redacted and sanitised)
    when a check fails. Raise it only with text composed by RepoSentinel: no
    repository content, file names, tool output or other untrusted text. Any
    other exception is reported by its type only.
    """


class Severity(enum.StrEnum):
    """How much damage the issue could cause *if* it is a true positive."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher rank means more severe. Used for sorting and thresholds."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}

# Most severe first; used wherever output is grouped by severity.
SEVERITY_ORDER: tuple[Severity, ...] = tuple(sorted(Severity, key=lambda s: -s.rank))


class Confidence(enum.StrEnum):
    """How likely the pattern match is a true positive.

    No RepoSentinel finding is a *confirmed* vulnerability: findings are
    indicators that a human should review. Confidence helps prioritise that
    review.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CheckStatus(enum.StrEnum):
    COMPLETED = "completed"  # the check ran to the end
    FAILED = "failed"  # the check raised an error; its results are missing
    SKIPPED = "skipped"  # the check could not run (e.g. tool not installed)


class Outcome(enum.StrEnum):
    CLEAN = "clean"  # every check completed and reported nothing
    FINDINGS = "findings"  # every check completed and at least one finding exists
    INCOMPLETE = "incomplete"  # something did not run or could not be read


class CoverageReason(enum.StrEnum):
    """Why a path was not (fully) examined."""

    EXCLUDED = "excluded"  # default-excluded directory (.git, .venv, ...) or report file
    SYMLINK = "symlink"  # symbolic link or junction; never followed
    TOO_LARGE = "too_large"  # larger than the file-size limit
    BINARY = "binary"  # looks like binary data
    UNREADABLE = "unreadable"  # operating-system error while listing or reading
    UNPARSEABLE = "unparseable"  # a check could not parse the file's format
    LIMIT_REACHED = "limit_reached"  # file-count or depth limit stopped traversal

    @property
    def is_error(self) -> bool:
        """Errors mean the scan did not cover something it intended to cover."""
        return self in _ERROR_REASONS


_ERROR_REASONS = frozenset(
    {CoverageReason.UNREADABLE, CoverageReason.UNPARSEABLE, CoverageReason.LIMIT_REACHED}
)


@dataclass(frozen=True, slots=True)
class Rule:
    """Documentation and defaults for one kind of finding.

    The ``id`` is stable: once released it must keep the same meaning so that
    scripts and CI configurations that refer to it keep working.

    ``version`` must be increased whenever the rule's matching behaviour
    changes. Comparisons between scans made with different versions of a rule
    are reported as "not comparable", because a difference could come from the
    rule change rather than from the repository.
    """

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    severity_rationale: str
    remediation: str
    limitations: str
    references: tuple[str, ...] = ()
    version: int = 1
    # What a re-check that no longer detects this rule can NOT show.
    recheck_limits: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """One potential security issue: one *occurrence* at one location.

    ``evidence`` must never contain a secret value; checks redact it before
    creating the finding (see ``reposentinel.redact``).

    ``fingerprint`` identifies the *tracked finding* this occurrence belongs
    to. Several occurrences (for example two tokens in one file) can share one
    fingerprint; each keeps its own ``path`` and ``line``. An occurrence has no
    stable identity of its own. ``identity`` holds the rule-specific inputs for
    the fingerprint (see ``reposentinel.identity``); the engine turns them into
    the fingerprint and then clears them, so they are never stored or reported.
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: str
    remediation: str
    check_id: str
    path: str | None = None  # POSIX-style path relative to the scanned root
    line: int | None = None  # 1-based line number
    identity: tuple[str, ...] = ()  # fingerprint inputs; cleared by the engine
    fingerprint: str = ""  # "rs1:" + SHA-256 hex; set by the engine
    rule_version: int | None = None  # None for rules defined outside RepoSentinel

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("Finding.rule_id must not be empty")
        if self.line is not None and self.line < 1:
            raise ValueError("Finding.line is 1-based and must be >= 1")
        if self.line is not None and self.path is None:
            raise ValueError("Finding.line requires Finding.path")

    @property
    def location(self) -> str:
        if self.path is None:
            return "(repository)"
        return self.path if self.line is None else f"{self.path}:{self.line}"

    def sort_key(self) -> tuple[int, str, int, str, str]:
        """Most severe first, then by file, line, rule and evidence."""
        return (-self.severity.rank, self.path or "", self.line or 0, self.rule_id, self.evidence)


@dataclass(frozen=True, slots=True)
class CoverageIssue:
    """A path that was skipped, or only partly examined, and why."""

    path: str  # POSIX-style path relative to the scanned root; "." is the root
    reason: CoverageReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    name: str
    status: CheckStatus
    finding_count: int = 0
    examined: int | None = 0  # items (usually files) inspected; None if unknown
    message: str = ""  # note, skip reason, or (sanitised) error description
    # The exact files this check examined (POSIX paths, sorted). None means the
    # check does not report it (for example an external tool), so nothing can
    # be concluded about which files it looked at.
    examined_paths: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """The settings that decide what a scan could see. Recorded for comparisons."""

    checks: tuple[str, ...]  # check IDs requested, in order
    rule_versions: Mapping[str, int]  # rule ID -> version, for RepoSentinel's own rules
    limits: Mapping[str, int]  # max_file_size, max_files, max_depth
    exclusions: Mapping[str, tuple[str, ...]]  # default exclusion lists


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Everything a report needs. Built once by the engine, then only read."""

    target: str
    tool_version: str
    scanned_at: datetime
    files_in_scope: int  # files left after exclusions and limits
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]  # already sorted with Finding.sort_key
    coverage: tuple[CoverageIssue, ...]  # already sorted by path and reason
    files: tuple[str, ...] = ()  # every in-scope file (POSIX paths, sorted)
    scan_config: ScanConfig | None = None  # None only for hand-built reports

    @property
    def coverage_errors(self) -> tuple[CoverageIssue, ...]:
        return tuple(issue for issue in self.coverage if issue.reason.is_error)

    @property
    def outcome(self) -> Outcome:
        if (
            not self.checks
            or any(check.status is not CheckStatus.COMPLETED for check in self.checks)
            or self.coverage_errors
        ):
            return Outcome.INCOMPLETE
        return Outcome.FINDINGS if self.findings else Outcome.CLEAN

    def severity_counts(self) -> dict[Severity, int]:
        """Counts for every severity, most severe first (zeros included)."""
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def rule_counts(self) -> dict[str, int]:
        """Counts per rule ID, sorted by rule ID."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return dict(sorted(counts.items()))

    def coverage_counts(self) -> dict[CoverageReason, int]:
        counts: dict[CoverageReason, int] = {}
        for issue in self.coverage:
            counts[issue.reason] = counts.get(issue.reason, 0) + 1
        return {reason: counts[reason] for reason in CoverageReason if reason in counts}
