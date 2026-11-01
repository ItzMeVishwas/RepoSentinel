"""Run checks against a repository and assemble a ``ScanReport``.

The engine is the only place that decides what a scan *means*:

* each check runs in isolation, so one broken check becomes a "failed"
  status in the report instead of a crash that hides every other result;
* every finding, check message and coverage detail passes through one
  redaction step, so text copied from the repository (a workflow step name,
  a YAML error, a tool's output) cannot carry a credential into a report;
* findings are de-duplicated and sorted, so output is deterministic;
* the exit-code policy lives here, next to the outcome logic it depends on.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from reposentinel import __version__
from reposentinel.checks import Check, CheckSkipped
from reposentinel.checks.secrets import redact_known_secrets
from reposentinel.context import ScanContext
from reposentinel.identity import fingerprint
from reposentinel.models import (
    CheckError,
    CheckResult,
    CheckStatus,
    CoverageIssue,
    Finding,
    Outcome,
    ScanConfig,
    ScanReport,
    Severity,
)
from reposentinel.redact import sanitize_text
from reposentinel.walker import (
    DEFAULT_EXCLUDED_DIR_PATTERNS,
    DEFAULT_EXCLUDED_DIRS,
    DEFAULT_EXCLUDED_FILE_PATTERNS,
    ScanLimits,
    collect_files,
)


class ExitCode(enum.IntEnum):
    OK = 0  # scan complete; nothing at or above the --fail-on threshold
    FINDINGS = 1  # scan complete; findings at or above the threshold
    USAGE = 2  # invalid arguments or path (also used by the CLI framework)
    INCOMPLETE = 3  # a check failed or was skipped, files could not be read, or internal error


def describe_exception(exc: BaseException) -> str:
    """A short description of an exception that never quotes repository text.

    An exception raised while processing a file can carry that file's content
    in its message (a key name, a decoded fragment), and redaction cannot
    recognise every credential. So only the exception type is reported, plus
    the operating system's own description for OS errors.
    """
    name = type(exc).__name__
    if isinstance(exc, OSError) and exc.strerror:
        name = f"{name} ({exc.strerror})"
    return sanitize_text(redact_known_secrets(name), max_length=300) + (
        " (details withheld because they may quote repository content)"
    )


def redact_finding(finding: Finding) -> Finding:
    """Last line of defence: mask credential patterns in every text field.

    Checks already redact what they match, but some text is copied from the
    repository for context (for example a workflow step name) and could
    itself contain a credential. Paths are left unchanged so findings can
    still be located.
    """
    return dataclasses.replace(
        finding,
        title=redact_known_secrets(finding.title),
        summary=redact_known_secrets(finding.summary),
        evidence=redact_known_secrets(finding.evidence),
        remediation=redact_known_secrets(finding.remediation),
    )


def _redact_issue(issue: CoverageIssue) -> CoverageIssue:
    return dataclasses.replace(issue, detail=redact_known_secrets(issue.detail))


def with_fingerprint(finding: Finding) -> Finding:
    """Compute the tracked-finding fingerprint and drop the raw identity inputs.

    Done here, once, for every check and integration, so no check can forget
    it and the raw inputs (for example a job ID) never reach a report.
    """
    return dataclasses.replace(
        finding,
        fingerprint=fingerprint(finding.rule_id, finding.path, finding.identity),
        identity=(),
    )


def build_scan_config(checks: Sequence[Check], limits: ScanLimits) -> ScanConfig:
    """Record the settings that decide what this scan could see."""
    rule_versions = {rule.id: rule.version for check in checks for rule in check.rules}
    return ScanConfig(
        checks=tuple(check.id for check in checks),
        rule_versions=dict(sorted(rule_versions.items())),
        limits={
            "max_file_size": limits.max_file_size,
            "max_files": limits.max_files,
            "max_depth": limits.max_depth,
        },
        exclusions={
            "dirs": tuple(sorted(DEFAULT_EXCLUDED_DIRS)),
            "dir_patterns": DEFAULT_EXCLUDED_DIR_PATTERNS,
            "file_patterns": DEFAULT_EXCLUDED_FILE_PATTERNS,
            "virtual_environment_marker": ("pyvenv.cfg",),
        },
    )


def run_scan(
    root: Path,
    checks: Sequence[Check],
    limits: ScanLimits | None = None,
) -> ScanReport:
    """Scan ``root`` (an existing directory) with ``checks``."""
    limits = limits or ScanLimits()
    inventory = collect_files(root, limits)
    context = ScanContext(inventory, limits)

    results: list[CheckResult] = []
    findings: dict[tuple[str, str | None, int | None, str], Finding] = {}
    for check in checks:
        try:
            output = check.run(context)
        except CheckSkipped as skipped:
            results.append(
                CheckResult(
                    check.id,
                    check.name,
                    CheckStatus.SKIPPED,
                    examined=None,
                    message=sanitize_text(redact_known_secrets(str(skipped))),
                )
            )
            continue
        except Exception as exc:  # isolate any failure inside a check
            message = (
                sanitize_text(redact_known_secrets(str(exc)), max_length=300)
                if isinstance(exc, CheckError)  # text written by RepoSentinel itself
                else describe_exception(exc)
            )
            results.append(
                CheckResult(
                    check.id, check.name, CheckStatus.FAILED, examined=None, message=message
                )
            )
            continue

        new = 0
        for finding in map(redact_finding, output.findings):
            key = (finding.rule_id, finding.path, finding.line, finding.evidence)
            if key not in findings:
                findings[key] = with_fingerprint(finding)
                new += 1
        examined_paths = (
            None if output.examined_paths is None else tuple(sorted(set(output.examined_paths)))
        )
        results.append(
            CheckResult(
                check.id,
                check.name,
                CheckStatus.COMPLETED,
                finding_count=new,
                examined=output.examined,
                message=sanitize_text(redact_known_secrets(output.message)),
                examined_paths=examined_paths,
            )
        )

    return ScanReport(
        target=str(inventory.root),
        tool_version=__version__,
        scanned_at=datetime.now(UTC).replace(microsecond=0),
        files_in_scope=len(inventory.files),
        checks=tuple(results),
        findings=tuple(sorted(findings.values(), key=Finding.sort_key)),
        coverage=tuple(_redact_issue(issue) for issue in context.issues),
        files=tuple(entry.path for entry in inventory.files),
        scan_config=build_scan_config(checks, limits),
    )


def exit_code_for(report: ScanReport, fail_on: Severity | None) -> ExitCode:
    """Map a report to an exit code.

    ``fail_on`` is the lowest severity that should fail the run; ``None``
    means findings never fail the run (an incomplete scan still does).
    An incomplete scan takes priority: its findings may be missing results.
    """
    if report.outcome is Outcome.INCOMPLETE:
        return ExitCode.INCOMPLETE
    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in report.findings):
        return ExitCode.FINDINGS
    return ExitCode.OK
