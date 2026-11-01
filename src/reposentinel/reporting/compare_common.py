"""Wording and helpers shared by every comparison output format.

The sections follow docs/product-strategy.md, section 7.2. Every format lists
every section, even when it is empty, so a reader can see that a category was
considered rather than forgotten.
"""

from __future__ import annotations

from reposentinel.compare import (
    DETECTED,
    NO_LONGER_DETECTED,
    UNKNOWN,
    ComparisonResult,
    ComparisonStatus,
    TrackedComparison,
)

COMPARE_DISCLAIMER = (
    "Findings are potential indicators for human review, not confirmed vulnerabilities. "
    "'Not detected on re-check' means only that the rule no longer matches in the files the "
    "check examined; the underlying problem may remain. This comparison is not a security "
    "assessment of the repository."
)

SECTION_DETECTED = "Still detected and new"
SECTION_UNKNOWN = "Unknown"
SECTION_NOT_EXAMINED = "Not examined in the new scan"
SECTION_REMINDERS = "Credential reminders"
SECTION_NO_LONGER = "No longer detected"
MAX_LINES_SHOWN = 10
MAX_PATHS_SHOWN = 20


def status_text(finding: TrackedComparison) -> str:
    """The status label, with the occurrence counts when they changed."""
    if finding.status is ComparisonStatus.STILL_DETECTED and finding.old_count != finding.new_count:
        return f"{finding.status.label} ({finding.old_count} to {finding.new_count})"
    return finding.status.label


def _line_list(lines: tuple[int, ...]) -> str:
    shown = ", ".join(str(line) for line in lines[:MAX_LINES_SHOWN])
    more = len(lines) - MAX_LINES_SHOWN
    word = "line" if len(lines) == 1 else "lines"
    return f"{word} {shown}" + (f" and {more} more" if more > 0 else "")


def location_text(finding: TrackedComparison) -> str:
    """Path and lines: current lines for detected findings, old lines otherwise."""
    if finding.path is None:
        return "(repository)"
    parts: list[str] = []
    if finding.new_lines:
        parts.append(_line_list(finding.new_lines))
    if finding.old_lines and finding.old_lines != finding.new_lines:
        parts.append("before: " + _line_list(finding.old_lines))
    return finding.path + (f" ({'; '.join(parts)})" if parts else "")


def detected(result: ComparisonResult) -> list[TrackedComparison]:
    return result.with_status(*DETECTED)


def unknown(result: ComparisonResult) -> list[TrackedComparison]:
    return result.with_status(*UNKNOWN)


def no_longer_detected(result: ComparisonResult) -> list[TrackedComparison]:
    return result.with_status(*NO_LONGER_DETECTED)


def reminders(result: ComparisonResult) -> list[TrackedComparison]:
    return [finding for finding in result.findings if finding.credential_reminder]
