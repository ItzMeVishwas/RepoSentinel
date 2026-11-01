"""Wording and helpers shared by every report format."""

from __future__ import annotations

from reposentinel.models import CoverageIssue, CoverageReason, Outcome, ScanReport
from reposentinel.redact import sanitize_text

DISCLAIMER = (
    "Findings are potential indicators for human review, not confirmed vulnerabilities. "
    "A clean result means only that the checks listed found nothing; it does not mean the "
    "repository is secure."
)

OUTCOME_HEADLINES: dict[Outcome, str] = {
    Outcome.CLEAN: "CLEAN: every check completed and none reported a finding.",
    Outcome.FINDINGS: "FINDINGS: every check completed; review the findings listed.",
    Outcome.INCOMPLETE: (
        "INCOMPLETE: at least one check or file could not be scanned. Results may be "
        "missing; do not treat this scan as a pass."
    ),
}


def report_notes(report: ScanReport) -> list[str]:
    """Plain-language caveats about this particular scan, shown with the outcome."""
    notes: list[str] = []
    if report.files_in_scope == 0:
        notes.append(
            "No files were in scope, so nothing was examined. Check the path and the "
            "exclusions listed under Coverage."
        )
    return notes


def excluded_paths(report: ScanReport) -> list[CoverageIssue]:
    """Paths skipped by the default exclusions, so readers can see what was not scanned."""
    return [issue for issue in report.coverage if issue.reason is CoverageReason.EXCLUDED]


def clean(text: str | None, max_length: int = 1000) -> str:
    """Untrusted text made safe for display (see ``redact.sanitize_text``)."""
    return sanitize_text(text or "", max_length=max_length)
