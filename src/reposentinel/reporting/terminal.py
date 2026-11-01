"""Human-readable terminal report, rendered with Rich.

Untrusted strings (paths, evidence, messages) are always wrapped in
``rich.text.Text`` objects, which Rich never interprets as markup, and passed
through ``clean`` so control characters cannot inject terminal escape
sequences. The console is also created with markup, emoji and highlighting
disabled, as a second safeguard.
"""

from __future__ import annotations

from typing import TextIO

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from reposentinel.models import (
    SEVERITY_ORDER,
    CheckStatus,
    CoverageReason,
    Finding,
    Outcome,
    ScanReport,
    Severity,
)
from reposentinel.reporting.common import (
    DISCLAIMER,
    OUTCOME_HEADLINES,
    clean,
    excluded_paths,
    report_notes,
)

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
}
_STATUS_STYLES: dict[CheckStatus, str] = {
    CheckStatus.COMPLETED: "green",
    CheckStatus.FAILED: "bold red",
    CheckStatus.SKIPPED: "bold yellow",
}
_OUTCOME_STYLES: dict[Outcome, str] = {
    Outcome.CLEAN: "bold green",
    Outcome.FINDINGS: "bold yellow",
    Outcome.INCOMPLETE: "bold red",
}
_REASON_LABELS: dict[CoverageReason, str] = {
    CoverageReason.EXCLUDED: "excluded",
    CoverageReason.SYMLINK: "links not followed",
    CoverageReason.TOO_LARGE: "too large",
    CoverageReason.BINARY: "binary",
    CoverageReason.UNREADABLE: "unreadable",
    CoverageReason.UNPARSEABLE: "unparseable",
    CoverageReason.LIMIT_REACHED: "limit reached",
}
MAX_PROBLEMS_SHOWN = 20


def make_console(
    file: TextIO | None = None, *, color: bool = True, width: int | None = None
) -> Console:
    return Console(
        file=file,
        markup=False,
        emoji=False,
        highlight=False,
        no_color=None if color else True,  # None lets Rich honour the NO_COLOR variable
        force_terminal=None if color else False,
        width=width,
    )


def _heading(console: Console, title: str) -> None:
    console.print(Text(title, style="bold underline"))


def _details(rows: list[tuple[str, str]]) -> Padding:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(overflow="fold")
    for label, value in rows:
        grid.add_row(label, Text(value))
    return Padding(grid, (0, 0, 0, 6))


def _print_finding(console: Console, finding: Finding) -> None:
    title = Text("  ")
    title.append(finding.rule_id, style="bold")
    title.append("  ")
    title.append(clean(finding.title))
    console.print(title)
    console.print(
        _details(
            [
                ("Location:", clean(finding.location)),
                ("Summary:", clean(finding.summary)),
                ("Evidence:", clean(finding.evidence)),
                ("Confidence:", finding.confidence.value),
            ]
        )
    )


def _print_findings(report: ScanReport, console: Console) -> None:
    _heading(console, "Findings")
    for severity in SEVERITY_ORDER:
        group = [finding for finding in report.findings if finding.severity is severity]
        if not group:
            continue
        console.print(
            Text(f"{severity.value.upper()} ({len(group)})", style=SEVERITY_STYLES[severity])
        )
        for finding in group:
            _print_finding(console, finding)
        console.print()


def _print_remediation(report: ScanReport, console: Console) -> None:
    _heading(console, "How to fix")
    seen: set[str] = set()
    for finding in report.findings:  # most severe first
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        title = Text("  ")
        title.append(finding.rule_id, style="bold")
        title.append("  ")
        title.append(clean(finding.title))
        console.print(title)
        console.print(Padding(Text(clean(finding.remediation)), (0, 0, 0, 6)))
    console.print()


def _print_checks(report: ScanReport, console: Console) -> None:
    _heading(console, "Checks")
    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False, header_style="bold")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Examined", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Note", overflow="fold")
    not_completed = []
    for check in report.checks:
        completed = check.status is CheckStatus.COMPLETED
        if not completed:
            not_completed.append(check)
        table.add_row(
            Text(clean(check.name)),
            Text(check.status.value, style=_STATUS_STYLES[check.status]),
            Text("-" if check.examined is None else str(check.examined)),
            Text(str(check.finding_count) if completed else "-"),
            Text(clean(check.message) if completed else "see below"),
        )
    console.print(Padding(table, (0, 0, 0, 2)))
    # Reasons for failed or skipped checks get the full width: they matter.
    for check in not_completed:
        line = Text(
            f"{clean(check.name)} {check.status.value}: ", style=_STATUS_STYLES[check.status]
        )
        line.append(clean(check.message), style="")
        console.print(Padding(line, (0, 0, 0, 2)))
    console.print()


def _print_coverage(report: ScanReport, console: Console) -> None:
    _heading(console, "Coverage")
    console.print(Text(f"  Files in scope: {report.files_in_scope}"))
    skipped = [
        f"{_REASON_LABELS[reason]} {count}"
        for reason, count in report.coverage_counts().items()
        if not reason.is_error
    ]
    if skipped:
        console.print(Text("  Not scanned (by policy): " + ", ".join(skipped)))
    excluded = excluded_paths(report)
    if excluded:
        shown = ", ".join(
            f"{clean(issue.path)} ({clean(issue.detail)})"
            for issue in excluded[:MAX_PROBLEMS_SHOWN]
        )
        more = len(excluded) - MAX_PROBLEMS_SHOWN
        suffix = f", and {more} more (see the JSON report)" if more > 0 else ""
        console.print(Padding(Text(f"Excluded: {shown}{suffix}"), (0, 0, 0, 2)))
    problems = report.coverage_errors
    if problems:
        console.print(Text(f"  Problems ({len(problems)}):", style="bold red"))
        for issue in problems[:MAX_PROBLEMS_SHOWN]:
            label = _REASON_LABELS[issue.reason]
            console.print(Text(f"    {clean(issue.path)}: {label} ({clean(issue.detail)})"))
        if len(problems) > MAX_PROBLEMS_SHOWN:
            hidden = len(problems) - MAX_PROBLEMS_SHOWN
            console.print(Text(f"    ... and {hidden} more (see the JSON report)"))
    console.print()


def _print_summary(report: ScanReport, console: Console) -> None:
    _heading(console, "Summary")
    counts = ", ".join(f"{sev.value} {n}" for sev, n in report.severity_counts().items())
    console.print(Text(f"  Findings: {len(report.findings)} ({counts})"))
    statuses = ", ".join(
        f"{sum(1 for c in report.checks if c.status is status)} {status.value}"
        for status in CheckStatus
    )
    console.print(Text(f"  Checks:   {statuses}"))
    outcome = report.outcome
    console.print(
        Padding(Text(OUTCOME_HEADLINES[outcome], style=_OUTCOME_STYLES[outcome]), (0, 0, 0, 2))
    )
    for note in report_notes(report):
        console.print(Padding(Text(f"Note: {note}", style="bold yellow"), (0, 0, 0, 2)))
    console.print(Padding(Text(DISCLAIMER, style="dim"), (0, 0, 0, 2)))


def render_terminal(report: ScanReport, console: Console) -> None:
    console.print(Text(f"RepoSentinel {report.tool_version} scan report", style="bold"))
    header = Table.grid(padding=(0, 1))
    header.add_column(no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row("Target:", Text(clean(report.target)))
    header.add_row("Scanned:", Text(report.scanned_at.isoformat()))
    console.print(header)
    console.print()
    if report.findings:
        _print_findings(report, console)
        _print_remediation(report, console)
    _print_checks(report, console)
    _print_coverage(report, console)
    _print_summary(report, console)
