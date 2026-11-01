"""Human-readable comparison of two scan reports, rendered with Rich.

The same safeguards as the scan report apply: report-derived strings (paths,
evidence, messages, and explanations that contain them) are wrapped in
``rich.text.Text`` and passed through ``clean``, and the console has markup,
emoji and highlighting disabled.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from reposentinel.compare import (
    CREDENTIAL_REMINDER,
    SCOPE_STATEMENT,
    ComparisonResult,
    TrackedComparison,
    headline,
    summary_sentences,
)
from reposentinel.models import SEVERITY_ORDER, CheckStatus, CoverageIssue
from reposentinel.reporting.common import clean
from reposentinel.reporting.compare_common import (
    COMPARE_DISCLAIMER,
    MAX_PATHS_SHOWN,
    SECTION_DETECTED,
    SECTION_NO_LONGER,
    SECTION_NOT_EXAMINED,
    SECTION_REMINDERS,
    SECTION_UNKNOWN,
    detected,
    location_text,
    no_longer_detected,
    reminders,
    status_text,
    unknown,
)
from reposentinel.reporting.terminal import SEVERITY_STYLES

_STATUS_STYLES: dict[CheckStatus | None, str] = {
    CheckStatus.COMPLETED: "green",
    CheckStatus.FAILED: "bold red",
    CheckStatus.SKIPPED: "bold yellow",
    None: "bold yellow",
}


def _heading(console: Console, title: str, count: int | None = None) -> None:
    label = title if count is None else f"{title} ({count})"
    console.print(Text(label, style="bold underline"))


def _none(console: Console, text: str = "None.") -> None:
    console.print(Padding(Text(text, style="dim"), (0, 0, 0, 2)))


def _details(rows: list[tuple[str, str]]) -> Padding:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(overflow="fold")
    for label, value in rows:
        grid.add_row(label, Text(clean(value)))
    return Padding(grid, (0, 0, 0, 6))


def _title(finding: TrackedComparison, style: str = "") -> Text:
    title = Text("  ")
    title.append(clean(finding.rule_id), style="bold")
    title.append("  ")
    title.append(clean(finding.title))
    title.append("  ")
    title.append(f"[{status_text(finding)}]", style=style or "bold")
    return title


def _print_detected(result: ComparisonResult, console: Console) -> None:
    group = detected(result)
    _heading(console, SECTION_DETECTED, len(group))
    if not group:
        _none(console)
    fix_shown: set[str] = set()  # each rule's fix text is printed once
    for severity in SEVERITY_ORDER:
        items = [finding for finding in group if finding.severity is severity]
        if not items:
            continue
        console.print(
            Text(f"{severity.value.upper()} ({len(items)})", style=SEVERITY_STYLES[severity])
        )
        for finding in items:
            fix = finding.remediation
            if finding.rule_id in fix_shown:
                fix = f"See {finding.rule_id} above."
            fix_shown.add(finding.rule_id)
            console.print(_title(finding))
            console.print(
                _details(
                    [
                        ("Location:", location_text(finding)),
                        ("Evidence:", finding.evidence),
                        ("Why:", finding.explanation),
                        ("Confidence:", finding.confidence.value),
                        ("Fix:", fix),
                    ]
                )
            )
    console.print()


def _print_issue_list(console: Console, title: str, issues: tuple[CoverageIssue, ...]) -> None:
    console.print(Padding(Text(f"{title} ({len(issues)}):", style="bold"), (0, 0, 0, 2)))
    for issue in issues[:MAX_PATHS_SHOWN]:
        reason = issue.reason.value.replace("_", " ")
        console.print(Text(f"    {clean(issue.path)}: {reason} ({clean(issue.detail)})"))
    hidden = len(issues) - MAX_PATHS_SHOWN
    if hidden > 0:
        console.print(Text(f"    ... and {hidden} more (see the new JSON report)"))


def _print_unknown(result: ComparisonResult, console: Console) -> None:
    items = unknown(result)
    _heading(console, SECTION_UNKNOWN, result.unknown_count)
    if not result.unknown_count:
        _none(console, "None: every finding in the old report was re-checked.")
    for finding in items:
        console.print(_title(finding, "bold yellow"))
        console.print(
            _details(
                [
                    ("Location:", location_text(finding)),
                    ("Severity:", finding.severity.value),
                    ("Reason:", finding.explanation),
                ]
            )
        )
    for problem in result.check_problems:
        console.print(Padding(Text("Check: " + clean(problem), style="bold yellow"), (0, 0, 0, 2)))
    if result.coverage_errors:
        _print_issue_list(
            console, "Files or folders the new scan could not cover", result.coverage_errors
        )
    console.print()


def _print_not_examined(result: ComparisonResult, console: Console) -> None:
    _heading(console, SECTION_NOT_EXAMINED, len(result.not_examined))
    if not result.not_examined:
        _none(
            console, "Nothing was skipped by policy (exclusions, size limit, binary files, links)."
        )
    else:
        _print_issue_list(console, "Skipped by policy", result.not_examined)
    console.print()


def _print_reminders(result: ComparisonResult, console: Console) -> None:
    items = reminders(result)
    _heading(console, SECTION_REMINDERS, len(items))
    if not items:
        _none(console, "None: no credential finding became less detected.")
    else:
        console.print(Padding(Text(CREDENTIAL_REMINDER, style="bold yellow"), (0, 0, 0, 2)))
    for finding in items:
        line = Text("    ")
        line.append(clean(finding.rule_id), style="bold")
        line.append(f"  {clean(location_text(finding))}  ({clean(status_text(finding))})")
        console.print(line)
    console.print()


def _print_no_longer(result: ComparisonResult, console: Console) -> None:
    items = no_longer_detected(result)
    _heading(console, SECTION_NO_LONGER, len(items))
    if not items:
        _none(console)
    for finding in items:
        console.print(_title(finding, "bold green"))
        console.print(
            _details(
                [
                    ("Location:", location_text(finding)),
                    ("Severity:", finding.severity.value),
                    ("Re-check:", finding.explanation),
                    ("Does not show:", finding.recheck_limits),
                ]
            )
        )
    console.print()


def _print_checks(result: ComparisonResult, console: Console) -> None:
    _heading(console, "Checks")
    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False, header_style="bold")
    table.add_column("Check")
    table.add_column("Old scan")
    table.add_column("New scan")
    table.add_column("Examined (new)", justify="right")
    for check in result.checks:
        table.add_row(
            Text(clean(check.name)),
            Text(
                check.old_status.value if check.old_status else "did not run",
                style=_STATUS_STYLES[check.old_status],
            ),
            Text(
                check.new_status.value if check.new_status else "did not run",
                style=_STATUS_STYLES[check.new_status],
            ),
            Text("-" if check.new_examined is None else str(check.new_examined)),
        )
    console.print(Padding(table, (0, 0, 0, 2)))
    console.print()


def _print_notes(result: ComparisonResult, console: Console) -> None:
    if not (result.config_differences or result.notes):
        return
    _heading(console, "Notes")
    for difference in result.config_differences:
        console.print(
            Padding(
                Text("Settings differ: " + clean(difference), style="bold yellow"), (0, 0, 0, 2)
            )
        )
    for note in result.notes:
        console.print(Padding(Text("Note: " + clean(note), style="bold yellow"), (0, 0, 0, 2)))
    console.print()


def render_compare_terminal(result: ComparisonResult, console: Console) -> None:
    console.print(Text("RepoSentinel comparison", style="bold"))
    header = Table.grid(padding=(0, 1))
    header.add_column(no_wrap=True)
    header.add_column(overflow="fold")
    for label, info in (("Old:", result.old), ("New:", result.new)):
        header.add_row(
            label,
            Text(
                f"{clean(info.label)} (scanned {info.scanned_at.isoformat()}, "
                f"outcome {info.outcome.value}, RepoSentinel {clean(info.tool_version)})"
            ),
        )
    if result.targets_match:
        header.add_row("Target:", Text(clean(result.new.target)))
    else:
        header.add_row("Old target:", Text(clean(result.old.target)))
        header.add_row("New target:", Text(clean(result.new.target)))
        header.add_row("", Text("Declared the same repository by you (--different-roots)."))
    console.print(header)
    console.print()
    console.print(Text(clean(headline(result)), style="bold"))
    console.print(Text(SCOPE_STATEMENT, style="bold"))
    console.print()

    _print_detected(result, console)
    _print_unknown(result, console)
    _print_not_examined(result, console)
    _print_reminders(result, console)
    _print_no_longer(result, console)
    _print_checks(result, console)
    _print_notes(result, console)

    _heading(console, "Summary")
    for sentence in summary_sentences(result):
        console.print(Padding(Text(clean(sentence)), (0, 0, 0, 2)))
    console.print(Padding(Text(COMPARE_DISCLAIMER, style="dim"), (0, 0, 0, 2)))
