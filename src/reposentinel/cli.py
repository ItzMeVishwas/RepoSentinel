"""Command-line interface: ``reposentinel scan PATH``, ``reposentinel compare
OLD NEW`` and ``reposentinel rules``.

Exit codes for ``scan`` (see ``engine.ExitCode``):

  0  scan complete, no finding at or above --fail-on
  1  scan complete, at least one finding at or above --fail-on
  2  invalid arguments or path
  3  scan incomplete (a check failed or was skipped, a file could not be
     read or parsed, a limit was reached) or an internal error

Exit codes for ``compare``, first match wins (see ``compare.ComparisonResult``):

  2  invalid input: a report is unreadable, malformed, too large or of an
     unsupported schema, or the target paths differ without --different-roots
  3  any unknown result (not re-checked, not comparable, a check that failed,
     was skipped or did not run in the new scan, a coverage error in the new
     scan), whatever --fail-on says; also used for internal errors
  1  a still-detected or new finding at or above --fail-on
  0  none of the above
"""

from __future__ import annotations

import contextlib
import enum
import fnmatch
import io
import os
import sys
import threading
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from reposentinel import __version__
from reposentinel.checks import Check, all_rules, default_checks
from reposentinel.checks.secrets import redact_known_secrets
from reposentinel.compare import (
    SCOPE_STATEMENT,
    ComparisonError,
    ComparisonResult,
    compare_reports,
    exit_explanation,
    headline,
)
from reposentinel.engine import ExitCode, describe_exception, exit_code_for, run_scan
from reposentinel.integrations import GitleaksCheck
from reposentinel.models import ScanReport, Severity
from reposentinel.redact import sanitize_text
from reposentinel.report_loader import ReportError, load_report
from reposentinel.reporting import make_console, render_html, render_json, render_terminal
from reposentinel.reporting.compare_html import render_compare_html
from reposentinel.reporting.compare_json import render_compare_json
from reposentinel.reporting.compare_terminal import render_compare_terminal
from reposentinel.reporting.sarif import render_sarif
from reposentinel.reporting.terminal import SEVERITY_STYLES
from reposentinel.walker import (
    DEFAULT_EXCLUDED_FILE_PATTERNS,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    ScanLimits,
)

INTERRUPTED_EXIT_CODE = 130  # the conventional exit status after Ctrl+C (128 + SIGINT)

app = typer.Typer(
    name="reposentinel",
    help=(
        "Audit a local repository for selected security issues: risky files, hard-coded "
        "credential patterns and unsafe GitHub Actions workflows. Runs offline and never "
        "executes code from the scanned repository."
    ),
    epilog=(
        "Examples: 'reposentinel scan .'  |  'reposentinel scan . -f json -o before.json'  |  "
        "'reposentinel compare before.json after.json'  |  'reposentinel ui'. "
        "A run without findings means only that these checks found nothing in the files they "
        "examined; Git history is not scanned."
    ),
    no_args_is_help=True,
    add_completion=False,
    # Typer's pretty tracebacks show local variables, which could include file
    # contents (and therefore secrets). Never enable them for this tool.
    pretty_exceptions_enable=False,
)


class OutputFormat(enum.StrEnum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class FailOn(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NEVER = "never"

    def threshold(self) -> Severity | None:
        return None if self is FailOn.NEVER else Severity(self.value)


class Integration(enum.StrEnum):
    GITLEAKS = "gitleaks"


INTEGRATION_CHECKS: dict[Integration, type[Check]] = {Integration.GITLEAKS: GitleaksCheck}


class UsageProblem(Exception):
    """An input problem the user can fix; reported without a traceback."""


class ReportWriteError(Exception):
    """The scan finished but its report could not be saved."""


def write_report(output: Path, content: str) -> None:
    try:
        output.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ReportWriteError(f"could not write the report to {output}: {exc.strerror}") from None


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reposentinel {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """RepoSentinel command group."""


def _error(message: str) -> None:
    make_console(sys.stderr, color=False).print(Text(f"Error: {message}"))


def validate_target(path: Path) -> Path:
    """Return the resolved directory to scan, or raise UsageProblem."""
    if not path.exists():
        raise UsageProblem(f"path not found: {path}")
    if not path.is_dir():
        raise UsageProblem(
            f"not a directory: {path}. Pass the repository folder, not a single file."
        )
    resolved = path.resolve()
    try:
        with os.scandir(resolved) as iterator:
            next(iterator, None)
    except PermissionError:
        raise UsageProblem(
            f"permission denied: cannot list the contents of {path}. "
            "Check that your user account can open this folder."
        ) from None
    except OSError as exc:
        raise UsageProblem(f"cannot read directory {path}: {exc.strerror or exc}") from None
    return resolved


def validate_output(output: Path | None) -> Path | None:
    if output is None:
        return None
    if output.is_dir():
        raise UsageProblem(f"--output points to a directory: {output}. Give a file name.")
    parent = output.resolve().parent
    if not parent.is_dir():
        raise UsageProblem(f"the folder for --output does not exist: {parent}")
    return output


def render(report: ScanReport, fmt: OutputFormat, *, color: bool) -> str:
    """Render a report as a string (used when writing to a file)."""
    if fmt is OutputFormat.JSON:
        return render_json(report)
    if fmt is OutputFormat.HTML:
        return render_html(report)
    if fmt is OutputFormat.SARIF:
        return render_sarif(report)
    buffer = io.StringIO()
    render_terminal(report, make_console(buffer, color=color, width=100))
    return buffer.getvalue()


def _report_inside_target(output: Path, target: Path) -> bool:
    excluded = any(
        fnmatch.fnmatchcase(output.name, pattern) for pattern in DEFAULT_EXCLUDED_FILE_PATTERNS
    )
    return output.resolve().is_relative_to(target) and not excluded


def _exit_explanation(code: ExitCode, fail_on: FailOn) -> str:
    return {
        ExitCode.OK: f"Exit code 0: no findings at or above --fail-on={fail_on.value}.",
        ExitCode.FINDINGS: f"Exit code 1: findings at or above --fail-on={fail_on.value}.",
        ExitCode.INCOMPLETE: "Exit code 3: the scan is incomplete.",
    }.get(code, f"Exit code {int(code)}.")


@app.command(
    epilog=(
        "Exit codes: 0 complete, nothing at or above --fail-on; 1 findings at or above "
        "--fail-on; 2 usage error; 3 incomplete scan (a check failed or was skipped, files "
        "could not be read, or a limit was reached). "
        "Examples: 'reposentinel scan .'  |  'reposentinel scan . -f sarif -o reposentinel.sarif'"
    )
)
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Repository directory to scan (default: the current directory).",
            show_default=False,
        ),
    ] = Path("."),
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report format: text, json, html, or sarif (SARIF 2.1.0 for code-scanning tools).",
            case_sensitive=False,
        ),
    ] = OutputFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the report to this file (UTF-8) instead of standard output.",
            show_default=False,
        ),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Lowest severity that makes the command exit with code 1.",
            case_sensitive=False,
        ),
    ] = FailOn.LOW,
    max_file_size_kb: Annotated[
        int,
        typer.Option("--max-file-size-kb", min=1, help="Skip files larger than this many KiB."),
    ] = DEFAULT_MAX_FILE_SIZE // 1024,
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files", min=1, help="Stop after this many files (the scan is then incomplete)."
        ),
    ] = DEFAULT_MAX_FILES,
    integration: Annotated[
        list[Integration] | None,
        typer.Option(
            "--integration",
            help="Experimental: also run an installed external scanner (repeatable). It must "
            "already be on PATH; RepoSentinel never downloads tools.",
            case_sensitive=False,
            show_default=False,
        ),
    ] = None,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable colours in terminal output.")
    ] = False,
) -> None:
    """Scan a repository directory and report potential security issues."""
    try:
        target = validate_target(path)
        output = validate_output(output)
    except UsageProblem as problem:
        _error(str(problem))
        raise typer.Exit(ExitCode.USAGE) from None

    checks: list[Check] = default_checks()
    for name in dict.fromkeys(integration or []):  # de-duplicate, keep order
        checks.append(INTEGRATION_CHECKS[name]())
    limits = ScanLimits(max_file_size=max_file_size_kb * 1024, max_files=max_files)
    color = not no_color and output is None

    try:
        report = run_scan(target, checks, limits)
        code = exit_code_for(report, fail_on.threshold())
        if output is not None:
            write_report(output, render(report, output_format, color=False))
        elif output_format is OutputFormat.TEXT:
            console = make_console(color=color)
            render_terminal(report, console)
            console.print(Text(_exit_explanation(code, fail_on), style="dim"))
        else:
            typer.echo(render(report, output_format, color=False), nl=False)
    except ReportWriteError as problem:
        _error(str(problem))
        raise typer.Exit(ExitCode.INCOMPLETE) from None
    except KeyboardInterrupt:
        _error("scan interrupted (Ctrl+C); no report was written.")
        raise typer.Exit(INTERRUPTED_EXIT_CODE) from None
    except Exception as exc:  # never show a raw traceback (it could include file contents)
        _error(f"internal error: {describe_exception(exc)}. This is a bug in RepoSentinel.")
        raise typer.Exit(ExitCode.INCOMPLETE) from None

    if output is not None:
        stderr = make_console(sys.stderr, color=False)
        stderr.print(
            Text(
                f"Wrote {output_format.value} report to {output} "
                f"(outcome: {report.outcome.value}, findings: {len(report.findings)}). "
                + _exit_explanation(code, fail_on)
            )
        )
        if _report_inside_target(output, target):
            stderr.print(
                Text(
                    "Note: the report is inside the scanned directory. Name it "
                    "reposentinel-report.* (excluded from scans by default) or write it elsewhere."
                )
            )
    raise typer.Exit(code)


def _safe_message(text: str) -> str:
    """Error text that may quote a report file: redacted, printable, bounded."""
    return sanitize_text(redact_known_secrets(text), max_length=500)


def validate_compare_output(output: Path | None, inputs: tuple[Path, ...]) -> Path | None:
    output = validate_output(output)
    if output is not None:
        for report in inputs:
            if report.exists() and output.resolve() == report.resolve():
                raise UsageProblem(
                    f"--output would overwrite the input report {report}. Choose another file."
                )
    return output


def render_comparison(result: ComparisonResult, fmt: OutputFormat, *, color: bool) -> str:
    if fmt is OutputFormat.JSON:
        return render_compare_json(result)
    if fmt is OutputFormat.HTML:
        return render_compare_html(result)
    buffer = io.StringIO()
    console = make_console(buffer, color=color, width=100)
    render_compare_terminal(result, console)
    console.print(Text(exit_explanation(result)))
    return buffer.getvalue()


@app.command(
    epilog=(
        "Exit codes: 0 nothing failing; 1 a finding at or above --fail-on is still detected or "
        "new; 2 usage error or an invalid report; 3 something could not be re-checked or "
        "compared (this takes precedence over 1). "
        "Example: 'reposentinel compare before.json after.json -f html -o comparison.html'"
    )
)
def compare(
    old: Annotated[
        Path,
        typer.Argument(
            help="The earlier JSON report (saved with: scan --format json -o FILE).",
            show_default=False,
        ),
    ],
    new: Annotated[
        Path,
        typer.Argument(help="The later JSON report, made after your changes.", show_default=False),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format", "-f", help="Output format: text, json or html.", case_sensitive=False
        ),
    ] = OutputFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the comparison to this file (UTF-8) instead of standard output.",
            show_default=False,
        ),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Lowest severity of a still-detected or new finding that makes the command "
            "exit with code 1. Unknown results always give exit code 3.",
            case_sensitive=False,
        ),
    ] = FailOn.LOW,
    different_roots: Annotated[
        bool,
        typer.Option(
            "--different-roots",
            help="Compare reports made from different folder paths. Use it only if you know "
            "both describe the same repository; RepoSentinel cannot confirm this.",
        ),
    ] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable colours in terminal output.")
    ] = False,
) -> None:
    """Compare two saved scan reports: what is still detected, what is not, what is unknown.

    Reads only the two report files. It does not scan, open the repository, or
    look at Git history.
    """
    try:
        if output_format is OutputFormat.SARIF:
            raise UsageProblem(
                "SARIF export is for scan reports: use 'reposentinel scan PATH --format sarif'"
            )
        output = validate_compare_output(output, (old, new))
        result = compare_reports(
            load_report(old),
            load_report(new),
            fail_on=fail_on.threshold(),
            different_roots_declared=different_roots,
            old_label=old.name,
            new_label=new.name,
        )
    except (UsageProblem, ReportError, ComparisonError) as problem:
        _error(_safe_message(str(problem)))
        raise typer.Exit(ExitCode.USAGE) from None
    except Exception as exc:  # never show a raw traceback
        _error(f"internal error: {describe_exception(exc)}. This is a bug in RepoSentinel.")
        raise typer.Exit(ExitCode.INCOMPLETE) from None

    code = result.exit_code
    try:
        if output is not None:
            write_report(output, render_comparison(result, output_format, color=False))
        elif output_format is OutputFormat.TEXT:
            console = make_console(color=not no_color)
            render_compare_terminal(result, console)
            console.print(Text(exit_explanation(result), style="dim"))
        else:
            typer.echo(render_comparison(result, output_format, color=False), nl=False)
    except ReportWriteError as problem:
        _error(str(problem))
        raise typer.Exit(ExitCode.INCOMPLETE) from None
    except Exception as exc:  # never show a raw traceback
        _error(f"internal error: {describe_exception(exc)}. This is a bug in RepoSentinel.")
        raise typer.Exit(ExitCode.INCOMPLETE) from None

    if output is not None:
        make_console(sys.stderr, color=False).print(
            Text(
                f"Wrote {output_format.value} comparison to {output}. "
                f"{_safe_message(headline(result))} {SCOPE_STATEMENT} " + exit_explanation(result)
            )
        )
    raise typer.Exit(code)


def _print_new_links(session: Any, console: Console) -> None:
    """Each Enter in the terminal issues a new one-time link (the old one stops working)."""
    for _ in sys.stdin:
        session.new_launch_code()
        # soft_wrap: never insert line breaks into the link (they would break copying).
        console.print(Text(f"New one-time link: {session.launch_url}"), soft_wrap=True)


@app.command()
def ui(
    port: Annotated[
        int,
        typer.Option("--port", min=0, max=65535, help="Port on 127.0.0.1 (0 picks a free port)."),
    ] = 0,
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Do not open a browser; print the link only.")
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            file_okay=False,
            help="Folder for the local project history (default: your user data folder, "
            "or REPOSENTINEL_DATA_DIR).",
        ),
    ] = None,
    no_history: Annotated[
        bool,
        typer.Option(
            "--no-history",
            help="Do not open the local project history; one-off scans and comparisons only.",
        ),
    ] = False,
) -> None:
    """Start the optional local web interface on 127.0.0.1. Stop it with Ctrl+C.

    It scans folders and compares reports with the same engine as the
    commands above. It listens on this computer only and makes no network
    requests; see docs/webui.md for its security model.
    """
    # Imported here so that scan, compare and rules never load any UI code.
    from reposentinel.history import HistoryStore, default_data_dir
    from reposentinel.webui.server import UiNotBuiltError, make_server

    console = make_console(sys.stderr, color=False)
    # The history folder is created only when a project is first registered.
    store = None if no_history else HistoryStore((data_dir or default_data_dir()).absolute())
    try:
        server, session = make_server(port, store=store)
    except UiNotBuiltError as problem:
        _error(str(problem))
        raise typer.Exit(ExitCode.INCOMPLETE) from None
    except OSError as exc:
        _error(f"could not listen on 127.0.0.1:{port}: {exc.strerror or exc}")
        raise typer.Exit(ExitCode.USAGE) from None
    url = session.launch_url
    console.print(
        Text(f"RepoSentinel {__version__} web interface on 127.0.0.1, port {session.port}")
    )
    console.print(Text(f"Open this one-time link (it works once): {url}"), soft_wrap=True)
    console.print(
        Text(
            "Local project history: off (--no-history)."
            if store is None
            else f"Local project history (only for projects you register): {store.path}"
        ),
        soft_wrap=True,
    )
    console.print(
        Text(
            "Runs on this computer only. Press Enter here for a new link (for example after "
            "reloading the page); press Ctrl+C to stop. A session lasts at most 8 hours."
        )
    )
    if sys.stdin is not None and sys.stdin.isatty():
        threading.Thread(target=_print_new_links, args=(session, console), daemon=True).start()
    if not no_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        console.print(Text("RepoSentinel web interface stopped."))


@app.command(epilog="Example: 'reposentinel demo demo-repo' then 'reposentinel scan demo-repo'.")
def demo(
    folder: Annotated[
        Path,
        typer.Argument(help="A new or empty folder to create the demo in.", show_default=False),
    ],
) -> None:
    """Create a synthetic repository with FAKE credentials that triggers every rule."""
    from reposentinel.demo import create_demo_repo

    try:
        written = create_demo_repo(folder)
    except FileExistsError as problem:
        _error(str(problem))
        raise typer.Exit(ExitCode.USAGE) from None
    except OSError as exc:
        _error(f"could not create {folder}: {exc.strerror or exc}")
        raise typer.Exit(ExitCode.USAGE) from None
    console = make_console(sys.stdout, color=False)
    console.print(
        Text(
            f"Created a synthetic demo repository ({len(written)} files) in {folder}. Every "
            "credential in it is fake. Scan it with: reposentinel scan " + str(folder)
        ),
        soft_wrap=True,
    )


@app.command()
def rules() -> None:
    """List the native rules with their default severity and confidence."""
    table = Table(header_style="bold")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Title")
    for rule in all_rules():
        table.add_row(
            rule.id,
            Text(rule.severity.value, style=SEVERITY_STYLES[rule.severity]),
            rule.confidence.value,
            rule.title,
        )
    console = make_console()
    console.print(table)
    console.print(Text("Details, limitations and remediation: docs/rules.md", style="dim"))


def _make_streams_safe() -> None:
    """Avoid crashing on characters the console encoding cannot represent.

    On Windows, piped output often uses a legacy code page. A file name with
    characters outside it would otherwise raise UnicodeEncodeError mid-report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")


def main() -> None:
    _make_streams_safe()
    app()
