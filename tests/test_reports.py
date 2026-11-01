"""Report rendering: JSON structure, HTML escaping, terminal safety, no secret leaks."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from reposentinel.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    CoverageIssue,
    CoverageReason,
    Finding,
    ScanReport,
    Severity,
)
from reposentinel.reporting import (
    SCHEMA_VERSION,
    make_console,
    render_html,
    render_json,
    render_terminal,
)
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan

ESC = chr(27)
SCRIPT = '<script>alert("pwned")</script>'
ATTRIBUTE_BREAKOUT = '"><img src=x onerror=alert(1)>'
RICH_MARKUP = "[red]fake[/red][link=https://evil.test]click[/link]"


def hostile_report() -> ScanReport:
    """A report whose every untrusted field contains something dangerous."""
    finding = Finding(
        rule_id="RS-SEC-004",
        title="GitHub token",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        summary=SCRIPT,
        evidence=ATTRIBUTE_BREAKOUT,
        remediation="Revoke it & rotate.",
        check_id="secrets",
        path=f"dir/{SCRIPT}{ESC}[2J{RICH_MARKUP}.txt",
        line=3,
    )
    return ScanReport(
        target=f"C:/repos/{SCRIPT}",
        tool_version="0.1.0",
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        files_in_scope=1,
        checks=(
            CheckResult("secrets", "Secrets", CheckStatus.FAILED, 1, 1, SCRIPT + ESC + "[31m"),
        ),
        findings=(finding,),
        coverage=(CoverageIssue(SCRIPT, CoverageReason.UNREADABLE, ATTRIBUTE_BREAKOUT),),
    )


def render_text(report: ScanReport) -> str:
    buffer = io.StringIO()
    render_terminal(report, make_console(buffer, color=False, width=120))
    return buffer.getvalue()


class TagCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.attributes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        self.attributes.update(name for name, _ in attrs)


# --- HTML ------------------------------------------------------------------


def test_html_escapes_untrusted_text() -> None:
    html = render_html(hostile_report())
    assert SCRIPT not in html
    assert ATTRIBUTE_BREAKOUT not in html
    assert "&lt;script&gt;alert(&#34;pwned&#34;)&lt;/script&gt;" in html
    assert "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert "Revoke it &amp; rotate." in html


def test_html_contains_only_expected_tags_and_no_event_handlers() -> None:
    parser = TagCollector()
    parser.feed(render_html(hostile_report()))
    assert "script" not in parser.tags
    assert "img" not in parser.tags
    assert not any(name.startswith("on") for name in parser.attributes)
    assert "href" not in parser.attributes and "src" not in parser.attributes


def test_html_is_self_contained_with_restrictive_csp() -> None:
    html = render_html(hostile_report())
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert "http://" not in html and "https://" not in html.replace("https://evil.test", "")


def test_html_control_characters_are_made_visible() -> None:
    html = render_html(hostile_report())
    assert ESC not in html
    assert "\\x1b[2J" in html


def test_html_for_clean_report(make_repo: RepoFactory) -> None:
    html = render_html(scan(make_repo({"README.md": "# hi"})))
    assert "No findings from the checks that ran." in html
    assert "CLEAN" in html


def test_html_escapes_real_file_names(make_repo: RepoFactory) -> None:
    # '&' and "'" are legal in Windows and POSIX file names.
    root = make_repo({"Tom & Jerry's/.env": "X=1"})
    html = render_html(scan(root))
    assert "Tom &amp; Jerry&#39;s/.env" in html


# --- terminal ----------------------------------------------------------------


def test_terminal_neutralises_escape_sequences_and_markup() -> None:
    text = render_text(hostile_report())
    assert ESC not in text  # no raw escape character reaches the terminal
    assert "\\x1b[2J" in text  # it is shown as visible text instead
    assert RICH_MARKUP in text  # Rich markup in data is printed literally
    assert "INCOMPLETE" in text


def test_terminal_groups_findings_by_severity(make_repo: RepoFactory) -> None:
    root = make_repo({".env": "X=1", "app.py": f"t = '{synthetic.GITHUB_TOKEN}'"})
    text = render_text(scan(root))
    assert text.index("HIGH (1)") < text.index("MEDIUM (1)")
    assert "How to fix" in text
    assert "Findings: 2 (high 1, medium 1, low 0, info 0)" in text


def test_terminal_clean_report_explains_its_limits(make_repo: RepoFactory) -> None:
    text = render_text(scan(make_repo({"README.md": "# hi"})))
    assert "CLEAN" in text
    assert "does not mean the repository is secure" in text
    assert "Findings\n" not in text


@pytest.mark.parametrize("renderer", [render_text, render_html, render_json])
def test_undecodable_file_names_do_not_crash_rendering(renderer) -> None:
    # Python represents undecodable bytes in POSIX file names as lone surrogates.
    report = hostile_report()
    finding = report.findings[0]
    odd = Finding(
        **{**{f: getattr(finding, f) for f in Finding.__slots__}, "path": "a" + chr(0xDCFF)}
    )
    output = renderer(
        ScanReport(**{**{f: getattr(report, f) for f in ScanReport.__slots__}, "findings": (odd,)})
    )
    output.encode("utf-8")  # must be encodable for writing to a file or terminal


# --- JSON --------------------------------------------------------------------


def test_json_structure(make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "app.py": f"t = '{synthetic.GITHUB_TOKEN}'",
            ".env": "X=1",
            "big.bin": b"\x00" * 10,
        }
    )
    data = json.loads(render_json(scan(root)))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["tool"]["name"] == "reposentinel"
    assert data["outcome"] == "findings"
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["by_severity"] == {"high": 1, "medium": 1, "low": 0, "info": 0}
    assert data["summary"]["by_rule"] == {"RS-HYG-001": 1, "RS-SEC-004": 1}
    assert data["summary"]["checks"] == {"completed": 3, "failed": 0, "skipped": 0}
    assert data["summary"]["coverage"] == {"binary": 1}
    assert [f["rule_id"] for f in data["findings"]] == ["RS-SEC-004", "RS-HYG-001"]
    token = data["findings"][0]
    assert token["location"] == {"path": "app.py", "line": 1}
    assert set(token) == {
        "rule_id",
        "title",
        "severity",
        "confidence",
        "summary",
        "evidence",
        "location",
        "remediation",
        "check",
        "fingerprint",  # added in schema 1.1
        "rule_version",  # added in schema 1.1
    }
    assert token["rule_version"] == 1
    assert token["fingerprint"].startswith("rs1:")
    assert data["findings"][1]["location"] == {"path": ".env", "line": None}
    assert data["coverage"] == [
        {
            "path": "big.bin",
            "reason": "binary",
            "detail": "appears to be binary data",
            "is_error": False,
        }
    ]
    datetime.fromisoformat(data["scanned_at"])


def test_json_is_ascii_and_round_trips_hostile_text() -> None:
    text = render_json(hostile_report())
    text.encode("ascii")  # every non-ASCII and control character is escaped
    data = json.loads(text)
    assert data["findings"][0]["summary"] == SCRIPT
    assert data["outcome"] == "incomplete"


def test_repository_level_finding_has_null_location() -> None:
    report = hostile_report()
    finding = Finding("RS-X", "t", Severity.LOW, Confidence.LOW, "s", "e", "r", "c")
    replaced = ScanReport(
        **{**{f: getattr(report, f) for f in ScanReport.__slots__}, "findings": (finding,)}
    )
    assert json.loads(render_json(replaced))["findings"][0]["location"] is None


# --- secrets never leak ---------------------------------------------------------


def test_no_report_format_contains_a_secret(make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "config/settings.py": synthetic.credential_file(),
            "fine_grained.txt": synthetic.GITHUB_FINE_GRAINED_TOKEN,
            "temp.txt": synthetic.AWS_TEMP_KEY_ID,
            ".git-credentials": f"https://user:{synthetic.URL_PASSWORD}@git.example.test",
            ".github/workflows/bad.yml": f"jobs: [{synthetic.GITHUB_TOKEN}\n",
        }
    )
    report = scan(root)
    assert len(report.findings) >= 7
    for output in (render_text(report), render_json(report), render_html(report)):
        for value in synthetic.SECRET_VALUES:
            assert value not in output


def test_no_color_environment_variable_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert make_console(io.StringIO(), color=True).no_color
    monkeypatch.delenv("NO_COLOR")
    assert not make_console(io.StringIO(), color=True).no_color
    assert make_console(io.StringIO(), color=False).no_color


def test_json_strings_are_valid_unicode_for_undecodable_names() -> None:
    # Found in the audit: a lone surrogate survived into the JSON, which strict
    # parsers reject. It is now written as the visible text "\udcff".
    report = hostile_report()
    finding = report.findings[0]
    odd = Finding(
        **{**{f: getattr(finding, f) for f in Finding.__slots__}, "path": "a" + chr(0xDCFF)}
    )
    data = json.loads(
        render_json(
            ScanReport(
                **{**{f: getattr(report, f) for f in ScanReport.__slots__}, "findings": (odd,)}
            )
        )
    )
    path = data["findings"][0]["location"]["path"]
    assert path == "a" + chr(92) + "udcff"
    json.dumps(data, ensure_ascii=False).encode("utf-8")  # every string is valid Unicode


def test_html_csp_blocks_scripts_base_and_forms() -> None:
    html = render_html(hostile_report())
    csp = html.split('http-equiv="Content-Security-Policy" content="', 1)[1].split('"', 1)[0]
    directives = {part.split()[0]: part.split()[1:] for part in csp.split(";") if part.strip()}
    assert directives["default-src"] == ["'none'"]  # no scripts, images, fonts or connections
    assert directives["base-uri"] == ["'none'"]
    assert directives["form-action"] == ["'none'"]
    assert directives["style-src"] == ["'unsafe-inline'"]  # only the report's own <style> block


def test_empty_scope_is_called_out_in_every_format(tmp_path: Path) -> None:
    # Found in the audit: an empty folder was reported as a plain "CLEAN".
    report = scan(tmp_path)
    note = "No files were in scope, so nothing was examined."
    assert note in " ".join(render_text(report).split())
    assert note in render_html(report)
    assert any(note in n for n in json.loads(render_json(report))["notes"])


def test_notes_are_empty_for_a_normal_scan(make_repo: RepoFactory) -> None:
    report = scan(make_repo({"README.md": "# hi"}))
    assert json.loads(render_json(report))["notes"] == []
    assert "Note:" not in render_text(report)


def test_excluded_directories_are_listed_not_just_counted(make_repo: RepoFactory) -> None:
    # A pyvenv.cfg file is enough to make a folder look like a virtual
    # environment; the report must show which folders were skipped.
    root = make_repo(
        {
            "config/pyvenv.cfg": "home = x",
            "config/settings.py": f"TOKEN = '{synthetic.GITHUB_TOKEN}'",
            "node_modules/lib.js": "",
            "app.py": "",
        }
    )
    report = scan(root)
    assert report.findings == ()  # the token in config/ was not scanned...
    text = " ".join(render_text(report).split())
    assert (
        "Excluded: config (Python virtual environment), node_modules (excluded by default)" in text
    )
    html = render_html(report)
    assert "<code>config</code> (Python virtual environment)" in html  # ...and the report says so


def test_html_needs_nothing_its_csp_blocks(make_repo: RepoFactory) -> None:
    # The policy allows only inline styles. Check the page relies on nothing
    # else, so it renders fully under its own Content-Security-Policy.
    html = render_html(scan(make_repo({".env": "X=1", "README.md": "# hi"})))
    parser = TagCollector()
    parser.feed(html)
    loaders = {"script", "img", "link", "iframe", "frame", "object", "embed", "base", "form"}
    assert loaders.isdisjoint(parser.tags)
    assert {"audio", "video", "source", "track", "picture"}.isdisjoint(parser.tags)
    css = html.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "url(" not in css and "@import" not in css and "@font-face" not in css
    assert html.index("Content-Security-Policy") < html.index("<style>")  # applies to the CSS
