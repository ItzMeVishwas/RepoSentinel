"""Project-level checks: the demo script, the rule catalogue, docs and a self-scan."""

from __future__ import annotations

import importlib.util
import io
import re
import socket
from pathlib import Path
from types import ModuleType

import pytest

from reposentinel import demo
from reposentinel.checks import all_rules
from reposentinel.models import Severity
from reposentinel.reporting import make_console, render_html, render_json, render_terminal
from tests.helpers import scan

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str) -> ModuleType:
    path = PROJECT_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_demo_script() -> ModuleType:
    return load_script("create_demo_repo")


def test_demo_repository_triggers_every_rule(tmp_path: Path) -> None:
    load_demo_script().create_demo_repo(tmp_path / "demo")  # the script wraps reposentinel.demo
    report = scan(tmp_path / "demo")
    assert {f.rule_id for f in report.findings} == {rule.id for rule in all_rules()}
    output = render_json(report)
    for value in (demo.FAKE_GITHUB_TOKEN, demo.FAKE_AWS_KEY_ID, demo.FAKE_AWS_SECRET):
        assert value not in output
    assert demo.FAKE_DB_PASSWORD not in output


def test_demo_script_refuses_non_empty_directory(tmp_path: Path) -> None:
    demo = load_demo_script()
    (tmp_path / "keep.txt").write_text("user data", encoding="utf-8")
    with pytest.raises(FileExistsError):
        demo.create_demo_repo(tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]


def test_rule_catalogue_is_complete_and_well_formed() -> None:
    rules = all_rules()
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids)), "rule IDs must be unique"
    for rule in rules:
        assert re.fullmatch(r"RS-[A-Z]{3}-\d{3}", rule.id)
        for text in (rule.description, rule.severity_rationale, rule.remediation, rule.limitations):
            assert len(text) > 40, f"{rule.id} needs a fuller explanation"
        # Comparisons need a version and a "what a re-check cannot show" note.
        assert rule.version >= 1
        assert len(rule.recheck_limits) > 40, f"{rule.id} needs recheck_limits"


def test_every_rule_is_in_the_readme() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    for rule in all_rules():
        assert rule.id in readme, f"{rule.id} missing from README.md"


def test_rules_reference_is_up_to_date() -> None:
    generated = load_script("generate_rules_doc").render_rules_markdown()
    current = (PROJECT_ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert current == generated, "run: python scripts/generate_rules_doc.py"


def test_self_scan_reports_nothing_above_info() -> None:
    # Test fixtures build fake secrets at run time, so RepoSentinel's own source
    # tree must not trigger its rules. (Info findings, such as a developer's
    # git-ignored local .env file, are allowed.)
    report = scan(PROJECT_ROOT)
    serious = [f for f in report.findings if f.severity is not Severity.INFO]
    assert serious == [], [f"{f.rule_id} {f.location}" for f in serious]


def test_scan_and_reports_make_no_network_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RepoSentinel promises to run offline. Make every socket operation fail
    # loudly, then run a full scan and render every report format.
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("RepoSentinel attempted a network operation")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, no_network)

    load_demo_script().create_demo_repo(tmp_path / "demo")
    report = scan(tmp_path / "demo")
    render_json(report)
    render_html(report)
    render_terminal(report, make_console(io.StringIO(), color=False))
    assert len(report.findings) > 0


def test_project_text_files_are_plain_ascii_without_control_characters() -> None:
    # Guards against invisible characters (bidirectional overrides, zero-width
    # spaces, terminal escapes) slipping into RepoSentinel's own code or docs.
    # Tests build such characters with chr() instead of writing them literally.
    allowed_controls = {"\n", "\r", "\t"}
    patterns = ("*.py", "*.md", "*.j2", "*.toml", "*.yml", "*.yaml", ".gitignore")
    folders = [PROJECT_ROOT / name for name in ("src", "tests", "scripts", "docs", ".github")]
    files = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "SECURITY.md",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / ".gitignore",
    ]
    files += [f for folder in folders for pattern in patterns for f in folder.rglob(pattern)]
    # The web interface's source (not node_modules, not the generated build).
    frontend = PROJECT_ROOT / "frontend"
    files += [frontend / name for name in ("index.html", "package.json", "tsconfig.json")]
    files += [frontend / "vite.config.ts"]
    for folder in (frontend / "src", frontend / "e2e"):
        files += [
            f for pattern in ("*.ts", "*.tsx", "*.css", "*.mjs") for f in folder.rglob(pattern)
        ]
    problems = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.split("\n"), start=1):
            bad = [
                c for c in line if ord(c) > 0x7E or (ord(c) < 0x20 and c not in allowed_controls)
            ]
            if bad:
                problems.append(
                    f"{path.relative_to(PROJECT_ROOT)}:{number}: {[hex(ord(c)) for c in bad]}"
                )
    assert problems == []


def test_third_party_notices_cover_the_bundled_web_packages() -> None:
    # The web build bundles these packages into the shipped JavaScript; the MIT
    # license requires their full license text to travel with them.
    import json

    lock = json.loads((PROJECT_ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    package = json.loads((PROJECT_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    notices = (
        PROJECT_ROOT / "src" / "reposentinel" / "webui" / "THIRD_PARTY_LICENSES.txt"
    ).read_text(encoding="utf-8")
    bundled = [*package["dependencies"], "scheduler"]  # scheduler: a dependency of react-dom
    for name in bundled:
        entry = lock["packages"][f"node_modules/{name}"]
        assert f"{name} {entry['version']} ({entry['license']})" in notices, name
    assert notices.count("Permission is hereby granted, free of charge") == len(bundled)
