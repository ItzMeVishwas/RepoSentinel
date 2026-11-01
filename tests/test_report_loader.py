"""Loading saved JSON reports for ``compare``: every file is untrusted input (AC-14)."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from reposentinel import report_loader
from reposentinel.report_loader import ReportError, load_report, parse_report
from reposentinel.reporting import render_json, report_to_dict
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan


@pytest.fixture
def report_dict(make_repo: RepoFactory) -> dict[str, Any]:
    root = make_repo(
        {
            "config.py": f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n',
            ".env": "A=1\n",
            "node_modules/x.js": "1\n",
        }
    )
    data: dict[str, Any] = json.loads(render_json(scan(root)))
    return data


def _write(tmp_path: Path, data: Any, name: str = "report.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_round_trip_keeps_everything_compare_needs(make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"config.py": synthetic.credential_file(), ".env": "A=1\n"})
    original = scan(root)
    loaded = load_report(_write(tmp_path, json.loads(render_json(original))))
    assert loaded.target == original.target
    assert loaded.outcome is original.outcome
    assert loaded.files == original.files
    assert loaded.scan_config == original.scan_config
    assert [(c.check_id, c.status, c.examined_paths) for c in loaded.checks] == [
        (c.check_id, c.status, c.examined_paths) for c in original.checks
    ]
    assert [(f.fingerprint, f.path, f.line, f.rule_version) for f in loaded.findings] == [
        (f.fingerprint, f.path, f.line, f.rule_version) for f in original.findings
    ]
    # Loading and saving again gives the same document.
    assert report_to_dict(loaded) == report_to_dict(original)


# --- file-level problems --------------------------------------------------------


def test_missing_file_and_directory_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="file not found"):
        load_report(tmp_path / "missing.json")
    with pytest.raises(ReportError, match="not a report file"):
        load_report(tmp_path)


def test_oversized_file_is_rejected_without_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_loader, "MAX_REPORT_BYTES", 10)
    path = tmp_path / "big.json"
    path.write_text("[" + "1," * 20 + "1]", encoding="utf-8")
    with pytest.raises(ReportError, match="larger than"):
        load_report(path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"\xff\xfe{}", "not valid UTF-8"),
        (b"{", "not valid JSON. compare needs reports saved with"),
        (b"", "not valid JSON"),
        (b'{"a": NaN}', "not valid JSON"),
        (b'{"a": Infinity}', "not valid JSON"),
        (b'{"a": -Infinity}', "not valid JSON"),
        (b"[" * 200_000 + b"]" * 200_000, "not valid JSON"),
        (b'{"a": ' + b"9" * 5000 + b"}", "not valid JSON"),
    ],
    ids=["utf8", "truncated", "empty", "nan", "inf", "neg-inf", "deep", "huge-int"],
)
def test_unparseable_content_is_rejected(tmp_path: Path, content: bytes, message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(ReportError, match=message):
        load_report(path)


# --- schema ---------------------------------------------------------------------


def test_schema_1_0_asks_for_a_new_scan(report_dict: dict[str, Any]) -> None:
    report_dict["schema_version"] = "1.0"
    with pytest.raises(ReportError, match=r"older RepoSentinel.*scan again"):
        parse_report(report_dict)


@pytest.mark.parametrize("version", ["1.2", "2.0", "", None, 1.1, ["1.1"]])
def test_unknown_or_newer_schema_is_rejected(report_dict: dict[str, Any], version: Any) -> None:
    report_dict["schema_version"] = version
    with pytest.raises(ReportError, match="unsupported report schema"):
        parse_report(report_dict)


@pytest.mark.parametrize("value", [[], "text", 5, None, {"tool": {"name": "other"}}])
def test_not_a_reposentinel_report(value: Any) -> None:
    with pytest.raises(ReportError):
        parse_report(value)


# --- field-level validation -----------------------------------------------------

Mutation = Callable[[dict[str, Any]], None]


def _set(path: str, value: Any) -> Mutation:
    """Set a dotted path such as 'findings.0.severity' (list indexes are numbers)."""

    def mutate(data: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        node: Any = data
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        if isinstance(node, list):
            node[int(last)] = value
        else:
            node[last] = value

    return mutate


def _delete(path: str) -> Mutation:
    def mutate(data: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        node: Any = data
        for part in parents:
            node = node[int(part)] if isinstance(node, list) else node[part]
        del node[last]

    return mutate


def _duplicate_check(data: dict[str, Any]) -> None:
    data["checks"].append(copy.deepcopy(data["checks"][0]))


def _finding_for_unknown_check(data: dict[str, Any]) -> None:
    data["findings"][0]["check"] = "no-such-check"


INVALID: dict[str, Mutation] = {
    "findings-not-list": _set("findings", {}),
    "finding-not-object": _set("findings.0", "x"),
    "bad-fingerprint": _set("findings.0.fingerprint", "rs1:abc"),
    "missing-fingerprint": _delete("findings.0.fingerprint"),
    "upper-fingerprint": _set("findings.0.fingerprint", "rs1:" + "A" * 64),
    "bad-severity": _set("findings.0.severity", "critical"),
    "bad-confidence": _set("findings.0.confidence", 3),
    "line-zero": _set("findings.0.location.line", 0),
    "line-bool": _set("findings.0.location.line", True),
    "line-float": _set("findings.0.location.line", 1.5),
    "line-without-path": _set("findings.0.location", {"path": None, "line": 1}),
    "empty-rule": _set("findings.0.rule_id", ""),
    "unknown-check": _finding_for_unknown_check,
    "rule-version-mismatch": _set("findings.0.rule_version", 2),
    "rule-version-missing": _set("findings.0.rule_version", None),
    "duplicate-check": _duplicate_check,
    "bad-check-status": _set("checks.0.status", "maybe"),
    "missing-coverage-by-check": _set("coverage_by_check", {}),
    "examined-paths-not-list": _set("coverage_by_check.secrets.examined_paths", "config.py"),
    "examined-path-not-text": _set("coverage_by_check.secrets.examined_paths", [1]),
    "coverage-flag-mismatch": _set("coverage.0.is_error", True),
    "coverage-bad-reason": _set("coverage.0.reason", "other"),
    "files-not-list": _set("files", "config.py"),
    "files-count-mismatch": _set("files", []),
    "outcome-mismatch": _set("outcome", "clean"),
    "no-timezone": _set("scanned_at", "2026-10-26T10:00:00"),
    "bad-date": _set("scanned_at", "yesterday"),
    "config-missing": _set("scan_config", None),
    "config-checks-mismatch": _set("scan_config.checks", ["secrets"]),
    "config-limit-negative": _set("scan_config.limits.max_files", -1),
    "config-limit-missing": _delete("scan_config.limits.max_depth"),
    "config-version-zero": _set("scan_config.rule_versions.RS-SEC-004", 0),
    "config-exclusions-not-list": _set("scan_config.exclusions.dirs", ".git"),
}


@pytest.mark.parametrize("mutation", INVALID.values(), ids=INVALID.keys())
def test_invalid_fields_are_rejected(report_dict: dict[str, Any], mutation: Mutation) -> None:
    parse_report(copy.deepcopy(report_dict))  # the unmodified report is valid
    mutation(report_dict)
    with pytest.raises(ReportError):
        parse_report(report_dict)


def test_errors_never_quote_values_from_the_report(report_dict: dict[str, Any]) -> None:
    # Redaction cannot recognise every credential (here a token glued to other
    # text), so error messages name locations only.
    hidden = "x" + synthetic.GITHUB_TOKEN
    cases: list[Mutation] = [
        _set("scan_config.rule_versions." + hidden, 0),
        _set("schema_version", hidden),
        _set("findings.0.check", hidden),
        _set("findings.0.severity", hidden),
        _set("scan_config.exclusions." + hidden, hidden),
    ]
    for mutation in cases:
        data = copy.deepcopy(report_dict)
        mutation(data)
        with pytest.raises(ReportError) as info:
            parse_report(data)
        assert hidden not in str(info.value) and synthetic.GITHUB_TOKEN not in str(info.value)


def test_error_names_the_file_and_field(report_dict: dict[str, Any], tmp_path: Path) -> None:
    report_dict["findings"][0]["severity"] = "critical"
    path = _write(tmp_path, report_dict)
    with pytest.raises(ReportError) as info:
        load_report(path)
    assert str(path) in str(info.value)
    assert "findings[0].severity" in str(info.value)


# --- content is redacted, paths are kept ----------------------------------------


def test_free_text_is_redacted_on_load(report_dict: dict[str, Any]) -> None:
    token = synthetic.GITHUB_TOKEN
    finding = report_dict["findings"][0]
    for key in ("title", "summary", "evidence", "remediation"):
        finding[key] = f"{key} {token}"
    report_dict["checks"][0]["message"] = f"message {token}"
    report_dict["coverage"][0]["detail"] = f"detail {token}"
    report = parse_report(report_dict)
    texts = [report.findings[0].title, report.findings[0].summary, report.findings[0].evidence]
    texts += [report.findings[0].remediation, report.checks[0].message, report.coverage[0].detail]
    assert all(token not in text and "[REDACTED]" in text for text in texts)


def test_hostile_text_is_loaded_as_data(report_dict: dict[str, Any]) -> None:
    hostile = "<script>alert(1)</script>" + chr(0x1B) + "[31m" + chr(0x202E)
    report_dict["findings"][0]["summary"] = hostile
    report = parse_report(report_dict)
    # Kept as text; every renderer escapes and sanitises it (tested in test_compare_cli).
    assert report.findings[0].summary == hostile
