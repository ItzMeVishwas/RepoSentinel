"""SARIF 2.1.0 export: structure, severity mapping, locations, privacy and incomplete scans.

The checks below follow the SARIF 2.1.0 schema's required properties for the
subset RepoSentinel writes, and GitHub code scanning's documented upload
requirements. They do not run the official JSON Schema (that would add a
dependency); docs/sarif.md lists what is and is not covered.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reposentinel import cli
from reposentinel.checks import all_rules
from reposentinel.engine import ExitCode
from reposentinel.models import Outcome, Severity
from reposentinel.reporting.sarif import (
    FINGERPRINT_KEY,
    LEVELS,
    SARIF_SCHEMA,
    SECURITY_SEVERITY,
    SOURCE_ROOT,
    artifact_uri,
    render_sarif,
    report_to_sarif,
)
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan
from tests.test_leak_regression import BROKEN_WORKFLOW, FORBIDDEN, RAW_CONTROLS, WORKFLOW

runner = CliRunner()
U_UMLAUT, I_UMLAUT = chr(0xFC), chr(0xEF)  # built here: source files stay ASCII


@pytest.fixture
def repo(make_repo: RepoFactory) -> Path:
    return make_repo(
        {
            "config/settings.env": synthetic.credential_file(),
            f"dir with space/{U_UMLAUT}n{I_UMLAUT}code #1.env": synthetic.credential_file(),
            ".github/workflows/ci.yml": WORKFLOW,
            "app.py": "x = 1\n",
        }
    )


def sarif_of(root: Path) -> dict[str, Any]:
    log: dict[str, Any] = json.loads(render_sarif(scan(root)))
    return log


def test_top_level_structure(repo: Path) -> None:
    log = sarif_of(repo)
    assert log["$schema"] == SARIF_SCHEMA
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "RepoSentinel"
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", driver["version"])
    invocation = log["runs"][0]["invocations"][0]
    assert isinstance(invocation["executionSuccessful"], bool)  # required by the schema


def test_rules_and_results_are_consistent(repo: Path) -> None:
    report = scan(repo)
    run = report_to_sarif(report)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    assert set(ids) >= {rule.id for rule in all_rules()}  # every rule of the checks that ran
    for rule in rules:
        assert rule["shortDescription"]["text"] and rule["fullDescription"]["text"]
        assert rule["help"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"none", "note", "warning", "error"}
        assert isinstance(rule["properties"]["security-severity"], str)
    assert len(run["results"]) == len(report.findings) > 0
    for result, finding in zip(run["results"], report.findings, strict=True):
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"] == finding.rule_id
        assert result["level"] == LEVELS[finding.severity]
        assert result["message"]["text"]
        assert result["partialFingerprints"] == {FINGERPRINT_KEY: finding.fingerprint}
        assert result["properties"]["security-severity"] == SECURITY_SEVERITY[finding.severity]


def test_severity_mapping_matches_the_documented_ranges() -> None:
    # GitHub: > 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low, 0.0 none.
    def band(score: str) -> str:
        value = float(score)
        if value > 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        return "low" if value >= 0.1 else "none"

    assert {s: band(SECURITY_SEVERITY[s]) for s in Severity} == {
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "none",
    }
    assert LEVELS == {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }


def test_locations_are_relative_and_never_absolute(repo: Path) -> None:
    text = render_sarif(scan(repo))
    log = json.loads(text)
    run = log["runs"][0]
    assert SOURCE_ROOT in run["originalUriBaseIds"]
    assert "uri" not in run["originalUriBaseIds"][SOURCE_ROOT]  # the root is not exported
    uris = set()
    for result in run["results"]:
        for location in result.get("locations", []):
            physical = location["physicalLocation"]
            artifact = physical["artifactLocation"]
            assert artifact["uriBaseId"] == SOURCE_ROOT
            uri = artifact["uri"]
            uris.add(uri)
            assert not uri.startswith("/") and ":" not in uri and "\\" not in uri
            assert ".." not in uri.split("/")
            if "region" in physical:
                assert physical["region"]["startLine"] >= 1
    assert "config/settings.env" in uris
    assert "dir%20with%20space/%C3%BCn%C3%AFcode%20%231.env" in uris
    # No form of the absolute scanned folder appears anywhere.
    # (The temporary folder's path contains the user name, like a real one.)
    for form in (str(repo), repo.as_posix(), str(repo.resolve()), "pytest-of-"):
        assert form not in text and json.dumps(form)[1:-1] not in text, form


@pytest.mark.parametrize(
    ("path", "uri"),
    [
        ("a/b.txt", "a/b.txt"),
        ("/leading", "leading"),
        ("x y/%z#q?.env", "x%20y/%25z%23q%3F.env"),
        (f"{U_UMLAUT}ber.txt", "%C3%BCber.txt"),
    ],
)
def test_artifact_uri_encoding(path: str, uri: str) -> None:
    assert artifact_uri(path) == uri


def test_no_secrets_snippets_or_repository_text(make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "config.env": synthetic.credential_file(),
            ".github/workflows/ci.yml": WORKFLOW,
            ".github/workflows/broken.yml": BROKEN_WORKFLOW,
        }
    )
    text = render_sarif(scan(root))
    for secret in synthetic.SECRET_VALUES:
        assert secret not in text
    for value in FORBIDDEN:
        assert value not in text, value
    for control in RAW_CONTROLS:
        assert control not in text
    assert text.isascii()
    assert "synthetic test configuration" not in text  # no file contents or snippets
    assert '"snippet"' not in text and '"contextRegion"' not in text


def test_an_incomplete_scan_is_marked_unsuccessful(make_repo: RepoFactory) -> None:
    root = make_repo({".github/workflows/broken.yml": BROKEN_WORKFLOW})
    report = scan(root)
    assert report.outcome is Outcome.INCOMPLETE
    run = report_to_sarif(report)["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"]
    for notification in invocation["toolExecutionNotifications"]:
        assert notification["level"] in {"error", "warning"}
        assert notification["message"]["text"]
    assert run["properties"]["reposentinel"]["outcome"] == "incomplete"


def test_a_clean_complete_scan(make_repo: RepoFactory) -> None:
    run = report_to_sarif(scan(make_repo({"app.py": "x = 1\n"})))["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    # A clean result is still described as what it is, not as proof of safety.
    assert "not" in run["properties"]["reposentinel"]["disclaimer"].lower()


def test_cli_scan_writes_sarif(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.sarif"
    result = runner.invoke(cli.app, ["scan", str(repo), "--format", "sarif", "-o", str(out)])
    assert result.exit_code == ExitCode.FINDINGS, result.output
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0" and log["runs"][0]["results"]
    stdout = runner.invoke(cli.app, ["scan", str(repo), "-f", "sarif"])
    assert json.loads(stdout.stdout)["version"] == "2.1.0"


def test_cli_compare_refuses_sarif(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    assert runner.invoke(cli.app, ["scan", str(repo), "-f", "json", "-o", str(report)]).exit_code
    result = runner.invoke(cli.app, ["compare", str(report), str(report), "-f", "sarif"])
    assert result.exit_code == ExitCode.USAGE
    assert "SARIF export is for scan reports" in result.output
