"""SARIF 2.1.0 export of a scan (OASIS Static Analysis Results Interchange Format).

The output follows the SARIF 2.1.0 schema's required properties and the
subset GitHub code scanning documents (``$schema``, ``version``, one run with
``tool.driver`` and its ``rules``, results with ``message.text`` and a
physical location). See docs/sarif.md for the mapping and its limits.

Privacy and safety choices:

* Locations are relative paths under the base id ``%SRCROOT%``; the absolute
  scanned folder (which can contain a user name) is not exported.
* No source snippets, matched text or file contents: a result carries the
  finding's summary and its already-redacted evidence, nothing else from the
  file.
* ``partialFingerprints`` holds RepoSentinel's tracked-finding fingerprint
  (a SHA-256 of non-secret identity inputs). RepoSentinel does not compute
  GitHub's ``primaryLocationLineHash`` (that is derived from file contents);
  GitHub's upload action computes it when it is missing.
* An incomplete scan is exported with ``executionSuccessful: false`` and a
  notification per failed or skipped check, so a consumer never mistakes it
  for a complete run.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from reposentinel.checks import all_rules
from reposentinel.compare import SCOPE_STATEMENT
from reposentinel.models import CheckStatus, Finding, Outcome, Rule, ScanReport, Severity
from reposentinel.reporting.common import DISCLAIMER
from reposentinel.reporting.json_report import valid_unicode

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SOURCE_ROOT = "%SRCROOT%"
FINGERPRINT_KEY = "reposentinelFingerprint/v1"

# Severity -> SARIF level and GitHub's "security-severity" score (as a string).
# GitHub maps 7.0-8.9 to high, 4.0-6.9 to medium, 0.1-3.9 to low, 0.0 to none.
LEVELS: dict[Severity, str] = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
PRECISION = {"high": "high", "medium": "medium", "low": "low"}


def artifact_uri(path: str) -> str:
    """A relative URI reference for a POSIX path (percent-encoded; never starts with '/')."""
    raw = path.encode("utf-8", "surrogateescape")  # undecodable POSIX names keep their bytes
    return quote(raw, safe="/-._~").lstrip("/")


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.id.replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description[:1000]},
        "help": {
            "text": f"{rule.remediation}\n\nLimitations: {rule.limitations}",
            "markdown": (
                f"**How to fix.** {rule.remediation}\n\n**Limitations.** {rule.limitations}\n\n"
                f"**After a re-check.** {rule.recheck_limits}"
            ),
        },
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {
            "tags": ["security"],
            "precision": PRECISION[rule.confidence.value],
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "reposentinel/version": rule.version,
        },
    }


def _external_rule(finding: Finding) -> dict[str, Any]:
    """A descriptor for a rule outside RepoSentinel's catalogue (an integration)."""
    return {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.title or finding.rule_id},
        "fullDescription": {"text": finding.title or finding.rule_id},
        "help": {"text": finding.remediation or "See the tool that reported this finding."},
        "defaultConfiguration": {"level": LEVELS[finding.severity]},
        "properties": {
            "tags": ["security"],
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": {"text": finding.summary or finding.title},
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": {
            "confidence": finding.confidence.value,
            "evidence": finding.evidence,  # always redacted by RepoSentinel
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }
    if finding.path is not None:
        location: dict[str, Any] = {
            "artifactLocation": {"uri": artifact_uri(finding.path), "uriBaseId": SOURCE_ROOT}
        }
        if finding.line is not None:
            location["region"] = {"startLine": finding.line}
        result["locations"] = [{"physicalLocation": location}]
    return result


def report_to_sarif(report: ScanReport) -> dict[str, Any]:
    catalogue = {rule.id: rule for rule in all_rules()}
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    # Every native rule of the checks that ran, so consumers can show rule help
    # even for rules without results; then any external rule that reported.
    ran = set(report.scan_config.rule_versions) if report.scan_config else set(catalogue)
    for rule_id in sorted(ran & set(catalogue)):
        index[rule_id] = len(rules)
        rules.append(_rule_descriptor(catalogue[rule_id]))
    for finding in report.findings:
        if finding.rule_id not in index:
            index[finding.rule_id] = len(rules)
            rules.append(_external_rule(finding))

    notifications: list[dict[str, Any]] = []
    for check in report.checks:
        if check.status is not CheckStatus.COMPLETED:
            notifications.append(
                {
                    "level": "error",
                    "message": {
                        "text": f"The {check.name} check {check.status.value}: "
                        f"{check.message or 'no details'}"
                    },
                    "descriptor": {"id": check.check_id},
                }
            )
    if report.coverage_errors:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"{len(report.coverage_errors)} file(s) or folder(s) could not be "
                    "examined (unreadable, unparseable or a scan limit was reached); results "
                    "for them are missing."
                },
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "RepoSentinel",
                "version": report.tool_version,
                "semanticVersion": report.tool_version,
                "rules": rules,
            }
        },
        "invocations": [
            {
                "executionSuccessful": report.outcome is not Outcome.INCOMPLETE,
                "toolExecutionNotifications": notifications,
                "endTimeUtc": report.scanned_at.isoformat().replace("+00:00", "Z"),
            }
        ],
        "originalUriBaseIds": {
            SOURCE_ROOT: {
                "description": {
                    "text": "The root of the scanned folder. Its absolute path is not exported."
                }
            }
        },
        "columnKind": "unicodeCodePoints",
        "results": [_result(finding, index[finding.rule_id]) for finding in report.findings],
        "properties": {
            "reposentinel": {
                "outcome": report.outcome.value,
                "scope": SCOPE_STATEMENT,
                "disclaimer": DISCLAIMER,
                "filesInScope": report.files_in_scope,
                "coverageErrors": len(report.coverage_errors),
                "notExamined": sum(1 for issue in report.coverage if not issue.reason.is_error),
                "checks": [
                    {"id": check.check_id, "status": check.status.value} for check in report.checks
                ],
            }
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(report: ScanReport) -> str:
    # Plain ASCII output; lone surrogates (undecodable POSIX names) become
    # visible text first, as in the JSON report, so strict parsers accept it.
    return json.dumps(valid_unicode(report_to_sarif(report)), indent=2, ensure_ascii=True) + "\n"
