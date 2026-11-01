"""Machine-readable JSON report.

The structure is versioned with ``schema_version``. Adding fields is a
compatible change; renaming or removing fields, or changing their meaning,
requires a new major schema version. Keys are emitted in a fixed order and
findings are already sorted, so two scans of the same tree differ only in
``scanned_at``.

Strings are written as found (JSON escaping makes them safe to parse), with
two exceptions: secret values never reach this module (they are redacted
earlier), and lone surrogates (how Python represents undecodable bytes in
POSIX file names) are written as visible text such as "\\udcff". A lone
surrogate is not valid Unicode, and strict JSON parsers reject it.
"""

from __future__ import annotations

import json
from typing import Any

from reposentinel.models import CheckStatus, ScanConfig, ScanReport
from reposentinel.reporting.common import DISCLAIMER, report_notes

# 1.1 added (all additive): findings[].fingerprint and findings[].rule_version,
# coverage_by_check, files and scan_config. They let `reposentinel compare`
# tell what a later scan re-checked. Note that they include the list of file
# paths in scope and the paths each check examined.
SCHEMA_VERSION = "1.1"


def valid_unicode(value: Any) -> Any:
    """Recursively replace lone surrogates in strings with visible escapes."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {key: valid_unicode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [valid_unicode(item) for item in value]
    return value


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    status_counts = {
        status.value: sum(1 for check in report.checks if check.status is status)
        for status in CheckStatus
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "reposentinel", "version": report.tool_version},
        "target": report.target,
        "scanned_at": report.scanned_at.isoformat(),
        "outcome": report.outcome.value,
        "disclaimer": DISCLAIMER,
        "notes": report_notes(report),
        "summary": {
            "total_findings": len(report.findings),
            "by_severity": {sev.value: n for sev, n in report.severity_counts().items()},
            "by_rule": report.rule_counts(),
            "checks": status_counts,
            "files_in_scope": report.files_in_scope,
            "coverage": {reason.value: n for reason, n in report.coverage_counts().items()},
            "coverage_errors": len(report.coverage_errors),
        },
        "checks": [
            {
                "id": check.check_id,
                "name": check.name,
                "status": check.status.value,
                "findings": check.finding_count,
                "examined": check.examined,
                "message": check.message,
            }
            for check in report.checks
        ],
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "location": (
                    None if finding.path is None else {"path": finding.path, "line": finding.line}
                ),
                "remediation": finding.remediation,
                "check": finding.check_id,
                "fingerprint": finding.fingerprint,
                "rule_version": finding.rule_version,
            }
            for finding in report.findings
        ],
        "coverage": [
            {
                "path": issue.path,
                "reason": issue.reason.value,
                "detail": issue.detail,
                "is_error": issue.reason.is_error,
            }
            for issue in report.coverage
        ],
        "coverage_by_check": {
            check.check_id: {
                "examined_paths": (
                    None if check.examined_paths is None else list(check.examined_paths)
                )
            }
            for check in report.checks
        },
        "files": list(report.files),
        "scan_config": _scan_config_to_dict(report.scan_config),
    }


def _scan_config_to_dict(config: ScanConfig | None) -> dict[str, Any] | None:
    if config is None:
        return None
    return {
        "checks": list(config.checks),
        "rule_versions": dict(config.rule_versions),
        "limits": dict(config.limits),
        "exclusions": {key: list(values) for key, values in config.exclusions.items()},
    }


def render_json(report: ScanReport) -> str:
    # ensure_ascii (the default) escapes every non-ASCII character, including
    # invisible bidirectional controls, so the file is plain ASCII.
    return json.dumps(valid_unicode(report_to_dict(report)), indent=2) + "\n"
