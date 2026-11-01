"""Machine-readable comparison output.

Versioned separately from the scan report with ``comparison_schema_version``.
Keys are emitted in a fixed order and findings are already sorted, so the
same two reports always produce the same output. The file is plain ASCII
(see ``json_report.render_json``). It contains fingerprints, paths and
redacted evidence only; it is not a scan report and ``compare`` does not
accept it as input.
"""

from __future__ import annotations

import json
from typing import Any

from reposentinel.compare import (
    CREDENTIAL_REMINDER,
    SCOPE_STATEMENT,
    ComparisonResult,
    ComparisonStatus,
    ReportInfo,
    exit_explanation,
    headline,
    summary_sentences,
)
from reposentinel.models import CoverageIssue
from reposentinel.reporting.compare_common import COMPARE_DISCLAIMER, status_text
from reposentinel.reporting.json_report import valid_unicode

COMPARISON_SCHEMA_VERSION = "1.0"


def _info(info: ReportInfo) -> dict[str, Any]:
    return {
        "report": info.label,
        "target": info.target,
        "scanned_at": info.scanned_at.isoformat(),
        "tool_version": info.tool_version,
        "outcome": info.outcome.value,
        "files_in_scope": info.files_in_scope,
    }


def _issue(issue: CoverageIssue) -> dict[str, Any]:
    return {"path": issue.path, "reason": issue.reason.value, "detail": issue.detail}


def comparison_to_dict(result: ComparisonResult) -> dict[str, Any]:
    return {
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "tool": {"name": "reposentinel"},
        "old": _info(result.old),
        "new": _info(result.new),
        "targets_match": result.targets_match,
        "different_roots_declared": result.different_roots_declared,
        "scope": SCOPE_STATEMENT,
        "headline": headline(result),
        "summary": summary_sentences(result),
        "disclaimer": COMPARE_DISCLAIMER,
        "fail_on": result.fail_on.value if result.fail_on is not None else "never",
        "exit_code": int(result.exit_code),
        "exit_explanation": exit_explanation(result),
        "counts": {status.value: result.count(status) for status in ComparisonStatus},
        "unknowns": result.unknown_count,
        "files_examined": result.files_examined,
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "status": finding.status.value,
                "status_text": status_text(finding),
                "explanation": finding.explanation,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "check": finding.check_id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "path": finding.path,
                "old_lines": list(finding.old_lines),
                "new_lines": list(finding.new_lines),
                "old_occurrences": finding.old_count,
                "new_occurrences": finding.new_count,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "recheck_limits": finding.recheck_limits,
                "credential_reminder": (
                    CREDENTIAL_REMINDER if finding.credential_reminder else None
                ),
            }
            for finding in result.findings
        ],
        "checks": [
            {
                "id": check.check_id,
                "name": check.name,
                "old_status": check.old_status.value if check.old_status else None,
                "new_status": check.new_status.value if check.new_status else None,
                "old_examined": check.old_examined,
                "new_examined": check.new_examined,
            }
            for check in result.checks
        ],
        "check_problems": list(result.check_problems),
        "coverage_errors": [_issue(issue) for issue in result.coverage_errors],
        "not_examined": [_issue(issue) for issue in result.not_examined],
        "config_differences": list(result.config_differences),
        "notes": list(result.notes),
    }


def render_compare_json(result: ComparisonResult) -> str:
    return json.dumps(valid_unicode(comparison_to_dict(result)), indent=2) + "\n"
