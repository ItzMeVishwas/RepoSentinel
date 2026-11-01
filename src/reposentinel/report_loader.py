"""Load a saved JSON scan report, treating the file as untrusted input.

``reposentinel compare`` reads two report files that may come from anywhere
(another machine, CI, an email attachment). This module never trusts them:

* the file must be a regular file no larger than ``MAX_REPORT_BYTES``;
* it must be strict UTF-8 JSON (``NaN`` and ``Infinity`` are rejected, and
  pathologically deep nesting is caught);
* its ``schema_version`` must be exactly the version this RepoSentinel writes
  (older reports lack the comparison data; newer ones may mean something else);
* every field is type-checked, and the report must be internally consistent
  (for example its stated outcome must match its checks and coverage).

The result is an ordinary ``ScanReport``. Free-text fields (titles,
summaries, evidence, messages, coverage details) pass through the same
credential redaction as a scan, in case the file was edited or produced by
something else. Paths are kept exactly, because comparisons match on them.
Strings are still untrusted text: renderers escape and sanitise them as for
any scan. Error messages name JSON locations (keys and indexes) but never
quote values from the file, because redaction cannot recognise every
credential. Nothing in a report is ever used to open, read or run anything.
"""

from __future__ import annotations

import enum
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from reposentinel.checks.secrets import redact_known_secrets
from reposentinel.identity import is_valid_fingerprint
from reposentinel.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    CoverageIssue,
    CoverageReason,
    Finding,
    Outcome,
    ScanConfig,
    ScanReport,
    Severity,
)
from reposentinel.reporting.json_report import SCHEMA_VERSION

MAX_REPORT_BYTES = 64 * 1024 * 1024
SUPPORTED_SCHEMA_VERSION = SCHEMA_VERSION
_VERSION_RE = re.compile(r"\d{1,3}\.\d{1,3}")  # only such values are quoted in errors


class ReportError(Exception):
    """A report file cannot be used for a comparison. The message says why."""


def _fail(where: str, problem: str) -> NoReturn:
    raise ReportError(f"{where}: {problem}")


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"non-standard JSON value {name}")


def read_report_json(path: Path) -> Any:
    """Read and parse a report file with size and format limits."""
    try:
        if not path.exists():
            raise ReportError(f"{path}: file not found")
        if not path.is_file():
            raise ReportError(f"{path}: not a report file (it is a folder or a special file)")
        with path.open("rb") as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ReportError(
            f"{path}: cannot be read ({exc.strerror or type(exc).__name__})"
        ) from None
    return decode_report_json(raw, str(path))


def decode_report_json(raw: bytes, label: str, limit: int | None = None) -> Any:
    """Parse report bytes (from a file or an upload) with the size and format limits."""
    limit = MAX_REPORT_BYTES if limit is None else limit
    if len(raw) > limit:
        raise ReportError(
            f"{label}: larger than the {limit // (1024 * 1024)} MiB limit for reports"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ReportError(f"{label}: not valid UTF-8 text") from None
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        raise ReportError(
            f"{label}: not valid JSON. compare needs reports saved with "
            "'reposentinel scan PATH --format json --output FILE'"
        ) from None


def load_report(path: Path) -> ScanReport:
    """Load ``path`` as a RepoSentinel scan report, or raise ``ReportError``."""
    return _parse_labelled(read_report_json(path), str(path))


def load_report_bytes(raw: bytes, label: str, limit: int | None = None) -> ScanReport:
    """Load uploaded report bytes exactly as ``load_report`` loads a file."""
    return _parse_labelled(decode_report_json(raw, label, limit), label)


def _parse_labelled(data: Any, label: str) -> ScanReport:
    try:
        return parse_report(data)
    except ReportError as exc:
        raise ReportError(f"{label}: {exc}") from None


# --- small typed accessors ----------------------------------------------------


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(where, "expected an object")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(where, "expected a list")
    return value


def _str(container: dict[str, Any], key: str, where: str, *, non_empty: bool = False) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        _fail(f"{where}.{key}", "expected text")
    if non_empty and not value:
        _fail(f"{where}.{key}", "must not be empty")
    return value


def _text(container: dict[str, Any], key: str, where: str) -> str:
    """A free-text field, redacted like every text field of a scan."""
    return redact_known_secrets(_str(container, key, where))


def _int(
    container: dict[str, Any], key: str, where: str, *, minimum: int = 0, nullable: bool = False
) -> int | None:
    value = container.get(key)
    if value is None and nullable:
        return None
    # bool is a subclass of int in Python; a JSON true/false is not a number here.
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        _fail(f"{where}.{key}", f"expected a whole number of at least {minimum}")
    return value


def _enum[E: enum.Enum](container: dict[str, Any], key: str, kind: type[E], where: str) -> E:
    value = container.get(key)
    try:
        return kind(value)
    except ValueError:
        allowed = ", ".join(str(member.value) for member in kind)
        _fail(f"{where}.{key}", f"expected one of: {allowed}")


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    items = _list(value, where)
    if not all(isinstance(item, str) for item in items):
        _fail(where, "expected a list of text values")
    return tuple(items)


# --- the report itself --------------------------------------------------------


def _check_schema(data: dict[str, Any]) -> None:
    version = data.get("schema_version")
    tool = data.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "reposentinel":
        raise ReportError("not a RepoSentinel scan report")
    if version == SUPPORTED_SCHEMA_VERSION:
        return
    if version == "1.0":
        raise ReportError(
            "made by an older RepoSentinel (report schema 1.0) without the data needed for "
            "comparison; scan again with this version and save the report with --format json"
        )
    shown = f" {version}" if isinstance(version, str) and _VERSION_RE.fullmatch(version) else ""
    raise ReportError(
        f"unsupported report schema{shown}; this RepoSentinel reads schema "
        f"{SUPPORTED_SCHEMA_VERSION} only (a newer RepoSentinel may have written it)"
    )


def _parse_config(value: Any) -> ScanConfig:
    where = "scan_config"
    config = _obj(value, where)
    rule_versions_raw = _obj(config.get("rule_versions"), f"{where}.rule_versions")
    rule_versions: dict[str, int] = {}
    for rule_id, version in rule_versions_raw.items():
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            _fail(f"{where}.rule_versions", "every value must be a version number of at least 1")
        rule_versions[rule_id] = version
    limits_raw = _obj(config.get("limits"), f"{where}.limits")
    limits = {
        key: _int(limits_raw, key, f"{where}.limits", minimum=1)
        for key in ("max_file_size", "max_files", "max_depth")
    }
    exclusions_raw = _obj(config.get("exclusions"), f"{where}.exclusions")
    exclusions = {
        key: _str_list(values, f"{where}.exclusions")
        for key, values in sorted(exclusions_raw.items())
    }
    return ScanConfig(
        checks=_str_list(config.get("checks"), f"{where}.checks"),
        rule_versions=rule_versions,
        limits={key: value for key, value in limits.items() if value is not None},
        exclusions=exclusions,
    )


def _parse_checks(data: dict[str, Any]) -> tuple[CheckResult, ...]:
    coverage_by_check = _obj(data.get("coverage_by_check"), "coverage_by_check")
    checks: list[CheckResult] = []
    seen: set[str] = set()
    for index, item in enumerate(_list(data.get("checks"), "checks")):
        where = f"checks[{index}]"
        entry = _obj(item, where)
        check_id = _str(entry, "id", where, non_empty=True)
        if check_id in seen:
            _fail(f"{where}.id", "repeats the id of an earlier check")
        seen.add(check_id)
        coverage_where = f"coverage_by_check (entry for {where})"
        coverage = _obj(coverage_by_check.get(check_id), coverage_where)
        examined_raw = coverage.get("examined_paths")
        examined_paths = (
            None
            if examined_raw is None
            else _str_list(examined_raw, f"{coverage_where}.examined_paths")
        )
        checks.append(
            CheckResult(
                check_id=check_id,
                name=_text(entry, "name", where),
                status=_enum(entry, "status", CheckStatus, where),
                finding_count=_int(entry, "findings", where) or 0,
                examined=_int(entry, "examined", where, nullable=True),
                message=_text(entry, "message", where),
                examined_paths=examined_paths,
            )
        )
    return tuple(checks)


def _parse_findings(data: dict[str, Any], check_ids: set[str]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for index, item in enumerate(_list(data.get("findings"), "findings")):
        where = f"findings[{index}]"
        entry = _obj(item, where)
        location = entry.get("location")
        path: str | None = None
        line: int | None = None
        if location is not None:
            location = _obj(location, f"{where}.location")
            path = _str(location, "path", f"{where}.location")
            line = _int(location, "line", f"{where}.location", minimum=1, nullable=True)
        check_id = _str(entry, "check", where, non_empty=True)
        if check_id not in check_ids:
            _fail(f"{where}.check", "refers to a check the report does not list")
        fingerprint = entry.get("fingerprint")
        if not is_valid_fingerprint(fingerprint):
            _fail(f"{where}.fingerprint", "expected 'rs1:' followed by 64 hexadecimal digits")
        try:
            findings.append(
                Finding(
                    rule_id=_str(entry, "rule_id", where, non_empty=True),
                    title=_text(entry, "title", where),
                    severity=_enum(entry, "severity", Severity, where),
                    confidence=_enum(entry, "confidence", Confidence, where),
                    summary=_text(entry, "summary", where),
                    evidence=_text(entry, "evidence", where),
                    remediation=_text(entry, "remediation", where),
                    check_id=check_id,
                    path=path,
                    line=line,
                    fingerprint=str(fingerprint),
                    rule_version=_int(entry, "rule_version", where, minimum=1, nullable=True),
                )
            )
        except ValueError as exc:
            _fail(where, str(exc))
    return tuple(findings)


def _parse_coverage(data: dict[str, Any]) -> tuple[CoverageIssue, ...]:
    issues: list[CoverageIssue] = []
    for index, item in enumerate(_list(data.get("coverage"), "coverage")):
        where = f"coverage[{index}]"
        entry = _obj(item, where)
        reason = _enum(entry, "reason", CoverageReason, where)
        if entry.get("is_error") is not reason.is_error:
            _fail(f"{where}.is_error", "does not match the coverage reason")
        issues.append(
            CoverageIssue(_str(entry, "path", where), reason, _text(entry, "detail", where))
        )
    return tuple(issues)


def parse_report(value: Any) -> ScanReport:
    """Validate parsed JSON and turn it into a ``ScanReport``."""
    data = _obj(value, "report")
    _check_schema(data)
    tool = _obj(data.get("tool"), "tool")
    scanned_at_text = _str(data, "scanned_at", "report")
    try:
        scanned_at = datetime.fromisoformat(scanned_at_text)
    except ValueError:
        _fail("report.scanned_at", "expected an ISO 8601 date and time")
    if scanned_at.tzinfo is None:
        _fail("report.scanned_at", "expected a time zone")

    checks = _parse_checks(data)
    findings = _parse_findings(data, {check.check_id for check in checks})
    coverage = _parse_coverage(data)
    files = _str_list(data.get("files"), "files")
    config = _parse_config(data.get("scan_config"))
    if config.checks != tuple(check.check_id for check in checks):
        _fail("scan_config.checks", "does not match the checks listed in the report")
    summary = _obj(data.get("summary"), "summary")
    files_in_scope = _int(summary, "files_in_scope", "summary") or 0
    if files_in_scope != len(files):
        _fail("summary.files_in_scope", "does not match the number of files listed")

    for index, finding in enumerate(findings):
        expected = config.rule_versions.get(finding.rule_id)
        if expected is not None and finding.rule_version != expected:
            _fail(f"findings[{index}].rule_version", "does not match scan_config.rule_versions")

    report = ScanReport(
        target=_str(data, "target", "report"),
        tool_version=_text(tool, "version", "tool"),
        scanned_at=scanned_at,
        files_in_scope=files_in_scope,
        checks=checks,
        findings=findings,
        coverage=coverage,
        files=files,
        scan_config=config,
    )
    declared = _enum(data, "outcome", Outcome, "report")
    if declared is not report.outcome:
        _fail("report.outcome", "does not match the report's checks and coverage")
    return report
