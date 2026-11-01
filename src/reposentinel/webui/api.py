"""The local API's operations, independent of HTTP so they can be tested directly.

Each public function takes the parsed JSON body (untrusted) and returns a
JSON-serialisable result or raises ``ApiError``. Request fields are checked
strictly: unknown fields, wrong types and out-of-range values are rejected.

Results come from the same code the CLI uses: ``engine.run_scan`` and
``engine.exit_code_for`` for scans, ``report_loader`` and
``compare.compare_reports`` for comparisons, and the existing JSON and HTML
renderers for downloads. Scans and comparisons are kept in memory only (the
last few), never written to disk.
"""

from __future__ import annotations

import base64
import binascii
import tempfile
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reposentinel import __version__
from reposentinel.checks import all_rules, default_checks
from reposentinel.cli import FailOn, UsageProblem, validate_target
from reposentinel.compare import (
    DETECTED,
    NO_LONGER_DETECTED,
    UNKNOWN,
    ComparisonError,
    ComparisonResult,
    ComparisonStatus,
    compare_reports,
)
from reposentinel.demo import create_demo_repo
from reposentinel.engine import ExitCode, exit_code_for, run_scan
from reposentinel.history import MAX_SCANS_PER_PROJECT, HistoryError, HistoryStore
from reposentinel.models import ScanReport
from reposentinel.redact import sanitize_text
from reposentinel.report_loader import ReportError, load_report_bytes
from reposentinel.reporting import render_html, render_json, report_to_dict
from reposentinel.reporting.common import OUTCOME_HEADLINES
from reposentinel.reporting.compare_html import render_compare_html
from reposentinel.reporting.compare_json import comparison_to_dict, render_compare_json
from reposentinel.reporting.sarif import render_sarif
from reposentinel.walker import DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_FILES, ScanLimits

MAX_UPLOAD_REPORT_BYTES = 16 * 1024 * 1024  # per report; use the CLI for larger reports
MAX_PATH_LENGTH = 4096
MAX_FILE_SIZE_KB = 1024 * 1024  # 1 GiB
MAX_FILES = 1_000_000
KEEP_RESULTS = 4  # scans and comparisons kept in memory for downloads

_SCAN_EXPLANATIONS = {
    ExitCode.OK: "Exit code 0: no findings at or above the threshold.",
    ExitCode.FINDINGS: "Exit code 1: findings at or above the threshold.",
    ExitCode.INCOMPLETE: "Exit code 3: the scan is incomplete.",
}


DISPLAY_MAX_LENGTH = 4000


def display_copy(value: Any) -> Any:
    """A copy of report data with every string made safe to show in a browser.

    The browser escapes HTML, but invisible characters (bidirectional
    overrides, zero-width spaces, control characters) would still be rendered
    and could make text read differently from what it is. Each string goes
    through ``redact.sanitize_text``, the same function the terminal and HTML
    reports use, so they appear as visible codes such as ``\\u202e``. Downloads
    are not affected: they are the real reports.
    """
    if isinstance(value, str):
        return sanitize_text(value, max_length=DISPLAY_MAX_LENGTH)
    if isinstance(value, dict):
        return {key: display_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [display_copy(item) for item in value]
    return value


class ApiError(Exception):
    """A request the API refuses. ``status`` is the HTTP status to return."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        # Messages can quote a report file name or a path the user typed.
        self.message = sanitize_text(message, max_length=500)


# --- strict request field access -------------------------------------------


def _fields(body: Any, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(body, dict):
        raise ApiError(400, "the request body must be a JSON object")
    unknown = set(body) - allowed
    if unknown:
        raise ApiError(400, "unknown request field(s): " + ", ".join(sorted(unknown)))
    missing = required - set(body)
    if missing:
        raise ApiError(400, "missing request field(s): " + ", ".join(sorted(missing)))
    return body


def _int(body: Mapping[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = body.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ApiError(400, f"{key} must be a whole number from {minimum} to {maximum}")
    return value


def _str(body: Mapping[str, Any], key: str, maximum: int) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ApiError(400, f"{key} must be non-empty text of at most {maximum} characters")
    return value


def _bool(body: Mapping[str, Any], key: str) -> bool:
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise ApiError(400, f"{key} must be true or false")
    return value


def _choice(body: Mapping[str, Any], key: str, choices: tuple[str, ...], default: str) -> str:
    value = body.get(key, default)
    if value not in choices:
        raise ApiError(400, f"{key} must be one of: " + ", ".join(choices))
    return str(value)


# --- state ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Stored:
    scans: OrderedDict[str, ScanReport]
    comparisons: OrderedDict[str, ComparisonResult]


class Workspace:
    """The UI's operations. One-off results live in memory (a few of each);
    project scans are saved in the local history (``history.HistoryStore``)."""

    def __init__(self, store: HistoryStore | None = None) -> None:
        self.store = store
        self._stored = _Stored(OrderedDict(), OrderedDict())
        self._lock = threading.Lock()
        self._scan_running = threading.Lock()
        self._counter = 0

    def _next_id(self, prefix: str) -> str:
        with self._lock:
            self._counter += 1
            return f"{prefix}-{self._counter}"

    def _keep(self, store: OrderedDict[str, Any], key: str, value: Any) -> None:
        with self._lock:
            store[key] = value
            while len(store) > KEEP_RESULTS:
                store.popitem(last=False)

    def _get(self, store: OrderedDict[str, Any], key: object, what: str) -> Any:
        with self._lock:
            if not isinstance(key, str) or key not in store:
                raise ApiError(404, f"that {what} is no longer available; run it again")
            return store[key]

    # --- operations -------------------------------------------------------

    def session(self, body: Any) -> dict[str, Any]:
        _fields(body, set(), set())
        return {
            "version": __version__,
            "history": self.store is not None,  # whether projects and history are available
            "defaults": {
                "max_file_size_kb": DEFAULT_MAX_FILE_SIZE // 1024,
                "max_files": DEFAULT_MAX_FILES,
            },
            "limits": {
                "max_upload_report_bytes": MAX_UPLOAD_REPORT_BYTES,
                "max_file_size_kb": MAX_FILE_SIZE_KB,
                "max_files": MAX_FILES,
            },
            "rules": [
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "confidence": rule.confidence.value,
                    "version": rule.version,
                    "description": rule.description,
                    "severity_rationale": rule.severity_rationale,
                    "remediation": rule.remediation,
                    "limitations": rule.limitations,
                    "recheck_limits": rule.recheck_limits,
                }
                for rule in all_rules()
            ],
        }

    def scan(self, body: Any) -> dict[str, Any]:
        """A one-off scan of a folder; kept in memory only, never in the history."""
        fields = _fields(body, {"path", "max_file_size_kb", "max_files"}, {"path"})
        target = _folder(_str(fields, "path", MAX_PATH_LENGTH))
        report = self._run_scan(target, _limits(fields))
        scan_id = self._next_id("scan")
        self._keep(self._stored.scans, scan_id, report)
        return {"scan_id": scan_id, **_scan_payload(report)}

    def _run_scan(self, target: Path, limits: ScanLimits) -> ScanReport:
        if not self._scan_running.acquire(blocking=False):
            raise ApiError(409, "a scan is already running; wait for it to finish")
        try:
            # Native checks only: the UI never starts external programs.
            return run_scan(target, default_checks(), limits)
        finally:
            self._scan_running.release()

    def export_scan(self, body: Any) -> tuple[str, bytes]:
        fields = _fields(body, {"scan_id", "format"}, {"scan_id", "format"})
        fmt = _choice(fields, "format", EXPORT_FORMATS, "json")
        report: ScanReport = self._get(self._stored.scans, fields["scan_id"], "scan")
        return _export(report, fmt)

    def compare(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"old", "new", "fail_on", "different_roots"}, {"old", "new"})
        fail_on = FailOn(_choice(fields, "fail_on", tuple(f.value for f in FailOn), "low"))
        old_name, old_report = self._uploaded(fields["old"], "old")
        new_name, new_report = self._uploaded(fields["new"], "new")
        try:
            result = compare_reports(
                old_report,
                new_report,
                fail_on=fail_on.threshold(),
                different_roots_declared=_bool(fields, "different_roots"),
                old_label=old_name,
                new_label=new_name,
            )
        except ComparisonError as problem:
            raise ApiError(400, str(problem)) from None
        return self._comparison_payload(result)

    def _comparison_payload(self, result: ComparisonResult) -> dict[str, Any]:
        comparison_id = self._next_id("comparison")
        self._keep(self._stored.comparisons, comparison_id, result)
        return {
            "comparison_id": comparison_id,
            "comparison": display_copy(comparison_to_dict(result)),
            # Which statuses belong to which section, from the comparison module.
            "groups": STATUS_GROUPS,
        }

    def export_comparison(self, body: Any) -> tuple[str, bytes]:
        fields = _fields(body, {"comparison_id", "format"}, {"comparison_id", "format"})
        fmt = _choice(fields, "format", ("json", "html"), "json")
        result: ComparisonResult = self._get(
            self._stored.comparisons, fields["comparison_id"], "comparison"
        )
        content = render_compare_json(result) if fmt == "json" else render_compare_html(result)
        return f"reposentinel-comparison.{fmt}", content.encode("utf-8")

    # --- local data, projects and history ------------------------------------------

    def _history(self) -> HistoryStore:
        if self.store is None:
            raise ApiError(404, "local history is not available in this session")
        return self.store

    def data_info(self, body: Any) -> dict[str, Any]:
        _fields(body, set(), set())
        info = _guard(self._history().info)
        return {**display_copy(info), "max_scans_per_project": MAX_SCANS_PER_PROJECT}

    def data_delete_all(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"confirm"}, {"confirm"})
        if fields["confirm"] != "DELETE":
            raise ApiError(400, "type DELETE to confirm deleting all local RepoSentinel data")
        _guard(self._history().delete_all)
        return {"deleted": True}

    def projects_list(self, body: Any) -> dict[str, Any]:
        _fields(body, set(), set())
        store = self._history()
        projects = _guard(store.projects)
        latest = _guard(store.latest_scans)
        return {
            "projects": [
                display_copy(
                    {
                        "id": project.id,
                        "name": project.name,
                        "path": project.path,
                        "created_at": project.created_at,
                        "available": project.available,
                        "latest": latest[project.id].as_dict() if project.id in latest else None,
                    }
                )
                for project in projects
            ]
        }

    def activity(self, body: Any) -> dict[str, Any]:
        """The most recent saved scans across all projects (for the Overview)."""
        _fields(body, set(), set())
        recent = _guard(self._history().recent_scans, 8)
        return {
            "scans": [
                display_copy({"scan": record.as_dict(), "project_name": name})
                for record, name in recent
            ]
        }

    def demo_create(self, body: Any) -> dict[str, Any]:
        """Create the synthetic demo repository in a new temporary folder and register it.

        The folder is created by RepoSentinel (never a path from the request), holds
        only fake credentials, and is labelled as synthetic in its README.
        """
        _fields(body, set(), set())
        store = self._history()
        folder = Path(tempfile.mkdtemp(prefix="reposentinel-demo-"))
        try:
            create_demo_repo(folder)
        except OSError as exc:
            raise ApiError(
                500, f"could not create the demo folder: {exc.strerror or exc}"
            ) from None
        project = _guard(store.add_project, "Synthetic demo (fake credentials)", folder)
        return {
            "project": display_copy({"id": project.id, "name": project.name, "path": project.path})
        }

    def projects_add(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"name", "path"}, {"name", "path"})
        folder = _folder(_str(fields, "path", MAX_PATH_LENGTH))
        project = _guard(self._history().add_project, fields["name"], folder)
        return {"project": display_copy({"id": project.id, "name": project.name})}

    def projects_rename(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"project_id", "name"}, {"project_id", "name"})
        project = _guard(self._history().rename_project, fields["project_id"], fields["name"])
        return {"project": display_copy({"id": project.id, "name": project.name})}

    def projects_move(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"project_id", "path"}, {"project_id", "path"})
        folder = _folder(_str(fields, "path", MAX_PATH_LENGTH))
        project = _guard(self._history().move_project, fields["project_id"], folder)
        return {"project": display_copy({"id": project.id, "path": project.path})}

    def projects_remove(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"project_id"}, {"project_id"})
        _guard(self._history().remove_project, fields["project_id"])
        return {"removed": True}

    def projects_clear(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"project_id"}, {"project_id"})
        return {"deleted": _guard(self._history().clear_history, fields["project_id"])}

    def projects_scan(self, body: Any) -> dict[str, Any]:
        """Scan a registered project, save the run, and compare it with the previous one."""
        fields = _fields(body, {"project_id", "max_file_size_kb", "max_files"}, {"project_id"})
        store = self._history()
        project = _guard(store.project, fields["project_id"])
        if not project.available:
            raise ApiError(
                400,
                f"the folder {project.path} no longer exists or cannot be opened; if it was "
                "moved or renamed, update the project's location",
            )
        target = _folder(project.path)
        report = self._run_scan(target, _limits(fields))
        record = _guard(store.save_scan, project.id, report)
        return self._scan_view(record.id)

    def history_list(self, body: Any) -> dict[str, Any]:
        """A project's scans, newest first, with what changed between consecutive runs."""
        fields = _fields(body, {"project_id"}, {"project_id"})
        store = self._history()
        project = _guard(store.project, fields["project_id"])
        records = _guard(store.scans, project.id)
        entries: list[dict[str, Any]] = []
        loaded: dict[int, ScanReport] = {}  # each report is loaded (and validated) once

        def report_of(scan_id: int) -> ScanReport:
            if scan_id not in loaded:
                loaded[scan_id] = store.load(scan_id)[1]
            return loaded[scan_id]

        for position, record in enumerate(records):
            entry: dict[str, Any] = {"scan": record.as_dict(), "changes": None}
            older = records[position + 1] if position + 1 < len(records) else None
            if older is not None and position < MAX_TIMELINE_DELTAS:
                try:
                    result = compare_reports(report_of(older.id), report_of(record.id))
                    entry["changes"] = {
                        "previous_scan_id": older.id,
                        "counts": {
                            status.value: result.count(status) for status in ComparisonStatus
                        },
                        "unknowns": result.unknown_count,
                        "recurring": len(
                            store.seen_before(project.id, older.id, _new_fingerprints(result))
                        ),
                    }
                except (HistoryError, ComparisonError) as problem:
                    entry["changes"] = {"previous_scan_id": older.id, "error": str(problem)}
            entries.append(entry)
        listing: dict[str, Any] = display_copy(
            {
                "project": {"id": project.id, "name": project.name, "path": project.path},
                "scans": entries,
                "max_scans": MAX_SCANS_PER_PROJECT,
            }
        )
        return listing

    def history_get(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"scan_id"}, {"scan_id"})
        return self._scan_view(fields["scan_id"])

    def _scan_view(self, scan_id: object) -> dict[str, Any]:
        """A stored scan with its comparison against the project's previous scan."""
        store = self._history()
        record, report = _guard(store.load, scan_id)
        earlier = [r for r in _guard(store.scans, record.project_id) if r.id < record.id]
        payload: dict[str, Any] = {
            "history_scan": record.as_dict(),
            "scan_id": None,
            **_scan_payload(report),
            "previous": None,
        }
        if earlier:
            previous = earlier[0]
            try:
                _, old_report = store.load(previous.id)
                result = compare_reports(
                    old_report,
                    report,
                    old_label=f"scan #{previous.id}",
                    new_label=f"scan #{record.id}",
                )
            except HistoryError as problem:
                payload["previous"] = {"scan_id": previous.id, "error": str(problem)}
            except ComparisonError as problem:
                payload["previous"] = {
                    "scan_id": previous.id,
                    "error": f"{problem}. The project's folder location changed between these "
                    "scans; compare them on the Compare page and confirm they are the same "
                    "repository.",
                }
            else:
                recurring = _guard(
                    store.seen_before, record.project_id, previous.id, _new_fingerprints(result)
                )
                payload["previous"] = {
                    "scan_id": previous.id,
                    **self._comparison_payload(result),
                    "changes": {
                        finding.fingerprint: finding.status.value
                        for finding in result.findings
                        if finding.new_count
                    },
                    "recurring": sorted(recurring),
                }
        return payload

    def history_delete(self, body: Any) -> dict[str, Any]:
        fields = _fields(body, {"scan_id"}, {"scan_id"})
        _guard(self._history().delete_scan, fields["scan_id"])
        return {"deleted": True}

    def history_compare(self, body: Any) -> dict[str, Any]:
        fields = _fields(
            body,
            {"old_scan_id", "new_scan_id", "fail_on", "different_roots"},
            {"old_scan_id", "new_scan_id"},
        )
        fail_on = FailOn(_choice(fields, "fail_on", tuple(f.value for f in FailOn), "low"))
        store = self._history()
        old_record, old_report = _guard(store.load, fields["old_scan_id"])
        new_record, new_report = _guard(store.load, fields["new_scan_id"])
        if old_record.project_id != new_record.project_id:
            raise ApiError(400, "both scans must belong to the same project")
        if old_record.id == new_record.id:
            raise ApiError(400, "choose two different scans")
        try:
            result = compare_reports(
                old_report,
                new_report,
                fail_on=fail_on.threshold(),
                different_roots_declared=_bool(fields, "different_roots"),
                old_label=f"scan #{old_record.id}",
                new_label=f"scan #{new_record.id}",
            )
        except ComparisonError as problem:
            raise ApiError(400, str(problem)) from None
        return self._comparison_payload(result)

    def history_export(self, body: Any) -> tuple[str, bytes]:
        fields = _fields(body, {"scan_id", "format"}, {"scan_id", "format"})
        fmt = _choice(fields, "format", EXPORT_FORMATS, "json")
        record, report = _guard(self._history().load, fields["scan_id"])
        name, content = _export(report, fmt)
        return name.replace("reposentinel-report", f"reposentinel-report-scan-{record.id}"), content

    @staticmethod
    def _uploaded(value: Any, which: str) -> tuple[str, ScanReport]:
        fields = _fields(value, {"name", "data_base64"}, {"name", "data_base64"})
        name = _str(fields, "name", 255)
        encoded = fields["data_base64"]
        if not isinstance(encoded, str):
            raise ApiError(400, f"the {which} report upload is corrupted")
        if len(encoded) > (MAX_UPLOAD_REPORT_BYTES * 4) // 3 + 8:
            mib = MAX_UPLOAD_REPORT_BYTES // (1024 * 1024)
            raise ApiError(
                400,
                f"the {which} report is larger than the {mib} MiB limit for uploads; "
                "use 'reposentinel compare' in a terminal for larger reports",
            )
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(400, f"the {which} report upload is corrupted") from None
        label = Path(name).name or f"{which} report"
        try:
            return label, load_report_bytes(raw, label, MAX_UPLOAD_REPORT_BYTES)
        except ReportError as problem:
            raise ApiError(400, str(problem)) from None


# --- helpers shared by the operations ---------------------------------------------

EXPORT_FORMATS = ("json", "html", "sarif")
MAX_TIMELINE_DELTAS = 30  # consecutive comparisons computed for a history listing
STATUS_GROUPS = {
    "detected": sorted(status.value for status in DETECTED),
    "unknown": sorted(status.value for status in UNKNOWN),
    "no_longer_detected": sorted(status.value for status in NO_LONGER_DETECTED),
}


def _guard[T](operation: Callable[..., T], *args: Any) -> T:
    """Run a history operation; its errors become 400 responses with a safe message."""
    try:
        return operation(*args)
    except HistoryError as problem:
        raise ApiError(400, str(problem)) from None


def _folder(raw_path: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        raise ApiError(400, "enter the full path of the folder (for example C:\\code\\my-app)")
    try:
        return validate_target(path)  # the same checks as `reposentinel scan`
    except UsageProblem as problem:
        raise ApiError(400, str(problem)) from None


def _limits(fields: Mapping[str, Any]) -> ScanLimits:
    size_kb = _int(fields, "max_file_size_kb", DEFAULT_MAX_FILE_SIZE // 1024, 1, MAX_FILE_SIZE_KB)
    max_files = _int(fields, "max_files", DEFAULT_MAX_FILES, 1, MAX_FILES)
    return ScanLimits(max_file_size=size_kb * 1024, max_files=max_files)


def _scan_payload(report: ScanReport) -> dict[str, Any]:
    code = exit_code_for(report, FailOn.LOW.threshold())
    return {
        "report": display_copy(report_to_dict(report)),
        "outcome_headline": OUTCOME_HEADLINES[report.outcome],
        "exit_code": int(code),
        "exit_explanation": _SCAN_EXPLANATIONS[code],
    }


def _export(report: ScanReport, fmt: str) -> tuple[str, bytes]:
    if fmt == "sarif":
        return "reposentinel-report.sarif", render_sarif(report).encode("utf-8")
    content = render_json(report) if fmt == "json" else render_html(report)
    return f"reposentinel-report.{fmt}", content.encode("utf-8")


def _new_fingerprints(result: ComparisonResult) -> set[str]:
    return {
        finding.fingerprint
        for finding in result.findings
        if finding.status in (ComparisonStatus.NEW, ComparisonStatus.NEW_NOT_EXAMINED_BEFORE)
    }
