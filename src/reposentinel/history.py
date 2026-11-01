"""Local projects and scan history, stored on this computer only.

Storage: one SQLite database (Python's built-in ``sqlite3``) in a per-user
data folder, never inside a scanned project:

* Windows: ``%LOCALAPPDATA%\\RepoSentinel``
* macOS: ``~/Library/Application Support/RepoSentinel``
* Linux and others: ``$XDG_DATA_HOME/reposentinel`` (default ``~/.local/share/reposentinel``)
* ``REPOSENTINEL_DATA_DIR`` overrides all of these (used by tests).

What is stored, per registered project: its display name and folder path,
and for every scan made through it the JSON report exactly as
``reposentinel scan --format json`` writes it (already redacted: findings
with redacted evidence, file paths, coverage, scan configuration, rule
versions), a small summary, and the fingerprints of its findings (hashes of
non-secret identity inputs, see ``identity.py``) for recurrence queries.
Never stored: file contents, matched secret values, session tokens or launch
codes. One-off scans that are not made through a registered project are not
stored at all.

Reliability: every change is one transaction; the schema is versioned and a
newer or unknown version is refused; a damaged database is reported, never
silently repaired or replaced; and every stored report is loaded back through
``report_loader`` (the same strict validation as ``reposentinel compare``),
so a damaged or tampered record is refused instead of compared.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
import threading
import time
import unicodedata
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reposentinel.models import CheckStatus, ScanReport
from reposentinel.redact import sanitize_text
from reposentinel.report_loader import MAX_REPORT_BYTES, ReportError, load_report_bytes
from reposentinel.reporting.json_report import render_json

SCHEMA_VERSION = 1
DB_NAME = "history.sqlite3"
MAX_PROJECTS = 200
MAX_SCANS_PER_PROJECT = 200  # the oldest scans of a project are removed beyond this
MAX_NAME_LENGTH = 80
MAX_PATH_LENGTH = 4096

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    path_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanned_at TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    outcome TEXT NOT NULL,
    files_in_scope INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    high INTEGER NOT NULL,
    medium INTEGER NOT NULL,
    low INTEGER NOT NULL,
    info INTEGER NOT NULL,
    checks_completed INTEGER NOT NULL,
    checks_total INTEGER NOT NULL,
    coverage_errors INTEGER NOT NULL,
    not_examined INTEGER NOT NULL,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_project ON scans(project_id, id);
CREATE TABLE IF NOT EXISTS scan_fingerprints (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS fingerprints_by_value ON scan_fingerprints(fingerprint);
"""


class HistoryError(Exception):
    """A history operation that cannot be done. The message is safe to show."""


def default_data_dir() -> Path:
    """The per-user folder for RepoSentinel's local data (see the module docstring)."""
    override = os.environ.get("REPOSENTINEL_DATA_DIR")
    if override:
        return Path(override)
    home = Path.home()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "RepoSentinel" if base else home / "AppData" / "Local" / "RepoSentinel"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "RepoSentinel"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else home / ".local" / "share") / "reposentinel"


@dataclass(frozen=True, slots=True)
class Project:
    id: int
    name: str
    path: str
    created_at: str

    @property
    def available(self) -> bool:
        """Does the folder still exist (it may have been moved or deleted)?"""
        try:
            return Path(self.path).is_dir()
        except OSError:
            return False


@dataclass(frozen=True, slots=True)
class ScanRecord:
    id: int
    project_id: int
    scanned_at: str
    tool_version: str
    outcome: str
    files_in_scope: int
    findings: int
    severity: dict[str, int]
    checks_completed: int
    checks_total: int
    coverage_errors: int
    not_examined: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scanned_at": self.scanned_at,
            "tool_version": self.tool_version,
            "outcome": self.outcome,
            "files_in_scope": self.files_in_scope,
            "findings": self.findings,
            "severity": dict(self.severity),
            "checks_completed": self.checks_completed,
            "checks_total": self.checks_total,
            "coverage_errors": self.coverage_errors,
            "not_examined": self.not_examined,
        }


_SCAN_COLUMNS = (
    "id, project_id, scanned_at, tool_version, outcome, files_in_scope, findings, high, "
    "medium, low, info, checks_completed, checks_total, coverage_errors, not_examined"
)


def _record(row: tuple[Any, ...]) -> ScanRecord:
    return ScanRecord(
        id=row[0],
        project_id=row[1],
        scanned_at=row[2],
        tool_version=row[3],
        outcome=row[4],
        files_in_scope=row[5],
        findings=row[6],
        severity={"high": row[7], "medium": row[8], "low": row[9], "info": row[10]},
        checks_completed=row[11],
        checks_total=row[12],
        coverage_errors=row[13],
        not_examined=row[14],
    )


def clean_name(name: object) -> str:
    """A project display name: printable, trimmed, 1 to MAX_NAME_LENGTH characters."""
    if not isinstance(name, str):
        raise HistoryError("the project name must be text")
    text = unicodedata.normalize("NFC", " ".join(name.split()))
    if not text or len(text) > MAX_NAME_LENGTH:
        raise HistoryError(f"the project name must have 1 to {MAX_NAME_LENGTH} characters")
    if sanitize_text(text, max_length=MAX_NAME_LENGTH + 10) != text:
        raise HistoryError("the project name contains invisible or control characters")
    return text


def _path_key(path: Path) -> str:
    return os.path.normcase(str(path))


class HistoryStore:
    """Projects and their scan history in one local SQLite database."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / DB_NAME
        self._lock = threading.Lock()
        self._ready = False

    # --- connection and schema -------------------------------------------------

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        """A connection in one transaction (committed on success, rolled back on error)."""
        with self._lock:
            try:
                if not self._ready or not self.path.is_file():
                    self._prepare()
                with closing(sqlite3.connect(self.path, timeout=10)) as conn:
                    conn.execute("PRAGMA foreign_keys = ON")
                    with conn:  # one transaction
                        yield conn
            except sqlite3.DatabaseError as exc:
                raise HistoryError(
                    "the local history database could not be used "
                    f"({type(exc).__name__}). It was not changed. You can delete all local "
                    "history in Settings, or move the file away: " + str(self.path)
                ) from None

    def _prepare(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if sys.platform != "win32":
                self.data_dir.chmod(0o700)  # only this user (Windows: profile permissions)
        except OSError as exc:
            raise HistoryError(
                f"cannot create the local data folder {self.data_dir}: {exc.strerror or exc}"
            ) from None
        with closing(sqlite3.connect(self.path, timeout=10)) as conn:
            check = conn.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError("integrity check failed")
            with conn:
                conn.executescript(_SCHEMA)
                row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
                elif row[0] != str(SCHEMA_VERSION):
                    raise HistoryError(
                        "the local history uses schema version "
                        f"{sanitize_text(row[0], max_length=20)}, "
                        f"but this RepoSentinel understands only version {SCHEMA_VERSION}. "
                        "It was not changed."
                    )
        self._ready = True

    # --- projects ----------------------------------------------------------------

    def _check_location(self, folder: Path) -> None:
        """History must never be written inside a scanned project (or vice versa)."""
        data = self.data_dir.resolve()
        if data.is_relative_to(folder) or folder.is_relative_to(data):
            raise HistoryError(
                "this folder contains RepoSentinel's local data folder (or is inside it); "
                "history must be stored outside scanned projects. Choose another folder or "
                "set REPOSENTINEL_DATA_DIR."
            )

    def add_project(self, name: object, folder: Path) -> Project:
        display = clean_name(name)
        if len(str(folder)) > MAX_PATH_LENGTH:
            raise HistoryError("the folder path is too long")
        resolved = folder.resolve()
        self._check_location(resolved)
        created = datetime.now(UTC).replace(microsecond=0).isoformat()
        with self._db() as conn:
            (count,) = conn.execute("SELECT COUNT(*) FROM projects").fetchone()
            if count >= MAX_PROJECTS:
                raise HistoryError(f"at most {MAX_PROJECTS} projects can be registered")
            if conn.execute(
                "SELECT 1 FROM projects WHERE path_key = ?", (_path_key(resolved),)
            ).fetchone():
                raise HistoryError("this folder is already registered as a project")
            cursor = conn.execute(
                "INSERT INTO projects (name, path, path_key, created_at) VALUES (?, ?, ?, ?)",
                (display, str(resolved), _path_key(resolved), created),
            )
            project_id = cursor.lastrowid
        if project_id is None:
            raise HistoryError("the project could not be saved")
        return Project(project_id, display, str(resolved), created)

    def projects(self) -> list[Project]:
        if not self.path.is_file():
            return []  # reading never creates the data folder
        with self._db() as conn:
            rows = conn.execute(
                "SELECT id, name, path, created_at FROM projects ORDER BY name COLLATE NOCASE, id"
            ).fetchall()
        return [Project(*row) for row in rows]

    def project(self, project_id: object) -> Project:
        if not isinstance(project_id, int) or isinstance(project_id, bool):
            raise HistoryError("unknown project")
        if not self.path.is_file():
            raise HistoryError("unknown project (it may have been removed)")
        with self._db() as conn:
            row = conn.execute(
                "SELECT id, name, path, created_at FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        if row is None:
            raise HistoryError("unknown project (it may have been removed)")
        return Project(*row)

    def rename_project(self, project_id: object, name: object) -> Project:
        project = self.project(project_id)
        display = clean_name(name)
        with self._db() as conn:
            conn.execute("UPDATE projects SET name = ? WHERE id = ?", (display, project.id))
        return Project(project.id, display, project.path, project.created_at)

    def move_project(self, project_id: object, folder: Path) -> Project:
        """Point a project at its folder's new location (after a move or rename)."""
        project = self.project(project_id)
        resolved = folder.resolve()
        self._check_location(resolved)
        with self._db() as conn:
            other = conn.execute(
                "SELECT id FROM projects WHERE path_key = ? AND id != ?",
                (_path_key(resolved), project.id),
            ).fetchone()
            if other:
                raise HistoryError("another project already uses this folder")
            conn.execute(
                "UPDATE projects SET path = ?, path_key = ? WHERE id = ?",
                (str(resolved), _path_key(resolved), project.id),
            )
        return Project(project.id, project.name, str(resolved), project.created_at)

    def remove_project(self, project_id: object) -> None:
        """Remove a project and all of its stored scans."""
        project = self.project(project_id)
        with self._db() as conn:
            conn.execute("DELETE FROM projects WHERE id = ?", (project.id,))

    def clear_history(self, project_id: object) -> int:
        """Delete every stored scan of a project; the project stays registered."""
        project = self.project(project_id)
        with self._db() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE project_id = ?", (project.id,))
            return cursor.rowcount

    # --- scans -------------------------------------------------------------------

    def save_scan(self, project_id: object, report: ScanReport) -> ScanRecord:
        """Store a completed scan run (its outcome may be incomplete) for a project."""
        project = self.project(project_id)
        self._check_location(Path(project.path).resolve())
        document = render_json(report)
        if len(document.encode("utf-8")) > MAX_REPORT_BYTES:
            raise HistoryError("this scan's report is too large to store in the local history")
        counts = report.severity_counts()
        completed = sum(1 for check in report.checks if check.status is CheckStatus.COMPLETED)
        not_examined = sum(1 for issue in report.coverage if not issue.reason.is_error)
        fingerprints = {finding.fingerprint for finding in report.findings}
        with self._db() as conn:
            cursor = conn.execute(
                f"INSERT INTO scans ({_SCAN_COLUMNS.split(', ', 1)[1]}, report_json) "  # noqa: S608 - fixed column list; values are bound parameters
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    project.id,
                    report.scanned_at.isoformat(),
                    report.tool_version,
                    report.outcome.value,
                    report.files_in_scope,
                    len(report.findings),
                    *(counts[severity] for severity in counts),
                    completed,
                    len(report.checks),
                    len(report.coverage_errors),
                    not_examined,
                    document,
                ),
            )
            scan_id = cursor.lastrowid
            conn.executemany(
                "INSERT INTO scan_fingerprints (scan_id, fingerprint) VALUES (?, ?)",
                [(scan_id, value) for value in sorted(fingerprints)],
            )
            # Keep the newest MAX_SCANS_PER_PROJECT scans of this project.
            conn.execute(
                "DELETE FROM scans WHERE project_id = ? AND id NOT IN "
                "(SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?)",
                (project.id, project.id, MAX_SCANS_PER_PROJECT),
            )
            row = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?",  # noqa: S608 - fixed column list; values are bound parameters
                (scan_id,),
            ).fetchone()
        return _record(row)

    def scans(self, project_id: object, limit: int = MAX_SCANS_PER_PROJECT) -> list[ScanRecord]:
        """The project's scans, newest first."""
        project = self.project(project_id)
        with self._db() as conn:
            rows = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans WHERE project_id = ? "  # noqa: S608 - fixed column list; values are bound parameters
                "ORDER BY id DESC LIMIT ?",
                (project.id, limit),
            ).fetchall()
        return [_record(row) for row in rows]

    def latest_scans(self) -> dict[int, ScanRecord]:
        """Each project's newest scan."""
        if not self.path.is_file():
            return {}
        with self._db() as conn:
            rows = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id IN "  # noqa: S608 - fixed column list; values are bound parameters
                "(SELECT MAX(id) FROM scans GROUP BY project_id)"
            ).fetchall()
        return {record.project_id: record for record in map(_record, rows)}

    def recent_scans(self, limit: int = 10) -> list[tuple[ScanRecord, str]]:
        """The newest scans of all projects, with each project's display name."""
        if not self.path.is_file():
            return []
        with self._db() as conn:
            rows = conn.execute(
                f"SELECT {', '.join('s.' + c for c in _SCAN_COLUMNS.split(', '))}, p.name "  # noqa: S608 - fixed column list; values are bound parameters
                "FROM scans s JOIN projects p ON p.id = s.project_id ORDER BY s.id DESC LIMIT ?",
                (max(1, min(limit, 50)),),
            ).fetchall()
        return [(_record(row[:-1]), row[-1]) for row in rows]

    def record(self, scan_id: object) -> ScanRecord:
        if not isinstance(scan_id, int) or isinstance(scan_id, bool):
            raise HistoryError("unknown scan")
        if not self.path.is_file():
            raise HistoryError("unknown scan (it may have been deleted)")
        with self._db() as conn:
            row = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?",  # noqa: S608 - fixed column list; values are bound parameters
                (scan_id,),
            ).fetchone()
        if row is None:
            raise HistoryError("unknown scan (it may have been deleted)")
        return _record(row)

    def load(self, scan_id: object) -> tuple[ScanRecord, ScanReport]:
        """A stored scan's report, validated exactly like a report file given to compare."""
        record = self.record(scan_id)
        with self._db() as conn:
            (document,) = conn.execute(
                "SELECT report_json FROM scans WHERE id = ?", (record.id,)
            ).fetchone()
        try:
            raw = document.encode("utf-8") if isinstance(document, str) else b""
            return record, load_report_bytes(raw, f"stored scan #{record.id}")
        except ReportError as problem:
            raise HistoryError(
                f"stored scan #{record.id} is damaged or was made by an incompatible "
                f"RepoSentinel version, so it cannot be used ({problem}). Delete it or scan again."
            ) from None

    def raw_report(self, scan_id: object) -> str:
        """The stored JSON report text (for downloads)."""
        record, report = self.load(scan_id)  # validates it first
        del record
        return render_json(report)

    def delete_scan(self, scan_id: object) -> None:
        record = self.record(scan_id)
        with self._db() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (record.id,))

    def seen_before(self, project_id: int, before_scan_id: int, fingerprints: set[str]) -> set[str]:
        """Which of ``fingerprints`` occurred in any scan of the project older than one id."""
        if not fingerprints:
            return set()
        found: set[str] = set()
        ordered = sorted(fingerprints)
        with self._db() as conn:
            for start in range(0, len(ordered), 500):
                chunk = ordered[start : start + 500]
                marks = ",".join("?" * len(chunk))
                rows = conn.execute(
                    "SELECT DISTINCT f.fingerprint FROM scan_fingerprints f "  # noqa: S608 - "?" only
                    "JOIN scans s ON s.id = f.scan_id "
                    f"WHERE s.project_id = ? AND s.id < ? AND f.fingerprint IN ({marks})",
                    (project_id, before_scan_id, *chunk),
                ).fetchall()
                found.update(row[0] for row in rows)
        return found

    # --- all data -------------------------------------------------------------------

    def info(self) -> dict[str, Any]:
        exists = self.path.is_file()
        projects = scans = 0
        if exists:
            with self._db() as conn:
                (projects,) = conn.execute("SELECT COUNT(*) FROM projects").fetchone()
                (scans,) = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        return {
            "data_dir": str(self.data_dir),
            "database": str(self.path),
            "exists": exists,
            "bytes": self.path.stat().st_size if exists else 0,
            "projects": projects,
            "scans": scans,
            "schema_version": SCHEMA_VERSION,
        }

    def delete_all(self) -> None:
        """Delete the database (all projects and history). The folder is removed if empty."""
        with self._lock:
            for suffix in ("", "-journal", "-wal", "-shm"):
                target = self.path.with_name(self.path.name + suffix)
                for attempt in range(5):
                    try:
                        target.unlink(missing_ok=True)
                        break
                    except PermissionError:  # Windows: a reader may still have it open
                        if attempt == 4:
                            raise HistoryError(
                                f"could not delete {target}; close other RepoSentinel windows "
                                "and try again"
                            ) from None
                        time.sleep(0.2)
            with contextlib.suppress(OSError):  # not empty (other files) or already gone
                self.data_dir.rmdir()
            self._ready = False
