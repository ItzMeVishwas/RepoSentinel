"""The local project history (``history.HistoryStore``): storage, safety and recovery."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from reposentinel import history
from reposentinel.history import HistoryError, HistoryStore
from reposentinel.reporting import render_json
from tests import synthetic
from tests.helpers import scan, write_files


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "appdata" / "RepoSentinel"


@pytest.fixture
def store(data_dir: Path) -> HistoryStore:
    return HistoryStore(data_dir)


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    return write_files(tmp_path / "work" / "my-app", {"config.env": synthetic.credential_file()})


def test_reading_never_creates_the_data_folder(store: HistoryStore, data_dir: Path) -> None:
    assert store.projects() == []
    assert store.latest_scans() == {}
    assert store.info()["exists"] is False
    with pytest.raises(HistoryError):
        store.project(1)
    with pytest.raises(HistoryError):
        store.record(1)
    assert not data_dir.exists()


def test_register_rename_and_list(store: HistoryStore, project_dir: Path) -> None:
    project = store.add_project("  My   app ", project_dir)
    assert project.name == "My app"  # whitespace normalised
    assert Path(project.path) == project_dir.resolve()
    assert project.available
    assert store.rename_project(project.id, "Renamed").name == "Renamed"
    assert [p.name for p in store.projects()] == ["Renamed"]
    with pytest.raises(HistoryError, match="already registered"):
        store.add_project("Again", project_dir)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        "x" * (history.MAX_NAME_LENGTH + 1),
        "evil" + chr(0x202E),
        "a" + chr(0x1B) + "[31m",
    ],
)
def test_project_names_are_validated(store: HistoryStore, project_dir: Path, name: str) -> None:
    with pytest.raises(HistoryError):
        store.add_project(name, project_dir)


@pytest.mark.parametrize("project_id", ["1", True, None, 1.0, [1]])
def test_ids_must_be_integers(store: HistoryStore, project_id: object) -> None:
    with pytest.raises(HistoryError):
        store.project(project_id)
    with pytest.raises(HistoryError):
        store.record(project_id)


def test_storage_is_never_inside_the_project(tmp_path: Path) -> None:
    project = write_files(tmp_path / "proj", {"a.txt": "x\n"})
    inside = HistoryStore(project / ".reposentinel-data")
    with pytest.raises(HistoryError, match="outside scanned projects"):
        inside.add_project("Proj", project)
    # ... nor may a project be the data folder or inside it.
    outside = HistoryStore(tmp_path / "data")
    (tmp_path / "data" / "nested").mkdir(parents=True)
    with pytest.raises(HistoryError, match="outside scanned projects"):
        outside.add_project("Nested", tmp_path / "data" / "nested")
    assert not (project / ".reposentinel-data").exists()


def test_scans_are_stored_outside_the_project(
    store: HistoryStore, data_dir: Path, project_dir: Path
) -> None:
    before = sorted(p.relative_to(project_dir) for p in project_dir.rglob("*"))
    project = store.add_project("App", project_dir)
    store.save_scan(project.id, scan(project_dir))
    assert (data_dir / history.DB_NAME).is_file()
    assert sorted(p.relative_to(project_dir) for p in project_dir.rglob("*")) == before


def test_no_secret_values_are_stored(
    store: HistoryStore, data_dir: Path, project_dir: Path
) -> None:
    project = store.add_project("App", project_dir)
    report = scan(project_dir)
    assert report.findings  # the fixture has credentials to find
    store.save_scan(project.id, report)
    store.delete_scan(store.save_scan(project.id, report).id)  # deleted rows can linger in pages
    raw = b"".join(p.read_bytes() for p in data_dir.iterdir() if p.is_file())
    for secret in synthetic.SECRET_VALUES:
        assert secret.encode() not in raw, secret
        assert secret.encode("utf-16-le") not in raw, secret
    # Nor any file content beyond what the JSON report holds (redacted evidence).
    assert b"synthetic test configuration" not in raw


def test_stored_report_round_trips_through_the_strict_loader(
    store: HistoryStore, project_dir: Path
) -> None:
    project = store.add_project("App", project_dir)
    report = scan(project_dir)
    record = store.save_scan(project.id, report)
    loaded_record, loaded = store.load(record.id)
    assert loaded_record == record
    # The same content (the loader sorts the exclusion lists' keys).
    assert json.loads(render_json(loaded)) == json.loads(render_json(report))
    assert record.findings == len(report.findings)
    assert record.severity == {s.value: n for s, n in report.severity_counts().items()}
    assert record.outcome == report.outcome.value
    assert record.checks_total == len(report.checks)


def test_scans_newest_first_latest_and_recurrence(store: HistoryStore, project_dir: Path) -> None:
    project = store.add_project("App", project_dir)
    first = store.save_scan(project.id, scan(project_dir))
    (project_dir / "config.env").unlink()
    second = store.save_scan(project.id, scan(project_dir))
    assert [r.id for r in store.scans(project.id)] == [second.id, first.id]
    assert store.latest_scans() == {project.id: second}
    _, report = store.load(first.id)
    fingerprints = {f.fingerprint for f in report.findings}
    assert store.seen_before(project.id, second.id, fingerprints) == fingerprints
    assert store.seen_before(project.id, first.id, fingerprints) == set()


def test_oldest_scans_are_pruned(
    store: HistoryStore, project_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(history, "MAX_SCANS_PER_PROJECT", 3)
    project = store.add_project("App", project_dir)
    report = scan(project_dir)
    ids = [store.save_scan(project.id, report).id for _ in range(5)]
    assert [r.id for r in store.scans(project.id)] == ids[:-4:-1]


def test_deletion_levels(
    store: HistoryStore, data_dir: Path, project_dir: Path, tmp_path: Path
) -> None:
    other_dir = write_files(tmp_path / "work" / "other", {"a.txt": "x\n"})
    app = store.add_project("App", project_dir)
    other = store.add_project("Other", other_dir)
    report = scan(project_dir)
    one, two = store.save_scan(app.id, report), store.save_scan(app.id, report)
    kept = store.save_scan(other.id, scan(other_dir))
    # One scan.
    store.delete_scan(one.id)
    assert [r.id for r in store.scans(app.id)] == [two.id]
    with pytest.raises(HistoryError):
        store.load(one.id)
    # One project's history; the project stays registered.
    assert store.clear_history(app.id) == 1
    assert store.scans(app.id) == [] and store.project(app.id).name == "App"
    assert store.record(kept.id) == kept
    # Removing a project removes its scans and fingerprints too.
    store.save_scan(app.id, report)
    store.remove_project(app.id)
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        assert conn.execute(
            "SELECT COUNT(*) FROM scan_fingerprints WHERE scan_id != ?", (kept.id,)
        ).fetchone() == (0,)
    conn.close()
    # Everything.
    store.delete_all()
    assert not data_dir.exists()
    assert store.projects() == []
    # The store is usable again afterwards.
    assert store.add_project("App", project_dir).name == "App"


def test_delete_all_keeps_a_folder_with_other_files(
    store: HistoryStore, data_dir: Path, project_dir: Path
) -> None:
    store.add_project("App", project_dir)
    (data_dir / "notes.txt").write_text("not ours\n", encoding="utf-8")
    store.delete_all()
    assert not store.path.exists()
    assert (data_dir / "notes.txt").read_text(encoding="utf-8") == "not ours\n"


def test_missing_folder_and_move(store: HistoryStore, project_dir: Path, tmp_path: Path) -> None:
    project = store.add_project("App", project_dir)
    moved = project_dir.with_name("my-app-moved")
    project_dir.rename(moved)
    assert not store.project(project.id).available
    assert store.move_project(project.id, moved).available
    assert Path(store.project(project.id).path) == moved.resolve()


def test_a_damaged_database_is_reported_not_replaced(store: HistoryStore, data_dir: Path) -> None:
    data_dir.mkdir(parents=True)
    garbage = b"this is not a database" * 100
    store.path.write_bytes(garbage)
    with pytest.raises(HistoryError, match="was not changed"):
        store.projects()
    assert store.path.read_bytes() == garbage


def test_a_newer_schema_is_refused(store: HistoryStore, project_dir: Path) -> None:
    store.add_project("App", project_dir)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    conn.close()
    fresh = HistoryStore(store.data_dir)
    with pytest.raises(HistoryError, match="schema version 99"):
        fresh.projects()


def test_a_tampered_record_is_refused(store: HistoryStore, project_dir: Path) -> None:
    project = store.add_project("App", project_dir)
    record = store.save_scan(project.id, scan(project_dir))
    with sqlite3.connect(store.path) as conn:
        conn.execute('UPDATE scans SET report_json = \'{"schema_version": "9"}\'')
    conn.close()
    with pytest.raises(HistoryError, match=f"stored scan #{record.id} is damaged"):
        store.load(record.id)
    # Its summary stays listable, so it can be found and deleted.
    assert store.scans(project.id) == [record]
    store.delete_scan(record.id)


def test_a_failed_change_is_rolled_back(
    store: HistoryStore, project_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = store.add_project("App", project_dir)
    report = scan(project_dir)

    def fail(*args: object) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "_db", _wrap_db(store, fail))
    with pytest.raises(HistoryError):
        store.save_scan(project.id, report)
    monkeypatch.undo()
    assert store.scans(project.id) == []  # the scan row was not left behind


def _wrap_db(store: HistoryStore, fail: Callable[..., None]) -> Callable[[], Any]:
    """``store._db`` whose connection fails on ``executemany`` (after the INSERT)."""
    original = HistoryStore._db

    class Failing:
        def __init__(self, conn: sqlite3.Connection) -> None:
            self._conn = conn

        def execute(self, *args: object) -> object:
            return self._conn.execute(*args)  # type: ignore[arg-type]

        def executemany(self, *args: object) -> None:
            fail(*args)

    @contextmanager
    def wrapped() -> Iterator[Failing]:
        with original(store) as conn:
            yield Failing(conn)

    return wrapped


def test_default_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("REPOSENTINEL_DATA_DIR", str(tmp_path / "x"))
    assert history.default_data_dir() == tmp_path / "x"
    monkeypatch.delenv("REPOSENTINEL_DATA_DIR")
    folder = history.default_data_dir()
    assert folder.name.lower() == "reposentinel"
    assert folder.is_absolute()
