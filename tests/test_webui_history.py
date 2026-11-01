"""The web interface's projects and history API, through a real local server.

Each test starts the server with a history store in a temporary folder, so
nothing is written to the real per-user data folder.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from reposentinel.history import HistoryStore
from reposentinel.webui import server
from tests import synthetic
from tests.helpers import write_files
from tests.test_leak_regression import BROKEN_WORKFLOW, FORBIDDEN, RAW_CONTROLS, WORKFLOW
from tests.test_webui_server import STATIC, Running, api_call, api_json, launch_code, start_session

HISTORY_ROUTES = [
    "/api/data",
    "/api/data/delete-all",
    "/api/projects",
    "/api/projects/add",
    "/api/projects/rename",
    "/api/projects/move",
    "/api/projects/remove",
    "/api/projects/clear-history",
    "/api/projects/scan",
    "/api/history",
    "/api/history/scan",
    "/api/history/delete",
    "/api/history/compare",
    "/api/history/export",
]


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "appdata"


@pytest.fixture
def live(data_dir: Path) -> Iterator[Running]:
    httpd, session = server.make_server(0, static=STATIC, store=HistoryStore(data_dir))
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        status, body = start_session(session)
        assert status == 200
        yield Running(session.port, session, body["token"])
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    return write_files(
        tmp_path / "work" / "app",
        {"config.env": synthetic.credential_file(), "main.py": "x = 1\n"},
    )


def ok(running: Running, path: str, payload: Any) -> Any:
    status, body = api_json(running, path, payload)
    assert status == 200, (path, body)
    return body


def add(running: Running, folder: Path, name: str = "App") -> int:
    return int(
        ok(running, "/api/projects/add", {"name": name, "path": str(folder)})["project"]["id"]
    )


# --- availability and authentication ------------------------------------------------


def test_without_a_store_history_is_unavailable() -> None:
    httpd, session = server.make_server(0, static=STATIC)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        _, body = start_session(session)
        running = Running(session.port, session, body["token"])
        status, reply = api_json(running, "/api/projects", {})
        assert status == 404 and "not available" in reply["error"]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_every_history_route_needs_the_session_token(
    live: Running, route: str, data_dir: Path
) -> None:
    assert api_call(live, route, {}, Authorization=None)[0] == 401
    assert api_call(live, route, {}, Authorization="Bearer wrong")[0] == 401
    assert api_call(live, route, {}, Origin="http://evil.example")[0] == 403
    assert api_call(live, route, {}, X_RepoSentinel_Request=None)[0] == 403
    assert api_call(live, route, {}, Sec_Fetch_Site="cross-site")[0] == 403
    assert not data_dir.exists()  # refused requests changed nothing


def test_the_launch_code_and_token_are_never_stored(
    live: Running, project_dir: Path, data_dir: Path
) -> None:
    code = launch_code(live.session)
    project_id = add(live, project_dir)
    ok(live, "/api/projects/scan", {"project_id": project_id})
    raw = b"".join(p.read_bytes() for p in data_dir.iterdir())
    assert live.token.encode() not in raw
    assert code.encode() not in raw


# --- registering projects --------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"name": "A", "path": "relative/folder"}, "full path"),
        ({"name": "A", "path": "{missing}"}, ""),
        ({"name": "A", "path": "{file}"}, ""),
        ({"name": "", "path": "{project}"}, "1 to 80"),
        ({"name": "bad" + chr(0x202E), "path": "{project}"}, "invisible"),
        ({"name": 5, "path": "{project}"}, ""),
        ({"name": "A", "path": "{project}", "extra": 1}, ""),
        ({"path": "{project}"}, ""),
    ],
)
def test_bad_registrations_are_refused(
    live: Running, project_dir: Path, tmp_path: Path, payload: dict[str, Any], message: str
) -> None:
    replace = {
        "{missing}": str(tmp_path / "nope"),
        "{file}": str(project_dir / "main.py"),
        "{project}": str(project_dir),
    }
    body = {k: replace.get(v, v) if isinstance(v, str) else v for k, v in payload.items()}
    status, reply = api_json(live, "/api/projects/add", body)
    assert status == 400 and message in reply["error"]
    assert ok(live, "/api/projects", {})["projects"] == []


def test_the_data_folder_cannot_be_inside_a_project(tmp_path: Path, project_dir: Path) -> None:
    httpd, session = server.make_server(
        0, static=STATIC, store=HistoryStore(project_dir / ".rs-data")
    )
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        _, body = start_session(session)
        running = Running(session.port, session, body["token"])
        status, reply = api_json(
            running, "/api/projects/add", {"name": "App", "path": str(project_dir)}
        )
        assert status == 400 and "outside scanned projects" in reply["error"]
        assert not (project_dir / ".rs-data").exists()
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- the scan-again-and-compare workflow ---------------------------------------------


def test_scan_again_and_compare(live: Running, project_dir: Path) -> None:
    project_id = add(live, project_dir)
    listing = ok(live, "/api/projects", {})["projects"]
    assert [p["name"] for p in listing] == ["App"] and listing[0]["latest"] is None
    assert listing[0]["available"] is True

    first = ok(live, "/api/projects/scan", {"project_id": project_id})
    assert first["previous"] is None  # nothing to compare with yet
    assert first["history_scan"]["findings"] == len(first["report"]["findings"]) > 0
    assert first["exit_code"] == 1

    (project_dir / "config.env").unlink()
    second = ok(live, "/api/projects/scan", {"project_id": project_id})
    previous = second["previous"]
    assert previous["scan_id"] == first["history_scan"]["id"]
    statuses = {f["status"] for f in previous["comparison"]["findings"]}
    assert statuses == {"not_detected_file_removed"}  # never "fixed" or "resolved"
    assert previous["groups"]["no_longer_detected"]

    write_files(project_dir, {"config.env": synthetic.credential_file()})
    third = ok(live, "/api/projects/scan", {"project_id": project_id})
    changes = third["previous"]["changes"]
    assert set(changes.values()) == {"new"}
    assert set(third["previous"]["recurring"]) == set(changes)  # seen in the first scan

    timeline = ok(live, "/api/history", {"project_id": project_id})
    ids = [entry["scan"]["id"] for entry in timeline["scans"]]
    assert ids == sorted(ids, reverse=True) and len(ids) == 3
    assert timeline["scans"][0]["changes"]["recurring"] == len(changes)
    assert timeline["scans"][-1]["changes"] is None

    picked = ok(live, "/api/history/compare", {"old_scan_id": ids[-1], "new_scan_id": ids[0]})
    assert {f["status"] for f in picked["comparison"]["findings"]} == {"still_detected"}

    view = ok(live, "/api/history/scan", {"scan_id": ids[1]})
    assert view["history_scan"]["id"] == ids[1] and view["previous"]["scan_id"] == ids[2]

    latest = ok(live, "/api/projects", {})["projects"][0]["latest"]
    assert latest["id"] == ids[0]


def test_comparison_export_of_a_history_comparison(live: Running, project_dir: Path) -> None:
    project_id = add(live, project_dir)
    ok(live, "/api/projects/scan", {"project_id": project_id})
    second = ok(live, "/api/projects/scan", {"project_id": project_id})
    comparison_id = second["previous"]["comparison_id"]
    status, headers, body = api_call(
        live, "/api/compare/export", {"comparison_id": comparison_id, "format": "json"}
    )
    assert status == 200 and "attachment" in headers["content-disposition"]
    assert json.loads(body)["findings"]


@pytest.mark.parametrize("fmt", ["json", "html", "sarif"])
def test_exports_of_a_stored_scan(live: Running, project_dir: Path, fmt: str) -> None:
    project_id = add(live, project_dir)
    scan_id = ok(live, "/api/projects/scan", {"project_id": project_id})["history_scan"]["id"]
    status, headers, body = api_call(
        live, "/api/history/export", {"scan_id": scan_id, "format": fmt}
    )
    assert status == 200
    assert headers["content-type"] == "application/octet-stream"
    assert headers["content-disposition"] == (
        f'attachment; filename="reposentinel-report-scan-{scan_id}.{fmt}"'
    )
    text = body.decode("utf-8")
    for secret in synthetic.SECRET_VALUES:
        assert secret not in text
    if fmt == "sarif":
        assert json.loads(text)["version"] == "2.1.0"
        assert str(project_dir) not in text and json.dumps(str(project_dir))[1:-1] not in text


def test_one_off_scans_export_sarif_and_are_not_saved(
    live: Running, project_dir: Path, data_dir: Path
) -> None:
    scan_id = ok(live, "/api/scan", {"path": str(project_dir)})["scan_id"]
    status, _, body = api_call(live, "/api/scan/export", {"scan_id": scan_id, "format": "sarif"})
    assert status == 200 and json.loads(body)["runs"][0]["results"]
    assert not data_dir.exists()  # a one-off scan is never written to the history


def test_scans_of_different_projects_are_not_compared(
    live: Running, project_dir: Path, tmp_path: Path
) -> None:
    other = write_files(tmp_path / "work" / "other", {"a.py": "x = 1\n"})
    a = ok(live, "/api/projects/scan", {"project_id": add(live, project_dir)})["history_scan"]
    b = ok(live, "/api/projects/scan", {"project_id": add(live, other, "Other")})["history_scan"]
    status, reply = api_json(
        live, "/api/history/compare", {"old_scan_id": a["id"], "new_scan_id": b["id"]}
    )
    assert status == 400 and "same project" in reply["error"]
    status, reply = api_json(
        live, "/api/history/compare", {"old_scan_id": a["id"], "new_scan_id": a["id"]}
    )
    assert status == 400 and "two different scans" in reply["error"]


@pytest.mark.parametrize(
    ("route", "payload"),
    [
        ("/api/history/scan", {"scan_id": 999}),
        ("/api/history/scan", {"scan_id": "1"}),
        ("/api/history/export", {"scan_id": 1, "format": "exe"}),
        ("/api/history/compare", {"old_scan_id": 1}),
        ("/api/projects/scan", {"project_id": 1, "max_files": 0}),
        ("/api/projects/rename", {"project_id": 999, "name": "x"}),
        ("/api/history", {"project_id": [1]}),
        ("/api/data", {"anything": 1}),
    ],
)
def test_bad_requests_are_refused(
    live: Running, project_dir: Path, route: str, payload: dict[str, Any]
) -> None:
    project_id = add(live, project_dir)
    ok(live, "/api/projects/scan", {"project_id": project_id})
    assert api_json(live, route, payload)[0] == 400


# --- managing projects and deleting data -----------------------------------------------


def test_missing_folder_rename_and_move(live: Running, project_dir: Path) -> None:
    project_id = add(live, project_dir)
    moved = project_dir.with_name("app-moved")
    project_dir.rename(moved)
    assert ok(live, "/api/projects", {})["projects"][0]["available"] is False
    status, reply = api_json(live, "/api/projects/scan", {"project_id": project_id})
    assert status == 400 and "no longer exists" in reply["error"]
    ok(live, "/api/projects/move", {"project_id": project_id, "path": str(moved)})
    ok(live, "/api/projects/rename", {"project_id": project_id, "name": "Moved app"})
    project = ok(live, "/api/projects", {})["projects"][0]
    assert project["name"] == "Moved app" and project["available"] is True
    ok(live, "/api/projects/scan", {"project_id": project_id})


def test_deleting_one_scan_a_history_and_a_project(live: Running, project_dir: Path) -> None:
    project_id = add(live, project_dir)
    first = ok(live, "/api/projects/scan", {"project_id": project_id})["history_scan"]["id"]
    ok(live, "/api/projects/scan", {"project_id": project_id})
    assert ok(live, "/api/history/delete", {"scan_id": first}) == {"deleted": True}
    assert len(ok(live, "/api/history", {"project_id": project_id})["scans"]) == 1
    assert ok(live, "/api/projects/clear-history", {"project_id": project_id}) == {"deleted": 1}
    assert ok(live, "/api/history", {"project_id": project_id})["scans"] == []
    ok(live, "/api/projects/remove", {"project_id": project_id})
    assert ok(live, "/api/projects", {})["projects"] == []


def test_delete_all_needs_typed_confirmation(
    live: Running, project_dir: Path, data_dir: Path
) -> None:
    ok(live, "/api/projects/scan", {"project_id": add(live, project_dir)})
    info = ok(live, "/api/data", {})
    assert info["exists"] is True and info["projects"] == 1 and info["scans"] == 1
    assert Path(info["data_dir"]) == data_dir.absolute()
    for confirm in ("delete", "yes", "", True):
        assert api_json(live, "/api/data/delete-all", {"confirm": confirm})[0] == 400
    assert data_dir.exists()
    assert ok(live, "/api/data/delete-all", {"confirm": "DELETE"}) == {"deleted": True}
    assert not data_dir.exists()
    assert ok(live, "/api/data", {})["exists"] is False
    assert ok(live, "/api/projects", {})["projects"] == []
    assert project_dir.joinpath("config.env").is_file()  # the project itself is untouched


# --- damaged data and hostile repositories ---------------------------------------------


def test_a_tampered_record_gives_a_safe_error(
    live: Running, project_dir: Path, data_dir: Path
) -> None:
    project_id = add(live, project_dir)
    ok(live, "/api/projects/scan", {"project_id": project_id})
    second = ok(live, "/api/projects/scan", {"project_id": project_id})["history_scan"]["id"]
    marker = "<img src=x onerror=alert(1)>" + chr(0x202E)
    with sqlite3.connect(data_dir / "history.sqlite3") as conn:
        conn.execute(
            "UPDATE scans SET report_json = ? WHERE id = ?",
            (json.dumps({"schema_version": marker}), second),
        )
    conn.close()
    status, reply = api_json(live, "/api/history/scan", {"scan_id": second})
    assert status == 400 and "damaged" in reply["error"]
    assert "onerror" not in reply["error"] and chr(0x202E) not in reply["error"]
    timeline = ok(live, "/api/history", {"project_id": project_id})
    assert "damaged" in timeline["scans"][0]["changes"]["error"]
    ok(live, "/api/history/delete", {"scan_id": second})  # it can still be removed


def test_a_damaged_database_is_reported(live: Running, project_dir: Path, data_dir: Path) -> None:
    add(live, project_dir)
    db = data_dir / "history.sqlite3"
    db.write_bytes(b"\0garbage" * 512)
    status, reply = api_json(live, "/api/projects", {})
    assert status == 400 and "was not changed" in reply["error"]
    assert db.read_bytes() == b"\0garbage" * 512


def test_no_repository_text_leaks_through_history(
    live: Running, tmp_path: Path, data_dir: Path
) -> None:
    root = write_files(
        tmp_path / "work" / "hostile",
        {
            ".github/workflows/ci.yml": WORKFLOW,
            ".github/workflows/broken.yml": BROKEN_WORKFLOW,
            "config.env": synthetic.credential_file(),
        },
    )
    project_id = add(live, root)
    outputs = [
        ok(live, "/api/projects/scan", {"project_id": project_id}),
        ok(live, "/api/projects/scan", {"project_id": project_id}),
        ok(live, "/api/history", {"project_id": project_id}),
        ok(live, "/api/projects", {}),
    ]
    texts = [json.dumps(output, ensure_ascii=False) for output in outputs]
    scan_id = outputs[1]["history_scan"]["id"]
    for fmt in ("json", "html", "sarif"):
        texts.append(
            api_call(live, "/api/history/export", {"scan_id": scan_id, "format": fmt})[2].decode()
        )
    # The stored text (reports, names, paths) is checked like any other output ...
    with sqlite3.connect(data_dir / "history.sqlite3") as conn:
        texts.extend(row[0] for row in conn.execute("SELECT report_json FROM scans"))
        texts.extend(row[0] + row[1] for row in conn.execute("SELECT name, path FROM projects"))
    conn.close()
    for text in texts:
        for value in (*FORBIDDEN, *synthetic.SECRET_VALUES):
            assert value not in text, value
        for control in RAW_CONTROLS:
            assert control not in text, hex(ord(control))
    # ... and the database's raw bytes (which include deleted pages) hold no secret values.
    raw = b"".join(p.read_bytes() for p in data_dir.iterdir())
    for value in (*FORBIDDEN, *synthetic.SECRET_VALUES):
        assert value.encode() not in raw, value


def test_the_session_says_whether_history_is_available(live: Running) -> None:
    assert ok(live, "/api/session", {})["history"] is True
    httpd, session = server.make_server(0, static=STATIC)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        _, body = start_session(session)
        running = Running(session.port, session, body["token"])
        assert ok(running, "/api/session", {})["history"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- onboarding: recent activity and the synthetic demo ---------------------------------


def test_recent_activity_lists_saved_scans_newest_first(live: Running, project_dir: Path) -> None:
    assert ok(live, "/api/activity", {}) == {"scans": []}
    project_id = add(live, project_dir)
    first = ok(live, "/api/projects/scan", {"project_id": project_id})["history_scan"]["id"]
    second = ok(live, "/api/projects/scan", {"project_id": project_id})["history_scan"]["id"]
    activity = ok(live, "/api/activity", {})["scans"]
    assert [entry["scan"]["id"] for entry in activity] == [second, first]
    assert {entry["project_name"] for entry in activity} == {"App"}
    assert api_json(live, "/api/activity", {"limit": 99})[0] == 400


def test_the_synthetic_demo_project(live: Running, data_dir: Path) -> None:
    created = ok(live, "/api/demo/create", {})["project"]
    folder = Path(created["path"])
    try:
        assert "fake" in created["name"].lower()
        assert folder.is_dir() and not folder.is_relative_to(data_dir)
        assert "FAKE" in (folder / "README.md").read_text(encoding="utf-8")
        result = ok(live, "/api/projects/scan", {"project_id": created["id"]})
        rules = {f["rule_id"] for f in result["report"]["findings"]}
        assert len(rules) == 12  # the demo triggers every native rule
        # The request cannot choose where the demo is written.
        assert api_json(live, "/api/demo/create", {"path": str(folder)})[0] == 400
    finally:
        shutil.rmtree(folder)
