"""The local web interface's HTTP server: security boundary and parity with the CLI.

A real server is started on 127.0.0.1 (a free port) in a background thread,
and real HTTP requests are made to it. The frontend build is replaced by a
small stand-in so these tests do not need Node.js.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reposentinel import cli
from reposentinel.compare import compare_reports
from reposentinel.engine import exit_code_for
from reposentinel.models import Severity
from reposentinel.report_loader import load_report
from reposentinel.reporting import render_html, render_json, report_to_dict
from reposentinel.reporting.compare_json import comparison_to_dict
from reposentinel.webui import api, server
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan
from tests.test_leak_regression import FORBIDDEN, WORKFLOW

STATIC = {
    "/index.html": (b"<!doctype html><title>stand-in</title>", "text/html; charset=utf-8"),
    "/assets/app.js": (b"console.log(1)", "text/javascript; charset=utf-8"),
}
STATIC["/"] = STATIC["/index.html"]


@dataclass
class Running:
    port: int
    session: server.Session
    token: str  # the bearer token from exchanging the launch code

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url(self, path: str) -> str:
        """``/api/scan`` -> ``/s/<prefix>/api/scan`` (this session's base path)."""
        return self.session.base_path + path.removeprefix("/")


def raw_request(
    port: int,
    method: str,
    path: str,
    *,
    host: str | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host != "":
            conn.putheader("Host", host or f"127.0.0.1:{port}")
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


def api_call(
    running: Running, path: str, payload: Any, **overrides: str | None
) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "Origin": running.origin,
        "Authorization": f"Bearer {running.token}",
        "X-RepoSentinel-Request": "1",
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
    }
    for name, value in overrides.items():
        key = name.replace("_", "-")
        if value is None:
            headers.pop(key, None)
        else:
            headers[key] = value
    return raw_request(
        running.port, "POST", running.url(path), headers=headers, body=json.dumps(payload).encode()
    )


def api_json(running: Running, path: str, payload: Any) -> tuple[int, Any]:
    status, _, body = api_call(running, path, payload)
    return status, json.loads(body)


def launch_code(session: server.Session) -> str:
    """The one-time code from the link the terminal shows (it is in the fragment)."""
    return session.launch_url.split(server.LAUNCH_FRAGMENT, 1)[1]


def start_session(
    session: server.Session, code: str | None = None, **headers: str
) -> tuple[int, Any]:
    """Exchange a launch code for a token, as the page does."""
    status, _, body = raw_request(
        session.port,
        "POST",
        session.base_path + "api/session/start",
        headers={
            "Origin": f"http://127.0.0.1:{session.port}",
            "X-RepoSentinel-Request": "1",
            "Content-Type": "application/json",
            **headers,
        },
        body=json.dumps({"launch_code": launch_code(session) if code is None else code}).encode(),
    )
    return status, json.loads(body)


@pytest.fixture
def running() -> Iterator[Running]:
    httpd, session = server.make_server(0, static=STATIC)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        status, body = start_session(session)
        assert status == 200
        yield Running(session.port, session, body["token"])
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- binding, static files, headers -----------------------------------------


def test_listens_on_loopback_only() -> None:
    httpd, session = server.make_server(0, static=STATIC)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
        assert httpd.server_name == "127.0.0.1"  # no reverse DNS lookup was made
        assert session.port == httpd.server_address[1] > 0
    finally:
        httpd.server_close()


def test_static_files_with_security_headers(running: Running) -> None:
    status, headers, body = raw_request(running.port, "GET", running.session.base_path)
    assert status == 200 and body == STATIC["/"][0]
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in headers
    assert "python" not in headers.get("server", "").lower()


@pytest.mark.parametrize(
    "path", ["/../pyproject.toml", "/assets/../index.html", "/etc/passwd", "/C:/Windows/win.ini"]
)
def test_only_packaged_files_are_served(running: Running, path: str) -> None:
    assert raw_request(running.port, "GET", running.url(path))[0] == 404
    assert raw_request(running.port, "GET", path)[0] == 404


# --- Host header: DNS rebinding ----------------------------------------------


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:{port}", "127.0.0.1:1", "0.0.0.0:{port}", ""]
)
def test_wrong_host_is_refused(running: Running, host: str) -> None:
    host = host.replace("{port}", str(running.port))
    assert raw_request(running.port, "GET", "/", host=host)[0] == 421
    status, _, _ = raw_request(
        running.port,
        "POST",
        "/api/session",
        host=host,
        headers={
            "Origin": running.origin,
            "Authorization": f"Bearer {running.token}",
            "X-RepoSentinel-Request": "1",
            "Content-Type": "application/json",
        },
        body=b"{}",
    )
    assert status == 421


def test_localhost_host_name_is_accepted(running: Running) -> None:
    status = raw_request(
        running.port, "GET", running.session.base_path, host=f"localhost:{running.port}"
    )[0]
    assert status == 200


# --- launch link and session -------------------------------------------------


def test_launch_code_works_once_and_sets_no_cookie() -> None:
    httpd, session = server.make_server(0, static=STATIC)
    threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True).start()
    try:
        url = session.launch_url
        assert url.startswith(f"http://127.0.0.1:{session.port}{session.base_path}#launch=")
        assert start_session(session, "wrong-code")[0] == 403
        status, _, _page = raw_request(session.port, "GET", session.base_path)
        assert status == 200  # loading the page (the fragment is never sent) changes nothing
        status, body = start_session(session)
        assert status == 200 and len(body["token"]) >= 43  # 256 bits
        assert body["token"] not in url
        assert start_session(session)[0] == 403  # single use
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_no_response_ever_sets_a_cookie(running: Running) -> None:
    for method, path in (("GET", running.session.base_path), ("GET", "/")):
        assert "set-cookie" not in raw_request(running.port, method, path)[1]
    for path in ("/api/session", "/api/scan"):
        assert "set-cookie" not in api_call(running, path, {})[1]


def test_launch_code_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    session = server.Session(1234)
    code = launch_code(session)
    monkeypatch.setattr(server, "LAUNCH_CODE_LIFETIME", -1.0)
    assert session.start(code) is None


def test_a_new_launch_code_replaces_the_old_one() -> None:
    session = server.Session(1234)
    old = launch_code(session)
    session.new_launch_code()
    assert session.start(old) is None
    assert session.start(launch_code(session)) is not None


def test_each_exchange_issues_a_new_token_and_ends_the_old_session() -> None:
    session = server.Session(1234)
    first = session.start(launch_code(session))
    session.new_launch_code()
    second = session.start(launch_code(session))
    assert first and second and first != second
    assert not session.authorized(f"Bearer {first}")
    assert session.authorized(f"Bearer {second}")


def test_sessions_are_unpredictable() -> None:
    first, second = server.Session(1), server.Session(1)
    assert launch_code(first) != launch_code(second) and first.base_path != second.base_path
    assert first.start(launch_code(first)) != second.start(launch_code(second))


# --- API request checks: CSRF, cross-origin, method, body ----------------------


@pytest.mark.parametrize(
    ("override", "status"),
    [
        ({"Authorization": None}, 401),
        ({"Authorization": "Bearer forged"}, 401),
        ({"Authorization": "Basic Zm9yZ2Vk"}, 401),
        ({"Authorization": "bearer"}, 401),
        # A cookie is ignored: only the Authorization header authenticates.
        ({"Authorization": None, "Cookie": "reposentinel_session=x"}, 401),
        ({"X_RepoSentinel_Request": None}, 403),
        ({"X_RepoSentinel_Request": "0"}, 403),
        ({"Origin": None}, 403),
        ({"Origin": "http://evil.example"}, 403),
        ({"Origin": "null"}, 403),
        ({"Origin": "http://127.0.0.1:1"}, 403),
        ({"Sec_Fetch_Site": "cross-site"}, 403),
        ({"Content_Type": "text/plain"}, 415),
    ],
)
def test_api_refuses_requests_missing_a_protection(
    running: Running, override: dict[str, str | None], status: int
) -> None:
    assert api_call(running, "/api/session", {}, **override)[0] == status


def test_api_never_grants_cors(running: Running) -> None:
    status, headers, _ = raw_request(
        running.port,
        "OPTIONS",
        running.url("/api/scan"),
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert status in (405, 501) and "access-control-allow-origin" not in headers
    assert raw_request(running.port, "GET", running.url("/api/session"))[0] == 405


def test_unknown_operation_and_body_limits(running: Running) -> None:
    assert api_call(running, "/api/run-command", {})[0] == 404
    assert api_call(running, "/api/session", {"extra": 1})[0] == 400
    status, _, _body = raw_request(
        running.port,
        "POST",
        running.url("/api/scan"),
        headers={
            "Origin": running.origin,
            "Authorization": f"Bearer {running.token}",
            "X-RepoSentinel-Request": "1",
            "Content-Type": "application/json",
            "Content-Length": str(server.SMALL_BODY + 1),
        },
    )
    assert status == 413
    for raw in (b"{not json", b'{"path": NaN}', b"[" * 100_000, b"\xff\xfe"):
        status, _, _ = raw_request(
            running.port,
            "POST",
            running.url("/api/scan"),
            headers={
                "Origin": running.origin,
                "Authorization": f"Bearer {running.token}",
                "X-RepoSentinel-Request": "1",
                "Content-Type": "application/json",
            },
            body=raw,
        )
        assert status in (400, 413)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"path": 5},
        {"path": ""},
        {"path": "relative/folder"},
        {"path": "C:\\", "max_files": 0},
        {"path": "C:\\", "max_files": True},
        {"path": "C:\\", "max_file_size_kb": 10**9},
        {"path": "C:\\", "integration": "gitleaks"},  # not an option of the UI
        {"path": "C:\\", "command": "calc.exe"},
    ],
)
def test_scan_request_validation(running: Running, payload: dict[str, Any]) -> None:
    status, data = api_json(running, "/api/scan", payload)
    assert status == 400 and isinstance(data["error"], str)


def test_scan_path_errors_are_clear(running: Running, tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("x")
    for path, words in (
        (tmp_path / "missing", "path not found"),
        (tmp_path / "file.txt", "not a directory"),
    ):
        status, data = api_json(running, "/api/scan", {"path": str(path)})
        assert status == 400 and words in data["error"]


# --- functional parity with the CLI ----------------------------------------------


def _without_time(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "scanned_at"}


def test_scan_matches_the_cli_engine(running: Running, make_repo: RepoFactory) -> None:
    root = make_repo(
        {
            "config.py": synthetic.credential_file(),
            ".env": "A=1\n",
            ".github/workflows/ci.yml": WORKFLOW,
            "node_modules/x.js": "1",
        }
    )
    status, data = api_json(running, "/api/scan", {"path": str(root)})
    assert status == 200
    direct = scan(root)
    # The display copy equals the CLI's report (it only differs for invisible characters).
    assert _without_time(data["report"]) == _without_time(report_to_dict(direct))
    assert data["exit_code"] == int(exit_code_for(direct, Severity.LOW))
    assert data["outcome_headline"].startswith("FINDINGS")
    text = json.dumps(data)
    for value in (*synthetic.SECRET_VALUES, *FORBIDDEN):
        assert value not in text

    # Downloads are the real renderers' output for that same scan.
    for fmt in ("json", "html"):
        status, headers, body = api_call(
            running, "/api/scan/export", {"scan_id": data["scan_id"], "format": fmt}
        )
        assert status == 200
        assert headers["content-type"] == "application/octet-stream"
        assert headers["content-disposition"] == f'attachment; filename="reposentinel-report.{fmt}"'
        if fmt == "json":
            assert _without_time(json.loads(body)) == _without_time(data["report"])
        else:
            assert body.decode().startswith("<!doctype html>")
            assert "Content-Security-Policy" in body.decode()
            assert body.decode().count('<article class="finding') == len(direct.findings)
    assert render_json(direct) and render_html(direct)  # the renderers used above


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")
def test_scan_through_the_ui_does_not_follow_a_junction(
    running: Running, tmp_path: Path, make_repo: RepoFactory
) -> None:
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n')
    root = make_repo({"a.py": "1\n"})
    _winapi.CreateJunction(str(outside), str(root / "link"))
    status, data = api_json(running, "/api/scan", {"path": str(root)})
    assert status == 200
    assert data["report"]["findings"] == []
    assert {"path": "link", "reason": "symlink"}.items() <= data["report"]["coverage"][0].items()


def test_invisible_characters_are_shown_as_codes(running: Running, make_repo: RepoFactory) -> None:
    rlo, zwsp = chr(0x202E), chr(0x200B)
    root = make_repo({f"docs/notes {rlo}txt.env": "A=1\n", f"a{zwsp}b.env": "B=1\n"})
    status, _, body = api_call(running, "/api/scan", {"path": str(root)})
    assert status == 200
    data = json.loads(body)
    paths = {f["location"]["path"] for f in data["report"]["findings"]}
    assert paths == {"docs/notes \\u202etxt.env", "a\\u200bb.env"}  # visible codes
    raw = json.loads(body.decode())  # no raw invisible character anywhere in the response
    assert rlo not in json.dumps(raw, ensure_ascii=False) and zwsp not in json.dumps(
        raw, ensure_ascii=False
    )
    # The download keeps the exact paths (the report is data, not display).
    status, _, report = api_call(
        running, "/api/scan/export", {"scan_id": data["scan_id"], "format": "json"}
    )
    assert {f["location"]["path"] for f in json.loads(report)["findings"]} == {
        f"docs/notes {rlo}txt.env",
        f"a{zwsp}b.env",
    }


def _upload(path: Path) -> dict[str, str]:
    return {"name": path.name, "data_base64": base64.b64encode(path.read_bytes()).decode()}


def test_compare_matches_the_cli(running: Running, make_repo: RepoFactory, tmp_path: Path) -> None:
    root = make_repo({"a.py": f'T = "{synthetic.GITHUB_TOKEN}"\n', ".env": "A=1\n"})
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    runner = CliRunner()
    runner.invoke(cli.app, ["scan", str(root), "-f", "json", "-o", str(before)])
    (root / ".env").unlink()
    (root / "b.py").write_text(f'T = "{synthetic.AWS_KEY_ID}"\n')
    runner.invoke(cli.app, ["scan", str(root), "-f", "json", "-o", str(after)])

    status, data = api_json(
        running, "/api/compare", {"old": _upload(before), "new": _upload(after)}
    )
    assert status == 200
    direct = compare_reports(
        load_report(before), load_report(after), old_label="before.json", new_label="after.json"
    )
    assert data["comparison"] == api.display_copy(comparison_to_dict(direct))
    cli_exit = runner.invoke(cli.app, ["compare", str(before), str(after)]).exit_code
    assert data["comparison"]["exit_code"] == cli_exit == 1
    assert set(data["groups"]) == {"detected", "unknown", "no_longer_detected"}

    status, data_never = api_json(
        running,
        "/api/compare",
        {"old": _upload(before), "new": _upload(after), "fail_on": "never"},
    )
    assert data_never["comparison"]["exit_code"] == 0

    status, _headers, body = api_call(
        running, "/api/compare/export", {"comparison_id": data["comparison_id"], "format": "html"}
    )
    assert status == 200 and "Git history was not scanned" in body.decode()


def test_compare_refuses_invalid_uploads(running: Running, tmp_path: Path) -> None:
    good = {"name": "a.json", "data_base64": base64.b64encode(b"{}").decode()}
    cases = [
        {"old": good},
        {"old": good, "new": {"name": "b.json", "data_base64": "%%%not base64"}},
        {"old": good, "new": {"name": "b.json", "data_base64": base64.b64encode(b"{").decode()}},
        {"old": good, "new": good, "fail_on": "critical"},
        {"old": good, "new": good, "different_roots": "yes"},
        {"old": {"name": "a.json"}, "new": good},
    ]
    for payload in cases:
        status, data = api_json(running, "/api/compare", payload)
        assert status == 400, payload
        assert "Traceback" not in data["error"]
    future = {"schema_version": "9.0", "tool": {"name": "reposentinel"}}
    payload = {
        "old": {
            "name": "f.json",
            "data_base64": base64.b64encode(json.dumps(future).encode()).decode(),
        },
        "new": good,
    }
    status, data = api_json(running, "/api/compare", payload)
    assert status == 400 and "unsupported report schema" in data["error"]


def test_oversized_upload_is_refused(running: Running, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_UPLOAD_REPORT_BYTES", 10)
    big = {"name": "a.json", "data_base64": base64.b64encode(b" " * 100).decode()}
    status, data = api_json(running, "/api/compare", {"old": big, "new": big})
    assert status == 400 and "larger than the 0 MiB limit" in data["error"]
    # Just under the encoded-size check, the loader's own byte limit applies.
    small = {"name": "a.json", "data_base64": base64.b64encode(b" " * 11).decode()}
    monkeypatch.setattr(api, "MAX_UPLOAD_REPORT_BYTES", 20)
    status, data = api_json(running, "/api/compare", {"old": small, "new": small})
    assert status == 400 and "not valid JSON" in data["error"]


def test_compare_different_roots_need_the_flag(
    running: Running, make_repo: RepoFactory, tmp_path: Path
) -> None:
    first = make_repo({"a.py": "1\n"})
    second = tmp_path / "copy"
    second.mkdir()
    (second / "a.py").write_text("1\n")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    runner = CliRunner()
    runner.invoke(cli.app, ["scan", str(first), "-f", "json", "-o", str(a)])
    runner.invoke(cli.app, ["scan", str(second), "-f", "json", "-o", str(b)])
    status, data = api_json(running, "/api/compare", {"old": _upload(a), "new": _upload(b)})
    assert status == 400 and "--different-roots" in data["error"]
    status, data = api_json(
        running, "/api/compare", {"old": _upload(a), "new": _upload(b), "different_roots": True}
    )
    assert status == 200 and data["comparison"]["different_roots_declared"] is True


def test_export_of_unknown_result_is_404(running: Running) -> None:
    status, _data = api_json(running, "/api/scan/export", {"scan_id": "scan-99", "format": "json"})
    assert status == 404
    status, _ = api_json(running, "/api/scan/export", {"scan_id": "scan-1", "format": "pdf"})
    assert status == 400


# --- failures and concurrency ------------------------------------------------------


def test_internal_errors_never_quote_details(
    running: Running, monkeypatch: pytest.MonkeyPatch, make_repo: RepoFactory
) -> None:
    def explode(self: api.Workspace, body: Any) -> Any:
        raise RuntimeError(f"bad {synthetic.GITHUB_TOKEN} " + FORBIDDEN[1])

    monkeypatch.setattr(api.Workspace, "scan", explode)  # looked up on each request
    status, data = api_json(running, "/api/scan", {"path": str(make_repo({"a": "1"}))})
    assert status == 500
    assert data["error"].startswith("internal error: RuntimeError (details withheld")
    assert synthetic.GITHUB_TOKEN not in data["error"] and FORBIDDEN[1] not in data["error"]


def test_a_second_scan_waits_for_the_first(make_repo: RepoFactory) -> None:
    workspace = api.Workspace()
    root = make_repo({"a.py": "1\n"})
    with workspace._scan_running, pytest.raises(api.ApiError) as info:  # a scan is running
        workspace.scan({"path": str(root)})
    assert info.value.status == 409
    assert workspace.scan({"path": str(root)})["exit_code"] == 0


# --- no network beyond the local connection ------------------------------------------


def test_scan_and_compare_make_no_outside_connections(
    running: Running, make_repo: RepoFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def connect(self: socket.socket, address: Any) -> Any:
        assert address[0] in ("127.0.0.1", "localhost"), address
        return real_connect(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        assert host in ("127.0.0.1", "localhost"), host
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for name in ("create_server", "gethostbyname", "gethostbyaddr", "getfqdn"):
        monkeypatch.setattr(socket, name, _no_network)
    root = make_repo({"a.py": f'T = "{synthetic.GITHUB_TOKEN}"\n'})
    status, data = api_json(running, "/api/scan", {"path": str(root)})
    assert status == 200
    report = tmp_path / "r.json"
    status, _, body = api_call(
        running, "/api/scan/export", {"scan_id": data["scan_id"], "format": "json"}
    )
    report.write_bytes(body)
    status, _ = api_json(running, "/api/compare", {"old": _upload(report), "new": _upload(report)})
    assert status == 200


def _no_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("unexpected network operation")


# --- the ui command -------------------------------------------------------------------


def test_ui_command_without_a_build_explains_how_to_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = server.load_static_files
    monkeypatch.setattr(server, "load_static_files", lambda root=None: original(tmp_path))
    result = CliRunner().invoke(cli.app, ["ui", "--no-browser"])
    assert result.exit_code == 3
    assert "npm run build" in result.stderr


def test_cli_does_not_load_the_web_interface() -> None:
    import subprocess

    code = "import sys, reposentinel.cli; print('reposentinel.webui' in sys.modules)"
    completed = subprocess.run(  # noqa: S603 - fixed arguments, this interpreter
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert completed.stdout.strip() == "False"


def test_ui_prints_the_whole_link_on_one_line(tmp_path: Path) -> None:
    # Regression: the link is long, and the terminal renderer used to wrap it
    # at the console width, breaking the launch code (and copying it).
    import os
    import re
    import subprocess

    with subprocess.Popen(
        [sys.executable, "-m", "reposentinel", "ui", "--no-browser"],
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        env={**os.environ, "COLUMNS": "60", "REPOSENTINEL_DATA_DIR": str(tmp_path / "data")},
    ) as process:
        try:
            assert process.stderr is not None
            lines = [process.stderr.readline() for _ in range(2)]
        finally:
            process.terminate()
            process.wait(timeout=30)
    pattern = r"http://127\.0\.0\.1:\d+/s/[A-Za-z0-9_-]{22}/#launch=[A-Za-z0-9_-]{32}\s*$"
    assert re.search(pattern, lines[1]), lines


@pytest.mark.parametrize("history", ["data-dir", "no-history"])
def test_ui_states_where_history_is_kept(tmp_path: Path, history: str) -> None:
    import subprocess

    data = tmp_path / "data dir"
    option = ["--data-dir", str(data)] if history == "data-dir" else ["--no-history"]
    with subprocess.Popen(  # noqa: S603 - fixed arguments, this interpreter
        [sys.executable, "-m", "reposentinel", "ui", "--no-browser", *option],
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    ) as process:
        try:
            assert process.stderr is not None
            lines = [process.stderr.readline() for _ in range(3)]
        finally:
            process.terminate()
            process.wait(timeout=30)
    if history == "data-dir":
        assert str(data / "history.sqlite3") in lines[2], lines
    else:
        assert "off" in lines[2], lines
    assert not data.exists()  # created only when a project is registered


CRLF = bytes([13, 10])


# --- errors produced by the HTTP machinery itself -------------------------------------


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "PROPFIND"])
def test_unsupported_methods_are_refused_with_security_headers(
    running: Running, method: str
) -> None:
    status, headers, body = raw_request(running.port, method, running.session.base_path)
    assert status == 405
    assert headers["allow"] == "GET, HEAD, POST"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert json.loads(body) == {"error": "method not allowed"}
    assert "access-control-allow-origin" not in headers


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        pytest.param(b"GARBAGE<script>alert(1)</script>" + CRLF * 2, 400, id="bad-request-line"),
        pytest.param(
            b"GET / HTTP/9.9" + CRLF + b"Host: 127.0.0.1" + CRLF * 2, 505, id="bad-version"
        ),
        pytest.param(b"GET /" + b"a" * 70000 + b" HTTP/1.1" + CRLF * 2, 414, id="long-uri"),
        pytest.param(
            b"GET / HTTP/1.1" + CRLF + b"X: " + b"y" * 70000 + CRLF * 2, 431, id="long-header"
        ),
    ],
)
def test_malformed_requests_get_a_fixed_json_error(
    running: Running, request_bytes: bytes, status: int
) -> None:
    with socket.create_connection(("127.0.0.1", running.port), timeout=30) as sock:
        sock.sendall(request_bytes)
        reply = b""
        while chunk := sock.recv(65536):
            reply += chunk
    head, _, body = reply.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    assert lines[0].split(" ")[1] == str(status)
    headers = {k.lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["server"] == "RepoSentinel"  # no Python version
    assert "error" in json.loads(body)
    assert b"script" not in body and b"GARBAGE" not in reply  # nothing echoed
