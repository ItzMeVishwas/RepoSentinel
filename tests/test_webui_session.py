"""Session isolation of the local web interface (bearer token, no cookies).

Cookies are not isolated by port (RFC 6265, section 8.5): a browser sends
127.0.0.1's cookies to every port, and the Path attribute is no protection
(section 4.1.2.4). An earlier design scoped a session cookie to a secret
path; a service on another port that learned the path received the cookie.
The session credential is therefore a bearer token that the page holds in
memory and sends in an Authorization header, which a browser never attaches
by itself. These tests check that: no credential reaches another local
service, even one that knows the base path; requests without the header
(forms, navigation, cookies, other origins) are refused; launch codes work
once and expire; tokens rotate, expire and do not carry over between
launches. The same scenarios run in a real browser in frontend/e2e/run.mjs.
"""

from __future__ import annotations

import http.cookiejar
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from reposentinel.webui import server
from tests.test_webui_server import (
    STATIC,
    Running,
    api_call,
    launch_code,
    raw_request,
    start_session,
)

OPERATIONS = (
    "/api/session",
    "/api/scan",
    "/api/scan/export",
    "/api/compare",
    "/api/compare/export",
)


class Spy:
    """Another web service on 127.0.0.1 that records every header it receives."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str]]] = []
        spy = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                spy.requests.append((self.path, dict(self.headers.items())))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True).start()

    def saw(self, secret: str) -> list[str]:
        return [path for path, headers in self.requests if secret in str(headers)]


@pytest.fixture
def spy() -> Iterator[Spy]:
    service = Spy()
    try:
        yield service
    finally:
        service.httpd.shutdown()
        service.httpd.server_close()


@pytest.fixture
def running() -> Iterator[Running]:
    """A started server whose launch code has been exchanged (as in test_webui_server)."""
    httpd, session = server.make_server(0, static=STATIC)
    threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True).start()
    try:
        status, body = start_session(session)
        assert status == 200
        yield Running(session.port, session, body["token"])
    finally:
        httpd.shutdown()
        httpd.server_close()


def browser_like_opener() -> tuple[Any, http.cookiejar.CookieJar]:
    """An HTTP client that stores and sends cookies by the same rules as browsers."""
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


# --- another local service, even one that knows the base path ---------------


def test_no_credential_reaches_another_local_service(running: Running, spy: Spy) -> None:
    opener, jar = browser_like_opener()
    base = running.session.base_path
    opener.open(f"http://127.0.0.1:{running.port}{base}", timeout=30).read()  # the app
    assert list(jar) == []  # the server set no cookie at all
    # The other service is visited at every path, including the secret base path.
    for path in ("/", base, base + "api/session", "/s/"):
        opener.open(f"http://127.0.0.1:{spy.port}{path}", timeout=30).read()
    assert spy.saw(running.token) == []
    assert all("Authorization" not in headers for _, headers in spy.requests)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_knowing_the_base_path_without_the_token_gains_nothing(
    running: Running, operation: str
) -> None:
    # What another program (with forged browser headers) can do with the path alone.
    assert api_call(running, operation, {}, Authorization=None)[0] == 401


def test_an_injected_cookie_is_ignored(running: Running) -> None:
    # Any service on any port can set cookies for 127.0.0.1 (RFC 6265, 8.6).
    for cookie in (f"reposentinel_session={running.token}", "reposentinel_session=x"):
        assert api_call(running, "/api/session", {}, Authorization=None, Cookie=cookie)[0] == 401


@pytest.mark.parametrize(
    "headers",
    [
        # An HTML form on another site or port (urlencoded or text/plain): forms
        # cannot send an Authorization header, an Origin of this server, or the
        # custom header.
        {"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
        {"Origin": "http://evil.example", "Content-Type": "text/plain"},
        {"Origin": "http://127.0.0.1:1", "Content-Type": "text/plain"},
        # Even a form posted from this origin lacks the token and the custom header.
        {"Content-Type": "application/x-www-form-urlencoded"},
    ],
)
def test_form_style_requests_are_refused(running: Running, headers: dict[str, str]) -> None:
    request_headers = {"Origin": running.origin, **headers}
    status, _, _ = raw_request(
        running.port,
        "POST",
        running.url("/api/scan"),
        headers=request_headers,
        body=b'{"path": "C:\\\\"}',
    )
    assert status in (401, 403, 415)


def test_navigation_to_the_api_is_refused(running: Running) -> None:
    for method in ("GET", "HEAD"):
        assert raw_request(running.port, method, running.url("/api/scan"))[0] == 405


# --- the launch code ---------------------------------------------------------------


def test_launch_code_exchange_needs_this_origin_and_the_header() -> None:
    httpd, session = server.make_server(0, static=STATIC)
    threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True).start()
    try:
        code = launch_code(session)
        for headers in (
            {"Origin": "http://evil.example"},
            {"Origin": "http://127.0.0.1:1"},
            {"X-RepoSentinel-Request": "0"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            assert start_session(session, code, **headers)[0] == 403
        # GET (a navigation or link preview) cannot exchange it.
        assert raw_request(session.port, "GET", session.base_path + "api/session/start")[0] == 405
        # It still works afterwards: the refused attempts did not use it up.
        assert start_session(session, code)[0] == 200
        assert start_session(session, code)[0] == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_launch_code_exchange_rejects_extra_or_wrong_fields(running: Running) -> None:
    for payload in ({}, {"launch_code": 5}, {"launch_code": "x", "token": "y"}):
        status, _, _ = api_call(running, "/api/session/start", payload, Authorization=None)
        assert status == 400


def test_old_launch_links_are_gone(running: Running) -> None:
    status, headers, _ = raw_request(running.port, "GET", "/launch/anything")
    assert status == 404 and "set-cookie" not in headers


# --- tokens ---------------------------------------------------------------------------


def test_session_expires(running: Running, monkeypatch: pytest.MonkeyPatch) -> None:
    assert api_call(running, "/api/session", {})[0] == 200
    monkeypatch.setattr(server, "SESSION_LIFETIME", -1)
    status, _, body = api_call(running, "/api/session", {})
    assert status == 401 and b"press Enter" in body


def test_a_token_from_another_launch_is_refused(running: Running) -> None:
    other = server.Session(running.port)
    token = other.start(launch_code(other))
    assert api_call(running, "/api/session", {}, Authorization=f"Bearer {token}")[0] == 401


def test_a_new_link_ends_the_previous_tab_session(running: Running) -> None:
    running.session.new_launch_code()
    status, body = start_session(running.session)
    assert status == 200
    assert api_call(running, "/api/session", {})[0] == 401  # the old token
    new = Running(running.port, running.session, body["token"])
    assert api_call(new, "/api/session", {})[0] == 200


def test_no_session_before_the_launch_code_is_used() -> None:
    session = server.Session(1)
    assert not session.authorized("Bearer ")
    assert not session.authorized(None)


# --- routing and reliability ----------------------------------------------------------


def test_nothing_is_served_outside_the_base_path(running: Running) -> None:
    status, headers, body = raw_request(running.port, "GET", "/")
    assert status == 404 and b"one-time link" in body
    assert headers["content-security-policy"] == server.CONTENT_SECURITY_POLICY
    for path in ("/index.html", "/assets/app.js", "/s/", "/s/wrong-prefix/"):
        assert raw_request(running.port, "GET", path)[0] == 404
    for path in ("/api/session", "/s/wrong-prefix/api/session"):
        status, _, _ = raw_request(
            running.port,
            "POST",
            path,
            headers={
                "Origin": running.origin,
                "Authorization": f"Bearer {running.token}",
                "X-RepoSentinel-Request": "1",
                "Content-Type": "application/json",
            },
            body=b"{}",
        )
        assert status == 404


def test_base_path_without_slash_redirects(running: Running) -> None:
    base = running.session.base_path
    status, headers, _ = raw_request(running.port, "GET", base.rstrip("/"))
    assert status == 308 and headers["location"] == base


def test_rejected_requests_still_deliver_their_reply(running: Running) -> None:
    # Regression test for an intermittent failure (about 1 run in 10): the
    # server refused requests before reading their body and closed the
    # connection with that body unread. Windows then resets the connection,
    # and the client could lose the reply ("WinError 10053"). A large body
    # makes the race near-certain; every reply must still arrive.
    body = b"{" + b" " * (2 * 1024 * 1024) + b"}"
    cases = [
        ({"Origin": "http://evil.example"}, 403),  # refused before reading
        ({}, 413),  # over the size limit of /api/scan
    ]
    for _ in range(10):
        for extra, expected in cases:
            headers = {
                "Origin": running.origin,
                "Authorization": f"Bearer {running.token}",
                "X-RepoSentinel-Request": "1",
                "Content-Type": "application/json",
                **extra,
            }
            status, _, reply = raw_request(
                running.port, "POST", running.url("/api/scan"), headers=headers, body=body
            )
            assert status == expected and b"error" in reply
