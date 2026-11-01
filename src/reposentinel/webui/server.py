"""Local HTTP server for the optional web UI. This is a security boundary.

Threat model: the server runs on the user's computer while the user's browser
also visits arbitrary websites. A hostile page must not be able to start a
scan, read a result, or reach the server through DNS rebinding; another user
on the network must not be able to connect at all.

Controls (each is tested in tests/test_webui_server.py):

* Listens on 127.0.0.1 only, never on another interface.
* Every request must carry a ``Host`` header naming this exact address and
  port (``127.0.0.1:PORT`` or ``localhost:PORT``). This defeats DNS rebinding,
  where an attacker's domain is made to resolve to 127.0.0.1.
* No cookies. Cookies are not isolated by port (RFC 6265, section 8.5): a
  browser sends 127.0.0.1's cookies to every port, any service on any port
  can also set them (section 8.6), and the Path attribute is no protection
  (section 4.1.2.4). So the session credential is a random 256-bit bearer
  token that the page keeps in memory only and sends in an ``Authorization``
  header, which a browser never attaches on its own: no navigation, form,
  image or request from another page or port can carry it.
* The token is obtained once per launch with a one-time launch code. The
  terminal shows ``http://127.0.0.1:PORT/s/<prefix>/#launch=<code>``; the code
  is in the fragment, which browsers never send to any server. The page
  removes it from the address bar and history, then exchanges it (a POST to
  ``api/session/start``) for the token. A code works once, for 10 minutes;
  a new code (Enter in the terminal) invalidates the previous one, and each
  exchange issues a new token, ending any earlier tab's session. Tokens
  expire after ``SESSION_LIFETIME`` and die with the server.
* The app lives under a per-launch base path (``/s/<prefix>/``); everything
  outside it answers 404. This is routing hygiene, not a credential.
* Every API call is a POST to a fixed path and must have: an ``Origin``
  header equal to this server's origin; the custom header
  ``X-RepoSentinel-Request: 1``; a JSON body within a size limit; and, except
  for the launch-code exchange, ``Authorization: Bearer <token>`` (compared in
  constant time). No CORS headers are ever sent, so another origin cannot
  send these headers (the preflight is never granted).
* Only purpose-built operations exist (``webui.api``): scan a folder the user
  typed, compare two uploaded reports, download those results. There is no
  file browsing, file reading, shell or process execution, and scans run only
  the native checks (never an external tool).
* Static files are served from a fixed list built at start-up from the
  packaged build directory, so a request path can never select another file.
* Every response has a strict Content-Security-Policy (scripts, styles and
  connections only from this origin), ``nosniff``, ``no-referrer``, no
  framing, and ``no-store`` caching. Request logging is off, so neither paths
  nor launch codes are printed.

Remaining limits (documented in docs/webui.md): the token is in the page's
memory, so script injected into the page could use it (the CSP and React's
escaping exist to prevent that); and software already running as the user
can read this process's or the browser's memory. Reloading the page ends the
session (the token is not stored); press Enter in the terminal for a new link.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import secrets
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar

from reposentinel.engine import describe_exception
from reposentinel.history import HistoryStore
from reposentinel.webui.api import MAX_UPLOAD_REPORT_BYTES, ApiError, Workspace

BIND_ADDRESS = "127.0.0.1"
LAUNCH_CODE_LIFETIME = 600.0  # seconds
SESSION_LIFETIME = 8 * 60 * 60  # seconds a token stays valid
LAUNCH_FRAGMENT = "#launch="
REQUEST_HEADER = "X-RepoSentinel-Request"
SMALL_BODY = 64 * 1024
COMPARE_BODY = 2 * ((MAX_UPLOAD_REPORT_BYTES * 4) // 3 + 1024) + 4096
LINGER_LIMIT = COMPARE_BODY + SMALL_BODY  # most unread request data discarded before closing
LINGER_SECONDS = 2.0  # how long to wait for more of it
STATIC_PACKAGE = "reposentinel.webui"
STATIC_DIR = "static"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class UiNotBuiltError(Exception):
    """The packaged frontend build is missing (see docs/webui.md)."""


def load_static_files(root: Path | None = None) -> dict[str, tuple[bytes, str]]:
    """URL path -> (content, content type) for every file of the frontend build."""
    if root is None:
        base = resources.files(STATIC_PACKAGE).joinpath(STATIC_DIR)
        root = Path(str(base))
    index = root / "index.html"
    if not index.is_file():
        raise UiNotBuiltError(
            "the web interface has not been built. From the repository folder run: "
            "cd frontend; npm ci; npm run build (see docs/webui.md)"
        )
    files: dict[str, tuple[bytes, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            url = "/" + path.relative_to(root).as_posix()
            kind = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            if kind.startswith("text/") or kind in ("application/javascript",):
                kind += "; charset=utf-8"
            files[url] = (path.read_bytes(), kind)
    files["/"] = files["/index.html"]
    return files


class Session:
    """Launch codes and the bearer token for one run of ``reposentinel ui``."""

    def __init__(self, port: int) -> None:
        self.port = port
        # 128 bits: the base path of the app and API (routing, not a credential).
        self.base_path = f"/s/{secrets.token_urlsafe(16)}/"
        self._lock = threading.Lock()
        self._token: str | None = None  # 256 bits once a launch code is exchanged
        self._started = 0.0
        self._launch_code: str | None = None
        self._issued = 0.0
        self.new_launch_code()

    def new_launch_code(self) -> str:
        """Issue a one-time code; any earlier unused code stops working."""
        with self._lock:
            self._launch_code = secrets.token_urlsafe(24)
            self._issued = time.monotonic()
            return self._launch_code

    @property
    def launch_url(self) -> str:
        with self._lock:
            code = self._launch_code
        return f"http://127.0.0.1:{self.port}{self.base_path}{LAUNCH_FRAGMENT}{code}"

    def start(self, code: str) -> str | None:
        """Exchange a launch code for a new token (once, within its lifetime)."""
        with self._lock:
            expected = self._launch_code
            if expected is None or time.monotonic() - self._issued > LAUNCH_CODE_LIFETIME:
                return None
            if not hmac.compare_digest(code.encode(), expected.encode()):
                return None
            self._launch_code = None
            self._token = secrets.token_urlsafe(32)  # replaces any earlier session
            self._started = time.monotonic()
            return self._token

    def authorized(self, header: str | None) -> bool:
        """True for ``Bearer <current token>`` while the session has not expired."""
        with self._lock:
            token, started = self._token, self._started
        if token is None or time.monotonic() - started > SESSION_LIFETIME:
            return False
        scheme, _, value = (header or "").partition(" ")
        return scheme == "Bearer" and hmac.compare_digest(value.encode(), token.encode())

    def valid_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    def valid_origins(self) -> set[str]:
        return {f"http://{host}" for host in self.valid_hosts()}


Operation = Callable[[Any], Any]


class Handler(BaseHTTPRequestHandler):
    server_version = "RepoSentinel"
    sys_version = ""
    timeout = 60  # seconds to receive a request; a slow client cannot hold a thread forever

    # Set by make_server.
    session: ClassVar[Session]
    workspace: ClassVar[Workspace]
    static: ClassVar[dict[str, tuple[bytes, str]]]

    def version_string(self) -> str:
        return self.server_version  # no Python or library version in the Server header

    def log_message(self, format: str, *args: Any) -> None:
        """No request logging (nothing about requests is printed)."""

    def finish(self) -> None:
        if self.command == "POST" and not getattr(self, "_body_read", False):
            self._linger()
        super().finish()

    def _linger(self) -> None:
        """After replying to a request whose body was not read, discard that body.

        Closing a socket while unread request data is still arriving makes the
        operating system reset the connection (always on Windows), and the
        client can then lose the reply it was already sent: a browser would
        report "not responding" instead of, say, "too large". So the server
        stops sending, then reads and discards what the client is still
        sending, bounded in size and time, before closing ("lingering close").
        """
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            self.connection.settimeout(LINGER_SECONDS)
            remaining = LINGER_LIMIT
            while remaining > 0:
                chunk = self.connection.recv(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass  # the client has gone; nothing more to do

    # --- responses ---------------------------------------------------------

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("ascii")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Errors raised by the HTTP machinery itself: an unsupported method, or a
        malformed or oversized request. They get the same security headers and
        JSON body as every other response, with a fixed message, instead of the
        standard library's HTML page (which has no security headers and echoes
        parts of the request)."""
        del message, explain  # never echo request text
        self.close_connection = True
        extra = {"Connection": "close"}
        if code == HTTPStatus.NOT_IMPLEMENTED:  # the standard library's "unsupported method"
            code = HTTPStatus.METHOD_NOT_ALLOWED
            extra["Allow"] = "GET, HEAD, POST"
        try:
            text = HTTPStatus(code).phrase.lower()
        except ValueError:
            text = "error"
        body = json.dumps({"error": text}, ensure_ascii=True).encode("ascii")
        self._send(code, body, "application/json; charset=utf-8", extra)

    # --- checks applied to every request -----------------------------------

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.session.valid_hosts()

    def _same_site_fetch(self) -> bool:
        # Browsers send Sec-Fetch-Site; when present it must not be cross-site.
        site = self.headers.get("Sec-Fetch-Site")
        return site in (None, "same-origin", "none")

    # --- GET: static files and the launch link ------------------------------

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if not self._host_ok():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "unexpected Host header")
            return
        path = self.path.split("?", 1)[0]
        if path == self.session.base_path.rstrip("/"):
            self._send(HTTPStatus.PERMANENT_REDIRECT, b"", "text/plain", {"Location": path + "/"})
            return
        relative = self._relative(path)
        if relative is None:
            self._send(HTTPStatus.NOT_FOUND, NOT_HERE, "text/plain; charset=utf-8")
            return
        if relative.startswith("/api/"):
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "API calls must use POST")
            return
        entry = self.static.get(relative)
        if entry is None:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        self._send(HTTPStatus.OK, entry[0], entry[1])

    def _relative(self, path: str) -> str | None:
        """The path inside this session's base path ("/..."), or None if outside it."""
        base = self.session.base_path
        head = path[: len(base)]
        if len(path) < len(base) or not hmac.compare_digest(head.encode(), base.encode()):
            return None
        return "/" + path[len(base) :]

    # --- POST: the API ---------------------------------------------------------

    def do_POST(self) -> None:
        relative = self._relative(self.path.split("?", 1)[0])
        routes: dict[str, tuple[Operation, int, bool]] = {
            "/api/session/start": (self._start_session, SMALL_BODY, False),
            "/api/session": (self.workspace.session, SMALL_BODY, False),
            "/api/scan": (self.workspace.scan, SMALL_BODY, False),
            "/api/scan/export": (self.workspace.export_scan, SMALL_BODY, True),
            "/api/compare": (self.workspace.compare, COMPARE_BODY, False),
            "/api/compare/export": (self.workspace.export_comparison, SMALL_BODY, True),
            "/api/data": (self.workspace.data_info, SMALL_BODY, False),
            "/api/data/delete-all": (self.workspace.data_delete_all, SMALL_BODY, False),
            "/api/activity": (self.workspace.activity, SMALL_BODY, False),
            "/api/demo/create": (self.workspace.demo_create, SMALL_BODY, False),
            "/api/projects": (self.workspace.projects_list, SMALL_BODY, False),
            "/api/projects/add": (self.workspace.projects_add, SMALL_BODY, False),
            "/api/projects/rename": (self.workspace.projects_rename, SMALL_BODY, False),
            "/api/projects/move": (self.workspace.projects_move, SMALL_BODY, False),
            "/api/projects/remove": (self.workspace.projects_remove, SMALL_BODY, False),
            "/api/projects/clear-history": (self.workspace.projects_clear, SMALL_BODY, False),
            "/api/projects/scan": (self.workspace.projects_scan, SMALL_BODY, False),
            "/api/history": (self.workspace.history_list, SMALL_BODY, False),
            "/api/history/scan": (self.workspace.history_get, SMALL_BODY, False),
            "/api/history/delete": (self.workspace.history_delete, SMALL_BODY, False),
            "/api/history/compare": (self.workspace.history_compare, SMALL_BODY, False),
            "/api/history/export": (self.workspace.history_export, SMALL_BODY, True),
        }
        if not self._host_ok():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "unexpected Host header")
            return
        if self.headers.get("Origin") not in self.session.valid_origins():
            self._error(HTTPStatus.FORBIDDEN, "cross-origin requests are not allowed")
            return
        if not self._same_site_fetch() or self.headers.get(REQUEST_HEADER) != "1":
            self._error(HTTPStatus.FORBIDDEN, "missing or invalid request header")
            return
        if relative is None:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        route = routes.get(relative)
        if relative != "/api/session/start" and not self.session.authorized(
            self.headers.get("Authorization")
        ):
            self._error(
                HTTPStatus.UNAUTHORIZED,
                "no active session (it expired, or the page was reloaded or opened in "
                "another tab): press Enter in the terminal running 'reposentinel ui' "
                "for a new link",
            )
            return
        if route is None:
            self._error(HTTPStatus.NOT_FOUND, "unknown API operation")
            return
        operation, limit, is_download = route
        body = self._read_json(limit)
        if body is _INVALID:
            return
        try:
            result = operation(body)
        except ApiError as problem:
            self._error(problem.status, problem.message)
            return
        except Exception as exc:  # never a traceback: it could quote repository content
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"internal error: {describe_exception(exc)}. This is a bug in RepoSentinel.",
            )
            return
        if is_download:
            filename, content = result
            self._send(
                HTTPStatus.OK,
                content,
                "application/octet-stream",
                {"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        else:
            self._json(HTTPStatus.OK, result)

    def _start_session(self, body: Any) -> dict[str, str]:
        """Exchange the one-time launch code for this session's bearer token."""
        code = body.get("launch_code") if isinstance(body, dict) else None
        if not isinstance(body, dict) or set(body) != {"launch_code"} or not isinstance(code, str):
            raise ApiError(400, "expected exactly one field: launch_code")
        token = self.session.start(code[:256])
        if token is None:
            raise ApiError(
                403,
                "this launch link has already been used or has expired: press Enter in "
                "the terminal running 'reposentinel ui' for a new link",
            )
        return {"token": token}

    def _read_json(self, limit: int) -> Any:
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "the body must be application/json")
            return _INVALID
        if self.headers.get("Transfer-Encoding"):
            self._error(HTTPStatus.BAD_REQUEST, "chunked request bodies are not accepted")
            return _INVALID
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
            return _INVALID
        if length < 0 or length > limit:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "the request body is too large")
            return _INVALID
        raw = self.rfile.read(length)
        self._body_read = True
        try:
            return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            self._error(HTTPStatus.BAD_REQUEST, "the body is not valid JSON")
            return _INVALID


_INVALID = object()
NOT_HERE = (
    b"RepoSentinel: nothing here. Open the one-time link printed by 'reposentinel ui' "
    b"in the terminal."
)


class LocalServer(ThreadingHTTPServer):
    """A threading HTTP server bound exclusively to 127.0.0.1, with no DNS lookups."""

    daemon_threads = True
    # SO_REUSEADDR on Windows lets another process bind the same port.
    allow_reuse_address = False

    def server_bind(self) -> None:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)  # Windows only
        if exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        # HTTPServer.server_bind would call socket.getfqdn(), a reverse DNS
        # lookup; bind directly instead.
        socketserver.TCPServer.server_bind(self)
        self.server_name = BIND_ADDRESS
        self.server_port = self.server_address[1]


def _reject_constant(name: str) -> Any:
    raise ValueError(name)


def make_server(
    port: int = 0,
    static: dict[str, tuple[bytes, str]] | None = None,
    store: HistoryStore | None = None,
) -> tuple[LocalServer, Session]:
    """Create (but do not start) the server on 127.0.0.1. ``port=0`` picks a free port.

    ``store`` is the local project history; without one the UI offers one-off
    scans and report comparison only."""
    files = load_static_files() if static is None else static
    server = LocalServer((BIND_ADDRESS, port), Handler)
    session = Session(server.server_address[1])
    handler = type(
        "BoundHandler",
        (Handler,),
        {"session": session, "workspace": Workspace(store), "static": files},
    )
    server.RequestHandlerClass = handler
    return server, session
