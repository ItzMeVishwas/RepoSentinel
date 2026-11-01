"""Smoke-test an INSTALLED RepoSentinel (for example from a freshly built wheel).

Run it with the Python of the environment where the wheel is installed, from
any folder; it works in a new temporary folder and imports nothing from the
source tree:

    <venv>/bin/python scripts/smoke_installed.py              # UI expected
    <venv>/bin/python scripts/smoke_installed.py --no-ui      # wheel built without the UI

It checks: the package is imported from the installed location (not a source
checkout); version, help and rules; a scan of the synthetic demo repository
(every rule, exit code 1, valid JSON 1.1, HTML with its CSP); a before/after
comparison in all formats with exit codes 1, 0 (--fail-on never), 3 (unknown)
and 2 (invalid input); and the web interface: launch link, bearer token
scoped to the secret base path, the app and its assets, an API call, and 404
outside the base path. With --no-ui it checks that `ui` explains how to build
the interface and exits 3 while every other command works.
Exits 1 on the first failure.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOKEN_PIECES = ("ghp", "_", "0123456789", "abcdefghijklmnopqrstuvwxyz")


class SmokeFailure(Exception):
    pass


def check(condition: bool, what: str) -> None:
    if not condition:
        raise SmokeFailure(what)
    print(f"ok   {what}", flush=True)


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "reposentinel", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def create_demo(target: Path) -> None:
    spec = importlib.util.spec_from_file_location("create_demo_repo", HERE / "create_demo_repo.py")
    if spec is None or spec.loader is None:
        raise SmokeFailure("cannot load scripts/create_demo_repo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.create_demo_repo(target)


def smoke_cli(work: Path) -> None:
    located = subprocess.run(
        [sys.executable, "-c", "import reposentinel; print(reposentinel.__file__)"],
        cwd=work,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    check("site-packages" in located, f"imported from the installed package ({located})")
    check(cli("--version", cwd=work).stdout.startswith("reposentinel "), "--version")
    help_text = cli("--help", cwd=work).stdout
    check(
        all(word in help_text for word in ("scan", "compare", "rules", "ui")),
        "--help lists commands",
    )
    demo_dir = work / "cli-demo"
    made = cli("demo", str(demo_dir), cwd=work)
    check(
        made.returncode == 0 and (demo_dir / "README.md").is_file(),
        "demo creates the synthetic repository",
    )
    check(
        cli("demo", str(demo_dir), cwd=work).returncode == 2, "demo refuses a folder that has files"
    )
    rules = cli("rules", cwd=work)
    check(rules.returncode == 0 and "RS-GHA-004" in rules.stdout, "rules lists the catalogue")

    demo = work / "demo"
    create_demo(demo)
    before, after = work / "before.json", work / "after.json"
    scan = cli("scan", str(demo), "-f", "json", "-o", str(before), cwd=work)
    check(scan.returncode == 1, f"demo scan exits 1 (got {scan.returncode})")
    report = json.loads(before.read_text(encoding="utf-8"))
    check(report["schema_version"] == "1.1", "JSON report schema 1.1")
    rule_ids = {f["rule_id"] for f in report["findings"]}
    check(len(rule_ids) == 12, f"every native rule fires on the demo ({len(rule_ids)} of 12)")
    token = "".join(TOKEN_PIECES)
    check(token not in before.read_text(encoding="utf-8"), "no synthetic secret in the JSON report")
    sarif_path = work / "reposentinel-report.sarif"
    sarif_run = cli("scan", str(demo), "-f", "sarif", "-o", str(sarif_path), cwd=work)
    sarif_text = sarif_path.read_text(encoding="utf-8")
    sarif = json.loads(sarif_text)
    check(
        sarif_run.returncode == 1
        and sarif["version"] == "2.1.0"
        and len(sarif["runs"][0]["results"]) == len(report["findings"]),
        "SARIF 2.1.0 export lists every finding",
    )
    check(
        token not in sarif_text
        and str(demo) not in sarif_text
        and json.dumps(str(demo))[1:-1] not in sarif_text,
        "SARIF has no secret value and no absolute folder path",
    )
    html = work / "reposentinel-report.html"
    cli("scan", str(demo), "-f", "html", "-o", str(html), cwd=work)
    check("default-src 'none'" in html.read_text(encoding="utf-8"), "HTML report has its CSP")
    text = " ".join(cli("scan", str(demo), "--no-color", cwd=work).stdout.split())
    check(
        "does not mean the repository is secure" in text and "history was scanned" not in text,
        "text report states its limits and claims no history scan",
    )

    (demo / ".env").unlink()
    (demo / "tools").mkdir()
    (demo / "tools" / "release.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
    cli("scan", str(demo), "-f", "json", "-o", str(after), cwd=work)
    compared = cli("compare", str(before), str(after), "--no-color", cwd=work)
    check(compared.returncode == 1, f"compare exits 1 (got {compared.returncode})")
    check(
        "Git history was not scanned" in " ".join(compared.stdout.split()),
        "compare states the scope",
    )
    data = json.loads(cli("compare", str(before), str(after), "-f", "json", cwd=work).stdout)
    check(
        data["counts"]["not_detected_file_removed"] >= 1 and data["counts"]["new"] >= 1,
        "compare statuses",
    )
    page = work / "comparison.html"
    cli("compare", str(before), str(after), "-f", "html", "-o", str(page), cwd=work)
    check(
        "Content-Security-Policy" in page.read_text(encoding="utf-8"), "comparison HTML has its CSP"
    )
    never = cli("compare", str(before), str(after), "--fail-on", "never", cwd=work)
    check(never.returncode == 0, "compare --fail-on never exits 0")
    big = demo / "app" / "settings.py"
    big.write_text(big.read_text(encoding="utf-8") + "#" * 2_000_000, encoding="utf-8")
    unknown_report = work / "unknown.json"
    cli("scan", str(demo), "-f", "json", "-o", str(unknown_report), cwd=work)
    unknown = cli("compare", str(before), str(unknown_report), "--fail-on", "never", cwd=work)
    check(unknown.returncode == 3, f"an unknown result exits 3 (got {unknown.returncode})")
    broken = work / "broken.json"
    broken.write_text("{", encoding="utf-8")
    invalid = cli("compare", str(broken), str(after), cwd=work)
    check(invalid.returncode == 2 and invalid.stdout == "", "invalid report exits 2 without output")


def start_ui(work: Path) -> tuple[subprocess.Popen[str], str]:
    # The local history goes to a temporary folder, never the real user data folder.
    env = {**os.environ, "REPOSENTINEL_DATA_DIR": str(work / "appdata")}
    process = subprocess.Popen(
        [sys.executable, "-m", "reposentinel", "ui", "--no-browser"],
        cwd=work,
        env=env,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    if process.stderr is None:
        raise SmokeFailure("no stderr pipe")
    deadline = time.monotonic() + 30
    seen = ""
    while time.monotonic() < deadline:
        line = process.stderr.readline()
        seen += line
        match = re.search(r"(http://127\.0\.0\.1:\d+/s/[A-Za-z0-9_-]+/#launch=\S+)", seen)
        if match:
            return process, match.group(1)
        if process.poll() is not None:
            break
    process.kill()
    raise SmokeFailure(f"ui did not print a launch link: {seen[-300:]}")


def post_json(url: str, origin: str, body: Any, token: str | None = None) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json", "X-RepoSentinel-Request": "1", "Origin": origin}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(  # noqa: S310 - the local server started above
        url, data=json.dumps(body).encode(), method="POST", headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def smoke_ui(work: Path) -> None:
    process, launch = start_ui(work)
    try:
        address, code = launch.split("#launch=", 1)
        parsed = urllib.parse.urlparse(address)
        origin, base = f"{parsed.scheme}://{parsed.netloc}", parsed.path
        check(
            re.fullmatch(r"/s/[A-Za-z0-9_-]{22,}/", base) is not None, "app is under its base path"
        )
        # A browser requests the address without the fragment: the code never reaches the server.
        with urllib.request.urlopen(address, timeout=30) as response:  # noqa: S310
            page = response.read().decode("utf-8")
            check(response.headers.get("Set-Cookie") is None, "no cookie is ever set")
        check('<div id="root">' in page, "the packaged app loads")
        for asset in re.findall(r'(?:src|href)="\./(assets/[^"]+)"', page):
            with urllib.request.urlopen(origin + base + asset, timeout=30) as response:  # noqa: S310
                check(
                    response.status == 200
                    and "script-src 'self'" in response.headers["Content-Security-Policy"],
                    f"asset {asset} is served with the CSP",
                )
        status, _ = post_json(origin + base + "api/session", origin, {})
        check(status == 401, "the API refuses requests without a token")
        status, body = post_json(origin + base + "api/session/start", origin, {"launch_code": code})
        check(status == 200 and isinstance(body.get("token"), str), "the launch code gives a token")
        token = body["token"]
        status, _again = post_json(
            origin + base + "api/session/start", origin, {"launch_code": code}
        )
        check(status == 403, "the launch code works only once")
        status, session = post_json(origin + base + "api/session", origin, {}, token)
        check(status == 200 and len(session["rules"]) == 12, "the API answers with the token")
        try:
            urllib.request.urlopen(origin + "/", timeout=30)  # noqa: S310
            outside = 200
        except urllib.error.HTTPError as error:
            outside = error.code
        check(outside == 404, "nothing is served outside the base path")
        smoke_history(origin + base, origin, token, work)
    finally:
        process.terminate()
        process.wait(timeout=30)


def smoke_history(api: str, origin: str, token: str, work: Path) -> None:
    """Projects, saved scans, comparison with the previous scan, SARIF, deletion."""
    data_dir = work / "appdata"
    project = work / "history-demo"
    create_demo(project)
    check(not data_dir.exists(), "no local data before a project is registered")
    status, body = post_json(
        api + "api/projects/add", origin, {"name": "Demo", "path": str(project)}, token
    )
    check(status == 200, "a project can be registered")
    project_id = body["project"]["id"]
    check((data_dir / "history.sqlite3").is_file(), "history is stored in the data folder")
    check(
        not any(p.suffix == ".sqlite3" for p in project.rglob("*")),
        "nothing is written into the project",
    )
    status, first = post_json(api + "api/projects/scan", origin, {"project_id": project_id}, token)
    check(status == 200 and first["previous"] is None, "the first project scan is saved")
    (project / ".env").unlink()
    status, second = post_json(api + "api/projects/scan", origin, {"project_id": project_id}, token)
    statuses = {f["status"] for f in second["previous"]["comparison"]["findings"]}
    check(
        status == 200 and "not_detected_file_removed" in statuses,
        "scan again compares with the previous scan",
    )
    status, listing = post_json(api + "api/history", origin, {"project_id": project_id}, token)
    check(status == 200 and len(listing["scans"]) == 2, "the history lists both scans")
    status, exported = post_json(
        api + "api/history/export",
        origin,
        {"scan_id": second["history_scan"]["id"], "format": "sarif"},
        token,
    )
    check(status == 200 and exported["version"] == "2.1.0", "a saved scan exports as SARIF")
    raw = b"".join(p.read_bytes() for p in data_dir.iterdir())
    check(
        "".join(TOKEN_PIECES).encode() not in raw and token.encode() not in raw,
        "no secret or session token is stored",
    )
    status, _ = post_json(api + "api/data/delete-all", origin, {"confirm": "yes"}, token)
    check(status == 400, "deleting all data needs the typed confirmation")
    status, _ = post_json(api + "api/data/delete-all", origin, {"confirm": "DELETE"}, token)
    check(status == 200 and not data_dir.exists(), "all local data can be deleted")


def smoke_no_ui(work: Path) -> None:
    result = cli("ui", "--no-browser", cwd=work)
    check(
        result.returncode == 3 and "npm run build" in result.stderr,
        "ui without the build explains how to build it (exit 3)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-ui", action="store_true", help="the package was built without the UI")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="reposentinel-smoke-") as folder:
        work = Path(folder)
        try:
            smoke_cli(work)
            if args.no_ui:
                smoke_no_ui(work)
            else:
                smoke_ui(work)
        except SmokeFailure as failure:
            print(f"FAIL {failure}", file=sys.stderr)
            return 1
    print("smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
