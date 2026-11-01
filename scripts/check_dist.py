"""Check built packages (wheel and sdist) before publishing them.

Verifies that each archive contains what users need and nothing that should
stay private: no caches, virtual environments, Node.js dependencies, local
tool state, environment files or generated reports. By default it also
requires the web interface's production build, and checks that every file
its index.html refers to is present (a release must not ship a UI that
cannot load).

Usage:
    python scripts/build_release.py          # builds the UI, then dist/*.whl and dist/*.tar.gz
    python scripts/check_dist.py dist
    python scripts/check_dist.py dist --no-ui  # only for a deliberate build without the UI
"""

from __future__ import annotations

import argparse
import email
import fnmatch
import re
import sys
import tarfile
import zipfile
from pathlib import Path

UI_DIR = "reposentinel/webui/static"

REQUIRED_IN_WHEEL = (
    "reposentinel/__init__.py",
    "reposentinel/__main__.py",
    "reposentinel/cli.py",
    "reposentinel/reporting/templates/report.html.j2",
    "reposentinel/reporting/templates/compare.html.j2",
    "reposentinel/reporting/templates/_security_meta.html.j2",
    "reposentinel/webui/server.py",
    "reposentinel/webui/THIRD_PARTY_LICENSES.txt",
)
REQUIRED_IN_SDIST = (
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "src/reposentinel/cli.py",
    "tests/test_cli.py",
    "frontend/package.json",
    "frontend/package-lock.json",
)

LICENSE_EXPRESSION = "MIT"

# Path fragments that must never be published.
FORBIDDEN = (
    "*/.venv/*",
    "*/__pycache__/*",
    "*.pyc",
    "*/.mypy_cache/*",
    "*/.ruff_cache/*",
    "*/.pytest_cache/*",
    "*/.git/*",
    "*/.claude/*",
    "*/.claude-flow/*",
    "*/node_modules/*",
    "*/.swarm/*",
    "*/.env",
    "*/.env.*",
    "*reposentinel-report*",
    "*.sarif",
    "*.sqlite3",
    "*.db",
    "*.log",
    "*.tsbuildinfo",
)

# src="./assets/x.js" or href="./assets/x.css" in the built index.html.
_ASSET_REF = re.compile(r"""(?:src|href)="([^"]+)\"""")


def _forbidden(names: list[str]) -> list[str]:
    # Prefix with "/" so patterns such as "*/.env" also match top-level entries.
    return [n for n in names if any(fnmatch.fnmatch("/" + n, p) for p in FORBIDDEN)]


def check_ui(names: list[str], index_html: str | None, prefix: str) -> list[str]:
    """Problems with the web interface build inside an archive (paths under ``prefix``)."""
    if index_html is None:
        return [f"missing {prefix}/index.html: build the UI first (npm ci; npm run build)"]
    problems: list[str] = []
    refs = _ASSET_REF.findall(index_html)
    if not any(ref.endswith(".js") for ref in refs):
        problems.append(f"{prefix}/index.html loads no script")
    for ref in refs:
        if not ref.startswith("./assets/"):
            # Absolute or external URLs would escape the session's base path or the CSP.
            problems.append(f"{prefix}/index.html refers to {ref!r} (must be ./assets/...)")
        elif f"{prefix}/{ref.removeprefix('./')}" not in names:
            problems.append(f"{prefix}/index.html refers to missing file {ref}")
    return problems


def check_wheel(path: Path, *, ui: bool = True) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        if not metadata_names:
            return ["wheel has no METADATA"]
        metadata = email.message_from_bytes(wheel.read(metadata_names[0]))
        index = f"{UI_DIR}/index.html"
        index_html = wheel.read(index).decode("utf-8") if index in names else None
    problems += [f"wheel is missing {name}" for name in REQUIRED_IN_WHEEL if name not in names]
    problems += [f"wheel contains {name}" for name in _forbidden(names)]
    if metadata["Name"] != "reposentinel":
        problems.append(f"unexpected package name {metadata['Name']!r}")
    if not metadata["Requires-Python"]:
        problems.append("wheel metadata has no Requires-Python")
    if metadata["License-Expression"] != LICENSE_EXPRESSION:
        problems.append(
            f"wheel metadata License-Expression is {metadata['License-Expression']!r}, "
            f"expected {LICENSE_EXPRESSION!r}"
        )
    if not [n for n in names if n.endswith(".dist-info/licenses/LICENSE")]:
        problems.append("wheel does not contain the LICENSE file (.dist-info/licenses/LICENSE)")
    if not [n for n in names if n.endswith(".dist-info/entry_points.txt")]:
        problems.append("wheel has no entry_points.txt (the reposentinel command)")
    if ui:
        problems += [f"wheel: {p}" for p in check_ui(names, index_html, UI_DIR)]
    return problems


def check_sdist(path: Path, *, ui: bool = True) -> list[str]:
    with tarfile.open(path) as sdist:
        members = {m.name: m for m in sdist.getmembers() if m.isfile()}
        # Strip the leading "reposentinel-<version>/" directory.
        names = [name.split("/", 1)[1] for name in members if "/" in name]
        index_member = next(
            (m for name, m in members.items() if name.endswith(f"/src/{UI_DIR}/index.html")), None
        )
        index_file = sdist.extractfile(index_member) if index_member is not None else None
        index_html = index_file.read().decode("utf-8") if index_file is not None else None
    problems = [f"sdist is missing {name}" for name in REQUIRED_IN_SDIST if name not in names]
    problems += [f"sdist contains {name}" for name in _forbidden(names)]
    if ui:
        problems += [f"sdist: {p}" for p in check_ui(names, index_html, f"src/{UI_DIR}")]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check built RepoSentinel packages")
    parser.add_argument("dist", type=Path, help="directory containing the wheel and sdist")
    parser.add_argument(
        "--no-ui", action="store_true", help="do not require the web interface build"
    )
    args = parser.parse_args(argv)
    wheels = sorted(args.dist.glob("reposentinel-*.whl"))
    sdists = sorted(args.dist.glob("reposentinel-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected one wheel and one sdist in {args.dist}", file=sys.stderr)
        return 1
    ui = not args.no_ui
    problems = check_wheel(wheels[0], ui=ui) + check_sdist(sdists[0], ui=ui)
    for problem in problems:
        print(f"problem: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"OK: {wheels[0].name} and {sdists[0].name}" + ("" if ui else " (without the UI)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
