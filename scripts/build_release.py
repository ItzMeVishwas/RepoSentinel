"""Build release archives in the right order, then check them.

1. Install the frontend's exact dependencies from frontend/package-lock.json
   (npm ci, with install scripts disabled).
2. Build the web interface into src/reposentinel/webui/static/.
3. Build the sdist and wheel with `python -m build` (the sdist carries the
   built interface, and the wheel is built from the sdist).
4. Check the archives: `twine check --strict` and scripts/check_dist.py.

Requirements: Node.js 22.12 or newer with npm, and the release tools
(`pip install -e ".[release]"`). Network access is needed for npm ci and for
the build backend, unless they are already in local caches (`--offline` uses
only npm's cache).

Usage:
    python scripts/build_release.py [--outdir dist] [--offline]

The output folder must be new or empty; nothing is deleted.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT / "frontend"
STATIC = PROJECT / "src" / "reposentinel" / "webui" / "static"


def run(argv: list[str], cwd: Path) -> None:
    print(f"$ {' '.join(argv)}", flush=True)
    subprocess.run(argv, cwd=cwd, check=True)  # noqa: S603 - fixed arguments, no shell


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outdir", type=Path, default=PROJECT / "dist")
    parser.add_argument("--offline", action="store_true", help="npm ci from the local cache only")
    args = parser.parse_args(argv)
    outdir = args.outdir.resolve()
    if outdir.exists() and any(outdir.iterdir()):
        print(f"error: {outdir} is not empty; choose a new --outdir", file=sys.stderr)
        return 2
    npm = shutil.which("npm")
    if npm is None:
        print("error: npm was not found; install Node.js 22.12 or newer", file=sys.stderr)
        return 2
    if not all(importlib.util.find_spec(name) for name in ("build", "twine")):
        print('error: install the release tools: pip install -e ".[release]"', file=sys.stderr)
        return 2

    ci = [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
    run([*ci, "--offline"] if args.offline else ci, FRONTEND)
    run([npm, "run", "build"], FRONTEND)
    if not (STATIC / "index.html").is_file():
        print(f"error: the UI build did not produce {STATIC / 'index.html'}", file=sys.stderr)
        return 1
    run([sys.executable, "-m", "build", "--outdir", str(outdir)], PROJECT)
    archives = [str(path) for path in sorted(outdir.glob("reposentinel-*"))]
    run([sys.executable, "-m", "twine", "check", "--strict", *archives], PROJECT)
    run([sys.executable, str(PROJECT / "scripts" / "check_dist.py"), str(outdir)], PROJECT)
    print(f"Release archives in {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
