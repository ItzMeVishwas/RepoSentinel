"""Run the test suite several times and keep the full record of every failure.

Used to investigate intermittent failures: each run writes JUnit XML and the
complete pytest output, so a failure that happens once is never lost.

Usage:
    python scripts/repeat_tests.py --runs 10 --out DIR [-- extra pytest args]

Prints one line per run and, at the end, every failing test with its message.
Exits 1 if any run failed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def failures(junit: Path) -> list[tuple[str, str]]:
    tree = ET.parse(junit)  # noqa: S314 - file written by pytest in this run
    found = []
    for case in tree.iter("testcase"):
        for problem in [*case.iter("failure"), *case.iter("error")]:
            name = f"{case.get('classname')}::{case.get('name')}"
            found.append((name, (problem.get("message") or "")[:300]))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    shell = os.environ.get("MSYSTEM") or ("powershell" if "PSModulePath" in os.environ else "?")
    all_failures: list[tuple[int, str, str]] = []
    for run in range(1, args.runs + 1):
        junit = args.out / f"run-{run}.xml"
        log = args.out / f"run-{run}.log"
        completed = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={junit}",
                *args.pytest_args,
            ],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        summary = (completed.stdout.strip().splitlines() or ["(no output)"])[-1]
        print(f"run {run} [{shell}]: exit {completed.returncode}: {summary}", flush=True)
        all_failures += [(run, name, message) for name, message in failures(junit)]
    for run, name, message in all_failures:
        print(f"FAILED in run {run}: {name}\n    {message}")
    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
