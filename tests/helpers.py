"""Plain helper functions shared by the tests."""

from __future__ import annotations

import sys
from pathlib import Path

from reposentinel.checks import default_checks
from reposentinel.engine import run_scan
from reposentinel.models import ScanReport
from reposentinel.walker import ScanLimits


def write_files(root: Path, files: dict[str, str | bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    return root


def scan(root: Path, limits: ScanLimits | None = None) -> ScanReport:
    """Run every native check against ``root``."""
    return run_scan(root, default_checks(), limits)


def create_junction(target: Path, link: Path) -> None:
    """Create an NTFS directory junction at ``link`` pointing to ``target`` (Windows only).

    Uses CPython's ``_winapi.CreateJunction`` (also used by CPython's own test
    suite); unlike symbolic links, junctions need no special privilege. The
    ``sys.platform`` check is what lets type checkers on other platforms skip
    this Windows-only API (it is declared only for win32); callers also skip
    their tests elsewhere.
    """
    if sys.platform != "win32":
        raise RuntimeError("directory junctions exist only on Windows")
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def rule_ids(report: ScanReport) -> list[str]:
    return [finding.rule_id for finding in report.findings]
