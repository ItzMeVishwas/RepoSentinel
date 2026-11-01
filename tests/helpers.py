"""Plain helper functions shared by the tests."""

from __future__ import annotations

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


def rule_ids(report: ScanReport) -> list[str]:
    return [finding.rule_id for finding in report.findings]
