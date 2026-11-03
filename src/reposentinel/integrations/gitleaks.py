"""Optional Gitleaks integration: ``--integration gitleaks``.

Tested with Gitleaks 8.30.1 on Windows, Linux and macOS
(``tests/test_gitleaks_real.py``, run in CI against official, checksum-verified
releases). Releases from 8.19.0 on are accepted; other releases are untested.

Gitleaks (MIT licence, https://github.com/gitleaks/gitleaks) has far broader
secret coverage than RepoSentinel's five native patterns. RepoSentinel never
downloads or installs it: if ``gitleaks`` is not on PATH the check is
*skipped*, and the scan is reported as incomplete because the user asked for
a check that did not run.

How Gitleaks is invoked, and why (flags verified against Gitleaks' source,
``cmd/root.go``, ``cmd/directory.go`` and ``cmd/version.go`` at v8.19.0 and
on ``master``, but NOT yet against a running binary; see docs/integrations.md):

* ``gitleaks version`` runs first. Releases older than 8.19.0 (which lack the
  ``dir`` command) make the check *skipped* with an upgrade message. A version
  that cannot be read (source builds print a placeholder) is reported as
  "version unknown" and the scan still runs.
* ``dir`` mode scans files only. ``git`` mode would run ``git log -p`` in the
  target repository, and repository Git configuration can make Git execute
  commands (for example diff text-conversion drivers).
* ``--config`` points at a temporary file that extends Gitleaks' built-in
  rules. Without it, Gitleaks would load ``.gitleaks.toml`` from the scanned
  repository, which could disable rules or allow-list everything.
* ``--ignore-gitleaks-allow`` stops ``gitleaks:allow`` comments in the
  scanned code from hiding results. (``.gitleaksignore`` files in the scanned
  repository are still honoured; Gitleaks has no option to disable them.)
* ``--redact=100`` keeps secret values out of Gitleaks' output, and
  RepoSentinel additionally never copies the ``Secret`` or ``Match`` fields.
* ``--exit-code 42`` separates "leaks found" (42) from "error" (1); by
  default Gitleaks uses 1 for both.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from reposentinel.checks.base import Check, CheckOutput, CheckSkipped
from reposentinel.context import ScanContext
from reposentinel.engine import describe_exception
from reposentinel.integrations.process import (
    ExecutableFinder,
    IntegrationError,
    Runner,
    find_executable,
    run_process,
)
from reposentinel.models import Confidence, Finding, Rule, Severity

MINIMUM_VERSION = (8, 19, 0)  # first release with the `dir` command
VERSION_TIMEOUT_SECONDS = 30.0
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
LEAKS_EXIT_CODE = 42
UNKNOWN_FLAG_EXIT_CODE = 126
DEFAULT_TIMEOUT_SECONDS = 600.0
MAX_REPORT_BYTES = 50 * 1024 * 1024

CONFIG_EXTENDING_DEFAULTS = "[extend]\nuseDefault = true\n"

REMEDIATION = (
    "Confirm whether the value is a real credential. If it is, revoke or rotate it, remove it "
    "from the code and from Git history, and load it at runtime from a secret store or CI "
    "secret instead."
)


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Find a version such as "8.28.0" or "v8.28.0" in ``gitleaks version`` output.

    Builds from source print a placeholder instead of a number; that returns None.
    """
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def build_command(
    executable: Path, root: Path, report_path: Path, config_path: Path, max_file_size: int
) -> list[str]:
    """The exact Gitleaks command line. ``root`` is absolute, so it cannot start with '-'."""
    max_megabytes = max(1, math.ceil(max_file_size / (1024 * 1024)))
    return [
        str(executable),
        "dir",
        str(root),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--config",
        str(config_path),
        "--redact=100",
        "--exit-code",
        str(LEAKS_EXIT_CODE),
        "--ignore-gitleaks-allow",
        "--max-target-megabytes",
        str(max_megabytes),
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
    ]


def load_report(path: Path) -> list[Any]:
    """Read Gitleaks' JSON report defensively."""
    if not path.is_file():
        raise IntegrationError("gitleaks finished but did not write a report")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise IntegrationError("gitleaks report is larger than RepoSentinel's 50 MiB limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("gitleaks report is not valid JSON") from None
    if data is None:  # Go encodes an empty (nil) list as null
        return []
    if not isinstance(data, list):
        raise IntegrationError("gitleaks report has an unexpected structure (expected a list)")
    return data


def relative_path(reported: str, root: Path) -> str | None:
    """Convert a path reported by Gitleaks to RepoSentinel's relative POSIX form."""
    path = Path(reported)
    if not path.is_absolute():
        path = root / path
    try:
        relative = Path(os.path.normpath(path)).relative_to(root)
    except ValueError:
        return None
    text = relative.as_posix()
    return None if text in ("", ".") or text.startswith("../") else text


def convert_results(entries: list[Any], context: ScanContext) -> tuple[list[Finding], int]:
    """Turn Gitleaks results into findings. Returns (findings, results outside scope).

    Only ``RuleID``, ``Description``, ``File`` and ``StartLine`` are read.
    ``Secret`` and ``Match`` are never touched, even though they are redacted.
    """
    findings: list[Finding] = []
    outside_scope = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrationError("gitleaks report contains an entry that is not an object")
        rule = entry.get("RuleID")
        reported_file = entry.get("File")
        if not isinstance(rule, str) or not rule or not isinstance(reported_file, str):
            raise IntegrationError("gitleaks report entry is missing RuleID or File")
        path = relative_path(reported_file, context.root)
        if path is None or context.get(path) is None:
            outside_scope += 1  # e.g. inside .git/ or node_modules/, which RepoSentinel excludes
            continue
        line = entry.get("StartLine")
        description = entry.get("Description")
        findings.append(
            Finding(
                rule_id=f"gitleaks:{rule}",
                title=f"Gitleaks: {description if isinstance(description, str) else rule}",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                summary=f"Gitleaks rule '{rule}' matched a possible secret.",
                evidence=f"gitleaks rule {rule} (value redacted)",
                remediation=REMEDIATION,
                check_id=GitleaksCheck.id,
                path=path,
                line=line
                if isinstance(line, int) and not isinstance(line, bool) and line >= 1
                else None,
            )
        )
    return findings, outside_scope


class GitleaksCheck(Check):
    id = "gitleaks"
    name = "Gitleaks secret scan"
    description = "Runs a locally installed Gitleaks in directory mode and imports its results."
    rules: ClassVar[tuple[Rule, ...]] = ()  # IDs come from Gitleaks: "gitleaks:<RuleID>"

    def __init__(
        self,
        *,
        finder: ExecutableFinder = find_executable,
        runner: Runner = run_process,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._finder = finder
        self._runner = runner
        self._timeout = timeout

    def run(self, context: ScanContext) -> CheckOutput:
        executable = self._finder("gitleaks", context.root)
        if executable is None:
            raise CheckSkipped(
                "gitleaks was not found on PATH (a copy inside the scanned folder is never "
                "run, and RepoSentinel never downloads tools). Install it from "
                "https://github.com/gitleaks/gitleaks/releases or a package manager, or "
                "run without --integration gitleaks."
            )
        with tempfile.TemporaryDirectory(prefix="reposentinel-gitleaks-") as temporary:
            workdir = Path(temporary)
            version = self._installed_version(executable, workdir)
            if version is not None and version < MINIMUM_VERSION:
                raise CheckSkipped(
                    f"gitleaks {_format_version(version)} is too old: RepoSentinel needs "
                    f"Gitleaks {_format_version(MINIMUM_VERSION)} or newer (the 'dir' command). "
                    "Upgrade it, or run without --integration gitleaks."
                )
            config_path = workdir / "gitleaks.toml"
            config_path.write_text(CONFIG_EXTENDING_DEFAULTS, encoding="utf-8")
            report_path = workdir / "gitleaks-report.json"
            argv = build_command(
                executable, context.root, report_path, config_path, context.limits.max_file_size
            )
            try:
                result = self._runner(argv, workdir, self._timeout)
            except subprocess.TimeoutExpired:
                raise IntegrationError(
                    f"gitleaks did not finish within {self._timeout:.0f} seconds"
                ) from None
            except OSError as exc:
                raise IntegrationError(
                    f"could not start gitleaks: {exc.strerror or describe_exception(exc)}"
                ) from None

            if result.returncode == UNKNOWN_FLAG_EXIT_CODE:
                raise IntegrationError(
                    "gitleaks rejected a command-line option; Gitleaks 8.19 or newer "
                    "(with the 'dir' command) is required"
                )
            if result.returncode not in (0, LEAKS_EXIT_CODE):
                # Gitleaks' own error output is not shown: it can quote scanned
                # content, which redaction cannot always recognise.
                output = "it wrote error output" if result.stderr.strip() else "no error output"
                raise IntegrationError(
                    f"gitleaks exited with code {result.returncode} ({output}, not shown "
                    "because it may quote repository content; run gitleaks directly to see it)"
                )
            entries = load_report(report_path)

        findings, outside_scope = convert_results(entries, context)
        if result.returncode == 0 and entries:
            raise IntegrationError("gitleaks reported no leaks but its report lists results")
        label = f"Gitleaks {_format_version(version)}" if version else "Gitleaks (version unknown)"
        message = f"{label}: {len(findings)} result(s) imported"
        if outside_scope:
            message += f"; {outside_scope} outside RepoSentinel's scan scope were ignored"
        return CheckOutput(findings=findings, examined=None, message=message)

    def _installed_version(self, executable: Path, workdir: Path) -> tuple[int, int, int] | None:
        """Ask Gitleaks for its version; None if it cannot be determined."""
        try:
            result = self._runner([str(executable), "version"], workdir, VERSION_TIMEOUT_SECONDS)
        except (subprocess.TimeoutExpired, OSError):
            return None  # the scan itself will report a clear error if the tool is broken
        if result.returncode != 0:
            return None
        return parse_version(result.stdout)
