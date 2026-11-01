"""Locate and run external scanners safely.

Running another program is the riskiest thing RepoSentinel does, so this
module is deliberately strict:

* **Executable lookup ignores the current directory.** On Windows,
  ``shutil.which`` searches the current directory *first*. If the user runs
  RepoSentinel from inside a hostile repository, a planted ``gitleaks.exe``
  there would be picked up. ``find_executable`` only searches absolute PATH
  entries and rejects anything inside the scanned repository.
* **No shell, no batch files.** Programs run with an argument list and
  ``shell=False``. On Windows only ``.exe`` files are accepted, because
  ``.bat``/``.cmd`` files are run by ``cmd.exe``, which re-parses arguments
  (a repository path containing ``&`` could then inject a command).
* **Neutral working directory.** The tool runs from a fresh temporary
  directory, never from the scanned repository, so it cannot pick up
  configuration or DLLs planted in that repository via the working directory.
* **Bounded.** Standard input is closed, there is a timeout, and captured
  output is truncated.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from reposentinel.models import CheckError

MAX_CAPTURED_OUTPUT = 64 * 1024  # characters of stdout/stderr kept


class IntegrationError(CheckError):
    """An external tool ran but did not produce a usable result.

    Its message is shown to the user, so it must never include the tool's own
    output (which can quote scanned content).
    """


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stderr: str
    stdout: str = ""


# (argv, working directory, timeout in seconds) -> result. Tests replace this.
Runner = Callable[[list[str], Path, float], ProcessResult]
ExecutableFinder = Callable[[str, Path], Path | None]


def find_executable(name: str, forbidden_root: Path) -> Path | None:
    """Find ``name`` on PATH without searching the current or scanned directory."""
    filename = f"{name}.exe" if sys.platform == "win32" else name
    forbidden = forbidden_root.resolve()
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue  # an empty or relative entry would mean "the current directory"
        directory = Path(os.path.normpath(entry))
        if directory.is_relative_to(forbidden):
            # A PATH folder inside the scanned repository is controlled by that
            # repository, even if it is a link pointing somewhere else.
            continue
        candidate = directory / filename
        try:
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            resolved = candidate.resolve()
            resolved_directory = directory.resolve()
        except OSError:
            continue
        if resolved.is_relative_to(forbidden) or resolved_directory.is_relative_to(forbidden):
            continue  # never run a program that lives inside the scanned repository
        return resolved
    return None


def run_process(argv: list[str], cwd: Path, timeout: float) -> ProcessResult:
    """Run ``argv`` without a shell. Raises subprocess.TimeoutExpired or OSError."""
    completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return ProcessResult(
        completed.returncode, stderr[-MAX_CAPTURED_OUTPUT:], stdout[:MAX_CAPTURED_OUTPUT]
    )
