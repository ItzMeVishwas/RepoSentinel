"""Build the list of files a scan will look at, safely.

Safety rules enforced here (each one is covered by tests):

* Symbolic links and Windows junctions are never followed, so a scan cannot
  escape the selected directory or loop forever. As a second line of
  defence, every directory is resolved and must stay inside the root, and
  it is checked again immediately before it is listed, in case it was
  replaced by a link in the meantime.
* Each file's identity (device and inode number) is recorded so that the
  reader can detect a file that was replaced after listing (see context.py).
* Version-control metadata, virtual environments, dependency folders, build
  output and RepoSentinel's own reports are excluded by default.
* Files larger than a size limit are skipped, and the total number of files
  and the directory depth are capped.
* Nothing is executed. Files are only listed and, later, read as bytes.

Traversal order is deterministic (entries are sorted by name), so the same
repository always produces the same file list.
"""

from __future__ import annotations

import codecs
import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from reposentinel.models import CoverageIssue, CoverageReason

# Directory names that are skipped wherever they appear.
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        # Version control metadata
        ".git",
        ".hg",
        ".svn",
        # Python virtual environments, caches and packaging output
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",
        "site-packages",
        # Third-party dependencies
        "node_modules",
        "bower_components",
        "vendor",
        ".terraform",
        # Build output and generated reports
        "build",
        "dist",
        ".next",
        ".nuxt",
        ".gradle",
        "coverage",
        "htmlcov",
        ".reposentinel",
    }
)

# Directory name patterns skipped wherever they appear.
DEFAULT_EXCLUDED_DIR_PATTERNS: tuple[str, ...] = ("*.egg-info",)

# File name patterns skipped wherever they appear: RepoSentinel's own reports.
# Reports never contain secret values, but re-scanning them would still create
# duplicate findings that point at the report instead of the real file.
DEFAULT_EXCLUDED_FILE_PATTERNS: tuple[str, ...] = ("reposentinel-report*",)

DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_MAX_FILES = 50_000
DEFAULT_MAX_DEPTH = 64

# How many leading bytes are inspected when deciding whether a file is binary.
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_files: int = DEFAULT_MAX_FILES
    max_depth: int = DEFAULT_MAX_DEPTH

    def __post_init__(self) -> None:
        if self.max_file_size < 1 or self.max_files < 1 or self.max_depth < 1:
            raise ValueError("scan limits must be positive")


@dataclass(frozen=True, slots=True)
class FileEntry:
    path: str  # POSIX-style path relative to the root, e.g. "src/app.py"
    abs_path: Path
    size: int
    device: int = 0  # st_dev when listed; 0 if the file system does not report it
    inode: int = 0  # st_ino when listed; 0 if the file system does not report it

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass(slots=True)
class Inventory:
    root: Path
    files: list[FileEntry] = field(default_factory=list)
    issues: list[CoverageIssue] = field(default_factory=list)


def describe_os_error(exc: OSError) -> str:
    """A short, path-free description of an operating-system error."""
    return exc.strerror or type(exc).__name__


def _relative(root: Path, path: Path | str) -> str:
    rel = Path(path).relative_to(root).as_posix()
    return rel or "."


def _is_excluded_dir(name: str, path: str) -> str | None:
    """Return a reason string if the directory should be skipped."""
    if name in DEFAULT_EXCLUDED_DIRS or any(
        fnmatch.fnmatchcase(name, pattern) for pattern in DEFAULT_EXCLUDED_DIR_PATTERNS
    ):
        return "excluded by default"
    if os.path.isfile(os.path.join(path, "pyvenv.cfg")):
        return "Python virtual environment"
    return None


def _is_link(path: Path) -> bool:
    return os.path.islink(path) or os.path.isjunction(path)


def _still_inside(directory: Path, root: Path) -> bool:
    """Re-check a directory just before listing it (it may have been swapped)."""
    try:
        return not _is_link(directory) and directory.resolve().is_relative_to(root)
    except OSError:
        return False


def _is_excluded_file(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in DEFAULT_EXCLUDED_FILE_PATTERNS)


def collect_files(root: Path, limits: ScanLimits | None = None) -> Inventory:
    """List the files under ``root`` that are in scope for scanning.

    ``root`` must be an existing directory; the CLI validates this first.
    Problems with individual paths are recorded as coverage issues instead of
    raising, so one unreadable folder does not stop the whole scan.
    """
    limits = limits or ScanLimits()
    root = root.resolve(strict=True)
    inventory = Inventory(root=root)
    files, issues = inventory.files, inventory.issues

    # Depth-first traversal with an explicit stack (no recursion limit issues).
    # Directories are pushed in reverse order so they are visited A-Z.
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if directory != root and not _still_inside(directory, root):
            issues.append(
                CoverageIssue(
                    _relative(root, directory),
                    CoverageReason.SYMLINK,
                    "became a link or moved outside the root after it was listed; not followed",
                )
            )
            continue
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            issues.append(
                CoverageIssue(
                    _relative(root, directory), CoverageReason.UNREADABLE, describe_os_error(exc)
                )
            )
            continue

        subdirectories: list[Path] = []
        for entry in entries:
            rel = _relative(root, entry.path)
            try:
                if entry.is_symlink() or entry.is_junction():
                    issues.append(
                        CoverageIssue(rel, CoverageReason.SYMLINK, "links are never followed")
                    )
                    continue

                if entry.is_dir(follow_symlinks=False):
                    reason = _is_excluded_dir(entry.name, entry.path)
                    if reason:
                        issues.append(CoverageIssue(rel, CoverageReason.EXCLUDED, reason))
                        continue
                    # Defence in depth against other reparse points or mounts.
                    if not Path(entry.path).resolve().is_relative_to(root):
                        issues.append(
                            CoverageIssue(
                                rel, CoverageReason.SYMLINK, "resolves outside the scanned root"
                            )
                        )
                        continue
                    if depth + 1 > limits.max_depth:
                        issues.append(
                            CoverageIssue(
                                rel,
                                CoverageReason.LIMIT_REACHED,
                                f"deeper than the depth limit ({limits.max_depth})",
                            )
                        )
                        continue
                    subdirectories.append(Path(entry.path))
                    continue

                if not entry.is_file(follow_symlinks=False):
                    issues.append(CoverageIssue(rel, CoverageReason.EXCLUDED, "not a regular file"))
                    continue

                if _is_excluded_file(entry.name):
                    issues.append(
                        CoverageIssue(rel, CoverageReason.EXCLUDED, "RepoSentinel report file")
                    )
                    continue

                # os.lstat, not entry.stat: on Windows DirEntry.stat() reports
                # zero for st_dev and st_ino, which the reader needs.
                info = os.lstat(entry.path)
                if not stat.S_ISREG(info.st_mode):
                    issues.append(CoverageIssue(rel, CoverageReason.EXCLUDED, "not a regular file"))
                    continue
                size = info.st_size
                if size > limits.max_file_size:
                    issues.append(
                        CoverageIssue(
                            rel,
                            CoverageReason.TOO_LARGE,
                            f"{size} bytes exceeds the {limits.max_file_size}-byte limit",
                        )
                    )
                    continue

                if len(files) >= limits.max_files:
                    issues.append(
                        CoverageIssue(
                            rel,
                            CoverageReason.LIMIT_REACHED,
                            f"file limit ({limits.max_files}) reached; traversal stopped here",
                        )
                    )
                    stack.clear()
                    subdirectories.clear()
                    break

                files.append(
                    FileEntry(
                        path=rel,
                        abs_path=Path(entry.path),
                        size=size,
                        device=info.st_dev,
                        inode=info.st_ino,
                    )
                )
            except OSError as exc:
                issues.append(CoverageIssue(rel, CoverageReason.UNREADABLE, describe_os_error(exc)))

        stack.extend((subdir, depth + 1) for subdir in reversed(subdirectories))

    files.sort(key=lambda entry: entry.path)
    issues.sort(key=lambda issue: (issue.path, issue.reason))
    return inventory


def decode_text(data: bytes) -> str | None:
    """Decode file contents for pattern matching, or return None for binary data.

    UTF-8 is assumed (invalid bytes are replaced, not fatal). Files with a
    UTF-16 byte-order mark are decoded as UTF-16; this matters on Windows,
    where some tools write UTF-16 text by default. Anything else containing a
    NUL byte near the start is treated as binary.
    """
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8) :].decode("utf-8", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")
