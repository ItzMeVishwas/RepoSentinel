"""The read-only view of a repository that checks receive.

Checks never open files themselves: they ask the context, which enforces the
size limit, detects binary data, and records anything it could not read as a
coverage issue so the report can say so.

It also refuses to read a file that changed after the file list was built.
After opening, ``fstat`` must show a regular file with the same device and
inode number that was recorded when the file was listed. This catches a file
or a parent directory being replaced by a link to somewhere outside the root
in the meantime, which matters on Windows, where ``O_NOFOLLOW`` does not exist.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path

from reposentinel.models import CoverageIssue, CoverageReason
from reposentinel.walker import FileEntry, Inventory, ScanLimits, decode_text, describe_os_error

# O_NOFOLLOW (POSIX) makes open() fail if the final path component is a
# symbolic link. O_NONBLOCK (POSIX) stops open() from blocking on a FIFO that
# replaced a file. O_BINARY (Windows) disables newline translation.
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


def _same_file(entry: FileEntry, info: os.stat_result) -> bool:
    if not entry.inode or not info.st_ino:
        return True  # this file system does not report identities; cannot compare
    return (entry.device, entry.inode) == (info.st_dev, info.st_ino)


class ScanContext:
    def __init__(self, inventory: Inventory, limits: ScanLimits) -> None:
        self.root: Path = inventory.root
        self.limits = limits
        self.files: tuple[FileEntry, ...] = tuple(inventory.files)
        self._by_path = {entry.path: entry for entry in self.files}
        self._issues: dict[tuple[str, CoverageReason], CoverageIssue] = {}
        for issue in inventory.issues:
            self.record_issue(issue.path, issue.reason, issue.detail)

    def files_matching(self, predicate: Callable[[FileEntry], bool]) -> list[FileEntry]:
        return [entry for entry in self.files if predicate(entry)]

    def get(self, path: str) -> FileEntry | None:
        """Look up an in-scope file by its relative POSIX path."""
        return self._by_path.get(path)

    def read_bytes(self, entry: FileEntry) -> bytes | None:
        try:
            fd = os.open(entry.abs_path, _OPEN_FLAGS)
        except OSError as exc:
            self.record_issue(entry.path, CoverageReason.UNREADABLE, describe_os_error(exc))
            return None
        with os.fdopen(fd, "rb") as handle:  # closes fd on every path below
            try:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode):
                    self.record_issue(
                        entry.path, CoverageReason.UNREADABLE, "not a regular file when opened"
                    )
                    return None
                if not _same_file(entry, info):
                    self.record_issue(
                        entry.path,
                        CoverageReason.UNREADABLE,
                        "file was replaced after it was listed (possible link swap); not read",
                    )
                    return None
                data = handle.read(self.limits.max_file_size + 1)
            except OSError as exc:
                self.record_issue(entry.path, CoverageReason.UNREADABLE, describe_os_error(exc))
                return None
        if len(data) > self.limits.max_file_size:
            # The file grew after it was listed.
            self.record_issue(
                entry.path, CoverageReason.TOO_LARGE, "file grew beyond the size limit"
            )
            return None
        return data

    def read_text(self, entry: FileEntry) -> str | None:
        """Return the decoded text of ``entry``, or None if it cannot be scanned."""
        data = self.read_bytes(entry)
        if data is None:
            return None
        text = decode_text(data)
        if text is None:
            self.record_issue(entry.path, CoverageReason.BINARY, "appears to be binary data")
        return text

    def record_issue(self, path: str, reason: CoverageReason, detail: str = "") -> None:
        """Record a coverage issue once per (path, reason)."""
        self._issues.setdefault((path, reason), CoverageIssue(path, reason, detail))

    def record_issues(self, issues: Iterable[CoverageIssue]) -> None:
        for issue in issues:
            self.record_issue(issue.path, issue.reason, issue.detail)

    @property
    def issues(self) -> tuple[CoverageIssue, ...]:
        return tuple(self._issues[key] for key in sorted(self._issues))
