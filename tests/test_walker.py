"""File inventory: exclusions, limits, links, unreadable paths and decoding."""

from __future__ import annotations

import codecs
import os
import shutil
import sys
from pathlib import Path

import pytest

from reposentinel.context import ScanContext
from reposentinel.models import CoverageReason
from reposentinel.walker import ScanLimits, collect_files, decode_text
from tests.conftest import RepoFactory
from tests.helpers import write_files


def paths(root: Path, limits: ScanLimits | None = None) -> list[str]:
    return [entry.path for entry in collect_files(root, limits).files]


def issues_by_reason(root: Path, reason: CoverageReason, limits: ScanLimits | None = None):
    return [i for i in collect_files(root, limits).issues if i.reason is reason]


def test_lists_files_in_sorted_posix_order(make_repo: RepoFactory) -> None:
    root = make_repo({"b.txt": "", "a/z.txt": "", "a/b/c.txt": "", "A.txt": ""})
    assert paths(root) == ["A.txt", "a/b/c.txt", "a/z.txt", "b.txt"]


def test_empty_directory_has_no_files(tmp_path: Path) -> None:
    inventory = collect_files(tmp_path)
    assert inventory.files == []
    assert inventory.issues == []


@pytest.mark.parametrize(
    "directory",
    [".git", ".venv", "node_modules", "__pycache__", "build", "dist", "pkg.egg-info", "vendor"],
)
def test_default_excluded_directories_are_not_traversed(
    make_repo: RepoFactory, directory: str
) -> None:
    root = make_repo({f"{directory}/inner/file.txt": "x", "kept.txt": "x"})
    assert paths(root) == ["kept.txt"]
    excluded = issues_by_reason(root, CoverageReason.EXCLUDED)
    assert [issue.path for issue in excluded] == [directory]


def test_excluded_directory_names_apply_at_any_depth(make_repo: RepoFactory) -> None:
    root = make_repo({"packages/web/node_modules/lib/index.js": "x", "packages/web/app.js": "x"})
    assert paths(root) == ["packages/web/app.js"]


def test_virtual_environment_detected_by_pyvenv_cfg(make_repo: RepoFactory) -> None:
    root = make_repo({"my-env/pyvenv.cfg": "home = x", "my-env/lib/site.py": "x", "main.py": ""})
    assert paths(root) == ["main.py"]
    (issue,) = issues_by_reason(root, CoverageReason.EXCLUDED)
    assert issue.detail == "Python virtual environment"


def test_reposentinel_reports_are_excluded(make_repo: RepoFactory) -> None:
    root = make_repo({"reposentinel-report.json": "{}", "reposentinel-report-ci.html": "<p>"})
    assert paths(root) == []


def test_files_over_size_limit_are_skipped(make_repo: RepoFactory) -> None:
    root = make_repo({"big.txt": "x" * 2048, "small.txt": "x"})
    limits = ScanLimits(max_file_size=1024)
    assert paths(root, limits) == ["small.txt"]
    (issue,) = issues_by_reason(root, CoverageReason.TOO_LARGE, limits)
    assert issue.path == "big.txt"
    assert not issue.reason.is_error  # a policy skip, not a failure


def test_file_limit_stops_traversal_and_is_an_error(make_repo: RepoFactory) -> None:
    root = make_repo({f"f{i}.txt": "" for i in range(5)})
    limits = ScanLimits(max_files=3)
    assert paths(root, limits) == ["f0.txt", "f1.txt", "f2.txt"]
    (issue,) = issues_by_reason(root, CoverageReason.LIMIT_REACHED, limits)
    assert issue.reason.is_error


def test_depth_limit(make_repo: RepoFactory) -> None:
    root = make_repo({"a/b/c/deep.txt": "", "a/shallow.txt": ""})
    limits = ScanLimits(max_depth=2)
    assert paths(root, limits) == ["a/shallow.txt"]
    (issue,) = issues_by_reason(root, CoverageReason.LIMIT_REACHED, limits)
    assert issue.path == "a/b/c"


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        ScanLimits(max_files=0)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")
def test_junction_pointing_outside_root_is_not_followed(tmp_path: Path) -> None:
    import _winapi  # CPython's own helper, used by its test suite to create junctions

    outside = write_files(tmp_path / "outside", {"secret.txt": "outside the repository"})
    root = write_files(tmp_path / "repo", {"inside.txt": "x"})
    _winapi.CreateJunction(str(outside), str(root / "link"))

    assert paths(root) == ["inside.txt"]
    (issue,) = issues_by_reason(root, CoverageReason.SYMLINK)
    assert issue.path == "link"


# CI sets this on Linux, where creating symbolic links needs no privilege, so the
# symbolic-link tests must run there: a failure to create a link fails the test
# instead of silently skipping it.
REQUIRE_SYMLINKS = os.environ.get("REPOSENTINEL_REQUIRE_SYMLINK_TESTS") == "1"


def _try_symlink(target: Path, link: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:  # Windows needs a privilege for this
        if REQUIRE_SYMLINKS:
            pytest.fail(f"REPOSENTINEL_REQUIRE_SYMLINK_TESTS=1 but a link could not be made: {exc}")
        pytest.skip(f"cannot create symbolic links here: {exc}")


def test_file_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = write_files(tmp_path / "outside", {"secret.txt": "x"})
    root = write_files(tmp_path / "repo", {"inside.txt": "x"})
    _try_symlink(outside / "secret.txt", root / "link.txt", directory=False)
    assert paths(root) == ["inside.txt"]
    assert [i.path for i in issues_by_reason(root, CoverageReason.SYMLINK)] == ["link.txt"]


def test_directory_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = write_files(tmp_path / "outside", {"secret.txt": "x"})
    root = write_files(tmp_path / "repo", {"inside.txt": "x"})
    _try_symlink(outside, root / "linkdir", directory=True)
    assert paths(root) == ["inside.txt"]
    assert [i.path for i in issues_by_reason(root, CoverageReason.SYMLINK)] == ["linkdir"]


def test_unreadable_directory_is_recorded_and_scan_continues(
    make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_repo({"locked/a.txt": "", "open/b.txt": ""})
    real_scandir = os.scandir
    locked = str(root / "locked")

    def fake_scandir(path):
        if os.fspath(path) == locked:
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    inventory = collect_files(root)
    assert [entry.path for entry in inventory.files] == ["open/b.txt"]
    (issue,) = [i for i in inventory.issues if i.reason is CoverageReason.UNREADABLE]
    assert (issue.path, issue.detail) == ("locked", "Permission denied")
    assert issue.reason.is_error


# --- reading and decoding ---------------------------------------------------


def context_for(root: Path, limits: ScanLimits | None = None) -> ScanContext:
    limits = limits or ScanLimits()
    return ScanContext(collect_files(root, limits), limits)


def test_binary_file_is_skipped_with_a_coverage_note(make_repo: RepoFactory) -> None:
    context = context_for(make_repo({"image.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00"}))
    (entry,) = context.files
    assert context.read_text(entry) is None
    assert [(i.path, i.reason) for i in context.issues] == [("image.png", CoverageReason.BINARY)]


def test_unreadable_file_is_recorded(
    make_repo: RepoFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = context_for(make_repo({"a.txt": "x"}))
    (entry,) = context.files

    def deny(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "open", deny)
    assert context.read_text(entry) is None
    (issue,) = context.issues
    assert (issue.reason, issue.detail) == (CoverageReason.UNREADABLE, "Permission denied")


def test_file_that_grew_after_listing_is_not_read(make_repo: RepoFactory) -> None:
    root = make_repo({"log.txt": "short"})
    context = context_for(root, ScanLimits(max_file_size=10))
    (root / "log.txt").write_text("x" * 100, encoding="utf-8")
    assert context.read_text(context.files[0]) is None
    assert context.issues[0].reason is CoverageReason.TOO_LARGE


def test_issues_are_recorded_once_per_path_and_reason(make_repo: RepoFactory) -> None:
    context = context_for(make_repo({"blob.bin": b"\x00\x01"}))
    context.read_text(context.files[0])
    context.read_text(context.files[0])
    assert len(context.issues) == 1


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"plain text", "plain text"),
        (codecs.BOM_UTF8 + b"with bom", "with bom"),
        ("utf-16 text".encode("utf-16"), "utf-16 text"),  # includes a byte-order mark
        (b"caf" + bytes([0xE9]) + b" latin-1", "caf" + chr(0xFFFD) + " latin-1"),  # replaced
        (b"binary\x00data", None),
    ],
)
def test_decode_text(data: bytes, expected: str | None) -> None:
    assert decode_text(data) == expected


# --- regressions found in the October 2026 security audit --------------------


def make_directory_link(target: Path, link: Path) -> None:
    """A junction on Windows (no privilege needed), a symbolic link elsewhere."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        _try_symlink(target, link, directory=True)


def test_directory_swapped_for_link_after_listing_is_not_read(tmp_path: Path) -> None:
    # The file list is built, then "sub" is replaced by a link to a folder
    # outside the root that holds a file with the same name. Reading must
    # detect that it is no longer the file that was listed.
    root = write_files(tmp_path / "repo", {"sub/a.txt": "harmless"})
    outside = write_files(tmp_path / "outside", {"a.txt": "outside the root"})
    context = context_for(root)
    shutil.rmtree(root / "sub")
    make_directory_link(outside, root / "sub")

    assert context.read_text(context.files[0]) is None
    (issue,) = context.issues
    assert issue.reason is CoverageReason.UNREADABLE
    assert "replaced after it was listed" in issue.detail
    assert issue.reason.is_error  # the scan is reported as incomplete


def test_file_replaced_after_listing_is_not_read(make_repo: RepoFactory) -> None:
    root = make_repo({"a.txt": "original"})
    context = context_for(root)
    replacement = root / "new.tmp"
    replacement.write_text("different file", encoding="utf-8")
    os.replace(replacement, root / "a.txt")  # same name, different file
    assert context.read_text(context.files[0]) is None
    assert "replaced after it was listed" in context.issues[0].detail


def test_unchanged_file_is_read_normally(make_repo: RepoFactory) -> None:
    context = context_for(make_repo({"a.txt": "hello"}))
    assert context.read_text(context.files[0]) == "hello"
    if sys.platform in ("win32", "linux"):
        assert context.files[0].inode != 0  # identities are recorded on these platforms


def test_directory_swapped_before_it_is_listed_is_not_traversed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "a_first" is listed before "sub". While "a_first" is being listed, "sub"
    # is replaced by a link to outside the root; the walker must notice when it
    # reaches "sub" instead of listing the outside folder.
    root = write_files(tmp_path / "repo", {"a_first/x.txt": "", "sub/inside.txt": ""})
    outside = write_files(tmp_path / "outside", {"outside.txt": "outside the root"})
    real_scandir = os.scandir
    swapped = False

    def swapping_scandir(path):
        nonlocal swapped
        if not swapped and Path(path).name == "a_first":
            swapped = True
            shutil.rmtree(root / "sub")
            make_directory_link(outside, root / "sub")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", swapping_scandir)
    inventory = collect_files(root)
    assert [entry.path for entry in inventory.files] == ["a_first/x.txt"]
    (issue,) = [i for i in inventory.issues if i.path == "sub"]
    assert issue.reason is CoverageReason.SYMLINK
    assert "after it was listed" in issue.detail
