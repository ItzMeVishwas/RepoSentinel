"""Shared fixtures. All repositories are built in pytest temporary directories."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from tests.helpers import write_files

RepoFactory = Callable[[dict[str, str | bytes]], Path]


@pytest.fixture
def make_repo(tmp_path: Path) -> RepoFactory:
    """Create a repository under tmp_path from a {relative path: content} mapping."""

    def factory(files: dict[str, str | bytes]) -> Path:
        return write_files(tmp_path / "repo", files)

    return factory
