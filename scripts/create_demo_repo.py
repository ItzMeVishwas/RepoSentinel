"""Create a small synthetic repository that triggers every RepoSentinel rule.

Every credential written is fake (see ``reposentinel.demo``). The same
repository is available from the installed command line as
``reposentinel demo FOLDER``.

Usage:
    python scripts/create_demo_repo.py <new-or-empty-directory>
"""

from __future__ import annotations

import argparse
from pathlib import Path

from reposentinel.demo import build_files, create_demo_repo

__all__ = ["build_files", "create_demo_repo", "main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", type=Path, help="new or empty directory to create")
    args = parser.parse_args(argv)
    try:
        written = create_demo_repo(args.directory)
    except FileExistsError as exc:
        parser.error(str(exc))
    print(f"Created {len(written)} synthetic files in {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
