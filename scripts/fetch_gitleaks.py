"""Download one pinned Gitleaks release for testing, and check it before use.

RepoSentinel itself never downloads tools. This development script exists so
that the integration can be tested against a real Gitleaks binary, in CI and
on a developer's computer, without trusting whatever happens to be on PATH:

* the release, the file name and its SHA-256 are pinned below (the hashes
  were checked against both the release's ``gitleaks_<version>_checksums.txt``
  and GitHub's asset digests on 2026-11-03);
* the archive is downloaded over HTTPS from the official release page only,
  and refused if its SHA-256 differs;
* it is extracted into a new, empty folder, refusing any archive member whose
  path would land outside that folder.

Usage:

    python scripts/fetch_gitleaks.py DEST_FOLDER

DEST_FOLDER must not exist yet or be empty, and must be outside any folder
you will scan. Afterwards it contains ``gitleaks`` (``gitleaks.exe`` on
Windows). Run the real-binary tests with:

    REPOSENTINEL_GITLEAKS_DIR=DEST_FOLDER python -m pytest tests/test_gitleaks_real.py

Exit code 0 on success; 1 if the download, the checksum or the extraction fails.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import platform
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "8.30.1"
BASE_URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
# (operating system, machine) -> (archive name, SHA-256)
ARCHIVES = {
    ("windows", "x64"): (
        f"gitleaks_{VERSION}_windows_x64.zip",
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    ),
    ("linux", "x64"): (
        f"gitleaks_{VERSION}_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    ("darwin", "arm64"): (
        f"gitleaks_{VERSION}_darwin_arm64.tar.gz",
        "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    ),
    ("darwin", "x64"): (
        f"gitleaks_{VERSION}_darwin_x64.tar.gz",
        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    ),
}
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 120


def current_platform() -> tuple[str, str]:
    system = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform, "")
    machine = platform.machine().lower()
    machine = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}.get(machine, machine)
    return system, machine


def download(url: str) -> bytes:
    if not url.startswith("https://github.com/"):
        raise ValueError(f"refusing to download from {url}")
    with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https URL
        data: bytes = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("the archive is larger than expected")
    return data


def _inside(dest: Path, name: str) -> Path:
    target = (dest / name).resolve()
    if not target.is_relative_to(dest):
        raise ValueError(f"archive member {name!r} would be written outside {dest}")
    return target


def extract_executable(data: bytes, archive_name: str, dest: Path) -> Path:
    """Write only the gitleaks executable from the archive into ``dest``."""
    executable = "gitleaks.exe" if archive_name.endswith(".zip") else "gitleaks"
    target = _inside(dest, executable)
    if archive_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            target.write_bytes(archive.read(executable))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(executable)
            if not member.isfile():
                raise ValueError("the gitleaks entry in the archive is not a regular file")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("the gitleaks entry in the archive cannot be read")
            target.write_bytes(source.read())
        target.chmod(0o755)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dest", type=Path, help="new or empty folder for the executable")
    args = parser.parse_args(argv)
    key = current_platform()
    if key not in ARCHIVES:
        print(f"no pinned Gitleaks {VERSION} archive for {key[0]} {key[1]}", file=sys.stderr)
        return 1
    archive_name, expected = ARCHIVES[key]
    dest: Path = args.dest
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        print(f"{dest} must be a new or empty folder", file=sys.stderr)
        return 1
    try:
        data = download(BASE_URL + archive_name)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            print(f"SHA-256 mismatch for {archive_name}: got {actual}", file=sys.stderr)
            return 1
        dest.mkdir(parents=True, exist_ok=True)
        path = extract_executable(data, archive_name, dest.resolve())
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"could not get Gitleaks {VERSION}: {exc}", file=sys.stderr)
        return 1
    print(f"Gitleaks {VERSION} ({archive_name}, SHA-256 verified) -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
