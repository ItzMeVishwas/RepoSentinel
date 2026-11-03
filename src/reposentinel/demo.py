"""A synthetic demo repository that triggers every native RepoSentinel rule.

Every credential-shaped value here is fake and assembled at run time from
harmless pieces, so this source file contains nothing that looks like a
secret (and scanning RepoSentinel itself stays clean). The generated README
says that the repository is synthetic.

Used by ``reposentinel demo FOLDER``, by the web interface's "Create a
synthetic demo project" button, and by the tests and scripts.
"""

from __future__ import annotations

import string
from pathlib import Path

DEMO_NOTICE = (
    "# Synthetic RepoSentinel demo\n\n"
    "This folder was created by RepoSentinel to demonstrate its checks. Every credential in it "
    "is FAKE and deliberately shaped to be detected. Do not use it, publish it, or copy it into "
    "a real project. You can delete this folder at any time.\n"
)

FAKE_GITHUB_TOKEN = "ghp_" + string.digits + string.ascii_lowercase  # 36 characters
FAKE_AWS_KEY_ID = "AKIA" + "FAKEDEMOKEY12345"
FAKE_AWS_SECRET = ("fakeDemoSecret" * 3)[:40]
FAKE_DB_PASSWORD = "not-a-real-pass"  # noqa: S105 - synthetic demo value
PEM_KIND = "RSA PRIVATE KEY"

TRIAGE_WORKFLOW = """\
name: Triage issues
on:
  issues:
    types: [opened]
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Label the issue
        uses: some-org/issue-labeler@v2
      - name: Echo the title
        run: |
          echo "New issue received"
          echo "${{ github.event.issue.title }}"
      - name: Safe pattern (not reported)
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"""

PR_TARGET_WORKFLOW = """\
name: Preview build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make preview
"""


def build_files() -> dict[str, str]:
    """Relative path -> file content for the demo repository."""
    pem = (
        f"-----BEGIN {PEM_KIND}-----\n"
        "THIS-IS-NOT-A-REAL-KEY-IT-IS-SYNTHETIC-DEMO-DATA\n"
        f"-----END {PEM_KIND}-----\n"
    )
    return {
        "README.md": DEMO_NOTICE,
        ".gitignore": "__pycache__/\n*.log\n",
        ".env": f"DATABASE_URL=postgres://demo_user:{FAKE_DB_PASSWORD}@db.internal.test:5432/app\n",
        ".env.example": "DATABASE_URL=postgres://user:password@localhost:5432/app\n",
        "app/settings.py": (
            '"""Application settings (synthetic demo values)."""\n\n'
            f'GITHUB_TOKEN = "{FAKE_GITHUB_TOKEN}"\n'
            f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY_ID}"\n'
            f'aws_secret_access_key = "{FAKE_AWS_SECRET}"\n'
        ),
        "deploy/id_rsa": pem,
        "deploy/.git-credentials": f"https://demo:{FAKE_GITHUB_TOKEN}@github.com\n",
        ".github/workflows/triage.yml": TRIAGE_WORKFLOW,
        ".github/workflows/preview.yml": PR_TARGET_WORKFLOW,
    }


def create_demo_repo(target: Path) -> list[Path]:
    """Write the demo files under ``target`` (which must be new or empty).

    ``target`` may be a folder that someone else can also write to, who could
    plant a link there while the demo is being written (for example a junction
    or symbolic link named ``app`` that points to another folder). So every
    folder below ``target`` is created here, and every file is created with
    exclusive creation (``O_CREAT | O_EXCL``), which never opens an existing
    file or link: if a file, folder or link already exists at the path of a
    folder or file the demo is about to create, the demo stops. It therefore
    never overwrites or truncates an existing file.

    Still possible, and not detected: someone who can write to ``target``
    replaces a folder created here (for example ``app`` or ``.github``) with a
    link to another folder at any time after the demo creates it and before
    the demo has finished writing into it. The demo then creates its remaining
    files and subfolders for that folder inside the other folder instead,
    wherever nothing of the same name exists there yet, and still reports
    success. These are new files and folders with the demo's fixed names and
    content (fake credentials and deliberately unsafe workflow files); no
    existing file is changed. Preventing this would need platform-specific
    directory handles.
    """
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise FileExistsError(f"{target} already exists and is not an empty directory")
    target.mkdir(parents=True, exist_ok=True)
    created = {target}
    written = []
    for relative, content in build_files().items():
        path = target / relative
        _create_folders(path.parent, created)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        except FileExistsError:
            raise FileExistsError(_appeared(path)) from None
        written.append(path)
    return written


def _create_folders(folder: Path, created: set[Path]) -> None:
    """Create ``folder`` and its missing parents below the demo root; each must be new."""
    missing = []
    while folder not in created:
        if folder == folder.parent:
            raise ValueError("demo paths must stay inside the demo folder")
        missing.append(folder)
        folder = folder.parent
    for new in reversed(missing):
        try:
            new.mkdir()
        except FileExistsError:
            raise FileExistsError(_appeared(new)) from None
        created.add(new)


def _appeared(path: Path) -> str:
    return (
        f"{path} appeared while the demo was being written (another program or user may "
        "have created it); stopped without writing to it"
    )
