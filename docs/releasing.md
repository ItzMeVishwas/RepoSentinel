# Building and releasing RepoSentinel

This is how the maintainer builds installable archives and publishes a
release.

RepoSentinel 0.1.0 is published on PyPI as
[`reposentinel-scanner`](https://pypi.org/project/reposentinel-scanner/0.1.0/),
with the Git tag `v0.1.0` (commit `6da5bd8`) and the
[GitHub release v0.1.0](https://github.com/ItzMeVishwas/RepoSentinel/releases/tag/v0.1.0).
Its two archives have these SHA-256 values, on PyPI and on the GitHub release:

| File | SHA-256 |
|---|---|
| `reposentinel_scanner-0.1.0-py3-none-any.whl` | `a6dc079826e468bb89e8d9221f276c5e5b742833e9ac7ca9a98fed4e9287589d` |
| `reposentinel_scanner-0.1.0.tar.gz` | `218b4ce37180cd29e71e6613cfd7b3f2e709558e8b094e647b64bfe228a644af` |

## What a release contains

* `reposentinel_scanner-X.Y.Z.tar.gz`, the source distribution. It includes
  the **built** web interface, so building a wheel from it does not need
  Node.js.
* `reposentinel_scanner-X.Y.Z-py3-none-any.whl`, the wheel (pure Python, any
  OS).

The distribution is named `reposentinel-scanner` (`pip install
reposentinel-scanner`; file names use the normalised form
`reposentinel_scanner`). PyPI refuses `reposentinel` as too similar to an
existing project. The import package and the command are still
`reposentinel`, and `scripts/check_dist.py` checks all three names.

The web interface is built from `frontend/` with exact dependency versions
from `frontend/package-lock.json`. The build output
(`src/reposentinel/webui/static/`) is generated, ignored by Git, and never
edited by hand.

## Build

Requirements: Python 3.12+, Node.js 22.12+ with npm, and the release tools.

```bash
python -m pip install -e ".[release]"      # build and twine
python scripts/build_release.py --outdir dist
```

`build_release.py` runs, in order and stopping at the first failure:

1. `npm ci --ignore-scripts` (exact versions from the lockfile; no install scripts);
2. `npm run build` (type check and production build into `webui/static/`);
3. `python -m build` (the sdist, then the wheel built from the sdist);
4. `twine check --strict` on both archives;
5. `scripts/check_dist.py`, which checks that both archives contain the web
   interface with every referenced asset (the sdist also carries the tests
   and the frontend source), and nothing that must never be shipped: virtual
   environments, caches, Git and local tool state, `node_modules`, `.env`
   files, generated reports, SARIF files, local databases and logs.

`--offline` makes npm use only its local cache (for machines without network
access); a normal build downloads the pinned packages from the npm registry.
The output folder must be new or empty; nothing is deleted.

Build from a clean checkout (or a fresh copy of the files Git tracks), not
from a working folder with local state.

## Verify the archives

```bash
python -m venv /tmp/rs-wheel
/tmp/rs-wheel/bin/python -m pip install dist/reposentinel_scanner-*.whl
cd /tmp                                   # outside the source folder
/tmp/rs-wheel/bin/reposentinel --version
/tmp/rs-wheel/bin/python /path/to/reposentinel/scripts/smoke_installed.py
```

On Windows use `\Scripts\python.exe` instead of `/bin/python`. The smoke
test checks the command line, every report format, comparison exit codes, the
demo command, the web interface's session and security headers, and the
project-history workflow (in a temporary data folder).

A wheel built without the web interface (`python -m build --wheel` from a
checkout where the interface was not built) must still work for every
command except `ui`, which explains how to build it:
`smoke_installed.py --no-ui` checks that.

To check the browser end to end against the installed wheel:

```bash
cd frontend
PYTHON=/tmp/rs-wheel/bin/python npm run e2e
```

## The reference build environment

The SHA-256 of an archive depends on where it was built, even when the files
inside are identical:

* a wheel built on Linux or macOS records a different operating system in
  every entry (Python's `zipfile`), so it never matches one built on Windows;
* CPython 3.14 on Windows compresses with zlib-ng, whose output differs from
  classic zlib.

Release archives are therefore built in one pinned environment, defined in
`.github/actions/reference-build/action.yml`:

| Part | Pinned to |
|---|---|
| Runner | GitHub's `windows-2025` image (the action refuses any other) |
| Python | CPython 3.13.17 from python.org, with classic zlib 1.3.1 |
| Node.js | 24.21.0; the web interface from `frontend/package-lock.json` |
| pip, build, twine and their dependencies | `release-tools.txt`, every file pinned by SHA-256 |
| hatchling and its dependencies | `build-backend.txt`, every file pinned by SHA-256 |

The build installs its isolated build environment only from those verified
files, never from a package index, so a new upstream release cannot change
the archives. The header comment of `action.yml` gives the same steps for a
build on the maintainer's Windows computer.

The CI job `reference-build` rebuilds the release commit named in
`.github/actions/reference-build/expected-archives.txt` on every change and
fails unless both archives have exactly the SHA-256 values recorded there.

## Publishing to PyPI

Releases are published by `.github/workflows/publish.yml` with PyPI
**trusted publishing**: PyPI accepts an upload only from this repository,
this workflow file and the matching GitHub environment. No PyPI token,
password or other secret is stored anywhere, and none is needed.

| GitHub environment | Uploads to | Protection |
|---|---|---|
| `testpypi` | TestPyPI (`https://test.pypi.org/`) | Runs only from `main` |
| `pypi` | PyPI | Runs only from `main`, and needs the approval of a required reviewer (the maintainer) |

Each index has a trusted publisher registered for project
`reposentinel-scanner`, owner `ItzMeVishwas`, repository `RepoSentinel`,
workflow `publish.yml` and that environment's name, so a run in the
`testpypi` environment can never publish to PyPI.

The workflow only runs when started by hand (**Actions > Publish > Run
workflow**). Its inputs are the index (`testpypi` by default), the version
and the expected SHA-256 of the wheel and of the source archive (surrounding
spaces and upper-case letters are accepted). It then:

1. checks the inputs: each hash must be 64 hexadecimal characters, and the
   version must be a normalised version, from which the two file names are
   derived;
2. rebuilds both archives from the commit it runs on, in the reference build
   environment, checks them (`twine check --strict`, `scripts/check_dist.py`),
   and stops unless the output holds exactly the two expected files with the
   expected SHA-256;
3. in a separate job on a fresh runner, where no project code runs, copies
   exactly those two files into a new folder, checks their names and SHA-256
   again, and uploads only that folder. Only this job can request the
   OpenID Connect token that trusted publishing needs.

An upload of a version that already exists fails; it is never skipped.

## Preparing and publishing a release

1. **Prepare the release commit.** In a pull request, update `CHANGELOG.md`
   and set the version in `src/reposentinel/__init__.py` (the package
   metadata reads it from there). Merge it once CI passes. Its merge commit
   on `main` is the release commit.
2. **Build and verify locally.** In a clean clone of the release commit, build
   the archives in the reference build environment (the commands in the
   header of `action.yml`), verify them as described in
   [Verify the archives](#verify-the-archives), and record their SHA-256:

   ```powershell
   Get-FileHash $env:TEMP\rs-dist\* -Algorithm SHA256
   ```

3. **Optionally, let CI check the hashes.** In a pull request, put the
   release commit, version and both hashes into `expected-archives.txt` and
   the same commit into the `ref:` of the "Check out the release commit" step
   in `.github/workflows/ci.yml`. The `reference-build` job then shows whether
   GitHub's runner makes exactly the same files. Changes under `.github/` do
   not change the archives, because that folder is not part of them.
4. **Publish to TestPyPI.** Start the Publish workflow on `main` with index
   `testpypi`, the version and the two hashes. The workflow builds the commit
   at the tip of `main`, so `main` must not have changed anything that goes
   into the archives since the release commit; if it has, the hashes will not
   match and nothing is uploaded. Then install from TestPyPI into a fresh
   virtual environment and run `scripts/smoke_installed.py`:

   ```bash
   python -m pip install --index-url https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ reposentinel-scanner==X.Y.Z
   ```

5. **Publish to PyPI.** Start the workflow again with index `pypi` and the
   same values, and approve the deployment to the `pypi` environment when
   GitHub asks for it.
6. **Check what PyPI serves.** Compare the hashes on
   `https://pypi.org/pypi/reposentinel-scanner/X.Y.Z/json` (or the PyPI
   project page) with the recorded ones, and install the release from PyPI
   into a fresh virtual environment.
7. **Tag and release on GitHub.** Create an annotated tag `vX.Y.Z` on the
   release commit and push only that tag. Create a GitHub release from it and
   attach exactly the two files downloaded from PyPI, together with a
   `SHA256SUMS.txt` that lists their SHA-256 values.

## Repository settings

These are set once on GitHub, in the repository's settings:

* **Private vulnerability reporting** (Security): required by `SECURITY.md`.
* **Secret scanning** and **push protection** (Security): GitHub turns them on
  by default for public repositories; check that they are on.
* **Dependabot alerts** and **security updates**; version updates are
  configured in `.github/dependabot.yml`.
* **Code scanning** (for example CodeQL default setup).
* **Branch protection** for the default branch: require the CI workflow to
  pass before merging.
* **Environments** `testpypi` and `pypi` (see
  [Publishing to PyPI](#publishing-to-pypi)), each limited to `main`, with a
  required reviewer for `pypi` and no administrator bypass, plus a pending or
  registered trusted publisher for each on TestPyPI and PyPI.
