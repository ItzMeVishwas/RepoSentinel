# Building and releasing RepoSentinel

This is how the maintainer builds installable archives and publishes a
release. Nothing has been published yet.

## What a release contains

* `reposentinel-X.Y.Z.tar.gz`, the source distribution. It includes the
  **built** web interface, so building a wheel from it does not need Node.js.
* `reposentinel-X.Y.Z-py3-none-any.whl`, the wheel (pure Python, any OS).

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
/tmp/rs-wheel/bin/python -m pip install dist/reposentinel-*.whl
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

## Publishing a release

1. Make sure the CI workflow passes on the commit to be released.
2. Update `CHANGELOG.md`, and set the version in `src/reposentinel/__init__.py`
   (the package metadata reads it from there).
3. Build the archives from a clean checkout (see above) and verify them.
4. Tag the release (`vX.Y.Z`) and create a GitHub release with the two
   archives attached.

Publishing to PyPI is a separate decision; it would use a trusted-publishing
workflow rather than a stored token.

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
