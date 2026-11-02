# Contributing to RepoSentinel

Thank you for your interest. RepoSentinel is an early-stage (alpha) project
maintained by one person. Issues, bug reports with synthetic examples,
documentation fixes and pull requests are welcome.

RepoSentinel is released under the [MIT License](LICENSE). By submitting a
contribution, you agree that it is licensed under the same terms.

## Reporting problems

* **Security problems in RepoSentinel itself:** follow [SECURITY.md](SECURITY.md).
  Do not open a public issue.
* **Bugs, false positives and false negatives:** open an issue using the bug
  template. Include a *synthetic* repository that reproduces the problem.
  Never paste real credentials, even revoked ones.

## Development setup

Requirements: Python 3.12 or newer, and Node.js 22.12 or newer for the web
interface.

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
cd frontend; npm ci --ignore-scripts; npm run build; cd ..
```

Linux and macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
(cd frontend && npm ci --ignore-scripts && npm run build)
```

## Checks every change must pass

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
python scripts/generate_rules_doc.py --check
python -m reposentinel scan .
cd frontend && npm run typecheck && npm run build && npm run e2e
```

Build the web interface (`npm run build` in `frontend/`) before running
`pytest`: a few tests start the real `reposentinel ui`, which needs it.
RepoSentinel supports Windows, Linux and macOS, and mypy checks platform-specific
code only for the platform it runs on; to check the others locally, run
`python -m mypy --platform linux` and `python -m mypy --platform win32`.

`npm run e2e` drives an installed Chrome or Edge against the real server
(`CHROME_PATH` selects the browser). To check that it does not depend on a fast
machine, run it with `E2E_CPU_SLOWDOWN=6` (a slower page) or
`E2E_API_DELAY_MS=400` (a slower server), as on small CI runners. SARIF output
is validated against the official schema with `scripts/validate_sarif.py` (see
[docs/sarif.md](docs/sarif.md)).
The CI workflow in `.github/workflows/ci.yml` runs all of these.

## Rules for code and tests

* **No real or real-looking secrets in source files.** Build synthetic
  credentials at run time from harmless pieces (see `tests/synthetic.py`), so
  RepoSentinel's self-scan of this repository stays clean.
* **Source files are plain ASCII.** Build invisible or control characters with
  `chr()` in tests; `tests/test_project.py` enforces this.
* **Finding text never quotes repository content.** Summaries and evidence are
  built from RepoSentinel's own vocabulary, positions and line numbers only.
* **Conservative wording.** Never describe a missing finding as "fixed",
  "resolved" or "secure". See the statuses in [docs/product-strategy.md](docs/product-strategy.md).
* **Security decisions live in Python.** The web interface displays results; it
  never computes findings, statuses or exit codes.
* **No network access, telemetry or code execution** from scanned repositories.
* Adding a rule: see "Adding a rule" in [docs/architecture.md](docs/architecture.md),
  then regenerate `docs/rules.md`.

## Pull requests

Keep each pull request focused, describe what changed and how you tested it,
and update the documentation and `CHANGELOG.md` when behaviour changes. The
pull-request template lists the checks.

By participating you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).
