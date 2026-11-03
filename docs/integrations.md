# External scanner integrations

RepoSentinel's native rules are intentionally few. Established scanners have
much broader coverage, so the goal is to run them *optionally* and normalise
their results into the same report. This page records what was evaluated
(October 2026), what was built, and what is still unverified.

> **The Gitleaks integration is experimental.** Its flags and behaviour were
> checked against Gitleaks' source code and tested with a simulated Gitleaks,
> but it has **not been run against a real Gitleaks binary**. Until that test
> is done and recorded below, do not rely on `--integration gitleaks` for
> security decisions. RepoSentinel's native rules do not depend on it.

None of these tools was installed on the development machine, and RepoSentinel
never downloads or installs tools itself.

## Summary

| Tool | Licence | Status | Reason |
|---|---|---|---|
| Gitleaks | MIT | **Experimental**: adapter implemented and opt-in (`--integration gitleaks`), not yet verified against a real binary | Broad secret detection that complements RS-SEC-* |
| Zizmor | MIT | Not integrated (next candidate) | Deep GitHub Actions analysis; overlaps RS-GHA-*; needs verification against a real binary |
| OSV-Scanner | Apache-2.0 | Not integrated | Its default mode queries the osv.dev API, which conflicts with RepoSentinel's offline guarantee |

## Gitleaks

Sources consulted: the Gitleaks README and the source files `cmd/root.go` and
`cmd/directory.go` on the `master` branch. The README notes that Gitleaks is
now feature-complete and receives security fixes only.

### Command line

```text
gitleaks dir <absolute repository path>
  --report-format json --report-path <temp>/gitleaks-report.json
  --config <temp>/gitleaks.toml          # contains: [extend] useDefault = true
  --redact=100 --exit-code 42 --ignore-gitleaks-allow
  --max-target-megabytes <RepoSentinel's file-size limit, rounded up>
  --no-banner --no-color --log-level error
```

| Choice | Why |
|---|---|
| `dir` mode, never `git` mode | `git` mode runs `git log -p` inside the target, and repository Git configuration can execute commands |
| `--config` pointing at a temporary file that extends the defaults | Otherwise Gitleaks loads `.gitleaks.toml` from the scanned repository, which could disable rules |
| `--ignore-gitleaks-allow` | `gitleaks:allow` comments in scanned code would otherwise hide results |
| `--redact=100`, and only `RuleID`, `Description`, `File`, `StartLine` are read | Secret values never enter RepoSentinel's data, even if redaction failed |
| `--exit-code 42` | By default Gitleaks exits 1 both for "leaks found" and for errors |
| Working directory: a fresh temporary folder | Gitleaks looks for `.gitleaksignore` in the working directory; also avoids loading files planted in the repository |
| Executable found by RepoSentinel's own PATH search | Ignores the current directory, and any PATH folder or program inside the scanned repository (even through a link); `.exe` only on Windows |
| `gitleaks version` run first (30 s timeout) | Releases before 8.19.0 lack `dir`; refusing them gives a clear message instead of an obscure error |

### How results are handled

| Situation | Result |
|---|---|
| `gitleaks` not on PATH | Check **skipped**, scan incomplete (exit 3), with installation guidance |
| `gitleaks version` reports a release older than 8.19.0 | Check **skipped**, scan incomplete, with an upgrade message; the scan is not attempted |
| `gitleaks version` output has no version number (source builds) or the command fails | Scan still runs; the check's note says "version unknown" |
| Exit code 0 and an empty report (`[]` or `null`) | Check completed, no findings |
| Exit code 42 and a valid report | Results become `gitleaks:<RuleID>` findings (severity high, confidence medium) |
| Results in paths RepoSentinel excludes (such as `node_modules/`) or outside the root | Ignored and counted in the check's note |
| Exit code 126 (unknown flag) | Check **failed**: Gitleaks 8.19 or newer is needed |
| Error text from Gitleaks | Not shown: the message says only whether Gitleaks wrote error output, because that output can quote scanned content. Run Gitleaks directly to see it |
| Any other exit code, a timeout (600 s), a missing, oversized (> 50 MiB) or malformed report, or an exit code 0 with results | Check **failed** with a sanitised message; scan incomplete |

### Known gaps

* **Not verified against a real Gitleaks binary.** The flags were checked
  against Gitleaks' source code (v8.19.0 and `master`), and the behaviour is
  tested with a simulated tool (`tests/test_integrations.py`). The simulation
  proves RepoSentinel's side of the contract: the command line, error
  handling, parsing, scope filtering and redaction. It cannot prove
  compatibility. Still to confirm with a real release:
  * the exact `gitleaks version` output format;
  * the `File` path format on Windows (absolute or relative, separators);
  * that `StartLine` is 1-based;
  * the empty-report format (`[]` or `null`);
  * that `--redact=100` and `--ignore-gitleaks-allow` behave as documented;
  * that exit codes 42, 1 and 126 occur as expected.
* A `.gitleaksignore` file **inside the scanned repository** is still honoured
  (Gitleaks always reads `<source>/.gitleaksignore` and has no option to turn
  this off). With Gitleaks 8.30.1 in directory mode, an entry only hides a
  result if it names the **absolute path** the folder is scanned from
  (`C:/work/app/config.py:github-pat:3`); relative paths, rule names and
  wildcards have no effect. So a repository can hide its own Gitleaks results
  only where it can predict that path, which is realistic on CI runners
  (`D:\a\<repo>\<repo>`, `/home/runner/work/<repo>/<repo>`).
  RepoSentinel's native rules are not affected.
* Gitleaks' own file-size limit is in whole megabytes, so it may scan slightly
  larger files than RepoSentinel does.
* **In `reposentinel compare`, a Gitleaks finding is never "Not detected on
  re-check".** Gitleaks does not report which files it examined, so the check
  records no `examined_paths`. A Gitleaks finding that disappears is "Not
  re-checked" (exit code 3), and a new one in a file the old scan did not run
  Gitleaks on is "New (not examined before)". Its fingerprint uses only the
  rule ID and the path. Comparing a scan made with `--integration gitleaks`
  against one made without it reports the check as not run.

### Verification record

**Windows 11, Gitleaks 8.30.1** (official `gitleaks_8.30.1_windows_x64.zip`,
SHA-256 `d29144de...afc4e` matching the release's checksums file and GitHub's
asset digest), 2026-11-03, following the steps below:

| Step | Observed | As assumed? |
|---|---|---|
| 3a `gitleaks version` | `8.30.1` (no `v`), exit 0 | Yes |
| 3b `dir` with the hardened flags | Exit 42. Fields: `RuleID`, `Description`, `File`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Match`, `Secret`, `Entropy`, `Fingerprint`, `SymlinkFile`, `Commit`, `Author`, `Email`, `Date`, `Message`, `Tags`. `File` is **absolute with `/`** (`C:/Users/.../gl-demo/allow.py`). `StartLine` is 1-based, also with CRLF line endings. `Secret` and `Match` are `REDACTED` | Yes (the path format is handled) |
| 3c without `--ignore-gitleaks-allow` | `allow.py` disappears; with the flag it is reported | Yes |
| 3d clean folder | Exit 0, report `[]` | Yes |
| 3e unknown option | Exit 126 | Yes |
| 3f missing folder | Exit 1, no report written | Yes |
| 4 `reposentinel scan --integration gitleaks` | Check completed, "Gitleaks 8.30.1: 2 result(s) imported", paths `allow.py`, `deploy/id_rsa`, `sub dir/app.py` (relative, `/`), same lines; no fake value in the report; clean folder gives a clean scan | Yes |
| 4 failure path | Not on PATH, or only inside the scanned folder: check skipped, exit 3 | Yes |
| extra | A `.gitleaks.toml` in the scanned folder that allow-lists everything hides every result when Gitleaks is run directly, but not through RepoSentinel (its own `--config` is used) | Yes |

Gitleaks 8.30.1 does not report the demo repository's `app/settings.py`
token (its random part is a run of letters), so line numbers were checked
with a token it does report.

These checks are automated in `tests/test_gitleaks_real.py`, which runs only
when `REPOSENTINEL_GITLEAKS_DIR` names a folder holding a Gitleaks obtained
with `scripts/fetch_gitleaks.py` (one pinned release, refused unless its
SHA-256 matches). The CI job `gitleaks` runs them on Linux, Windows and
macOS; it is not a required check.

### Verifying the adapter against a real Gitleaks

Until every step below has been done on a real release, the integration
stays **experimental**. Use only synthetic data: never point a first test at
a real repository.

**1. Get an official binary and check it.** Download the archive for your
platform and the checksums file (`gitleaks_<version>_checksums.txt`) from
the same release on <https://github.com/gitleaks/gitleaks/releases>, or use
a package manager you already trust. Check the archive before extracting it:

```powershell
# Windows: compare with the line for this file in the checksums file
Get-FileHash .\gitleaks_<version>_windows_x64.zip -Algorithm SHA256
```

```bash
# Linux and macOS
sha256sum --ignore-missing -c gitleaks_<version>_checksums.txt
```

Extract it into a new, empty folder **outside** any repository you will
scan (RepoSentinel refuses a `gitleaks` inside the scanned folder) and add
that folder to `PATH` for the current terminal only:

```powershell
$env:PATH = "C:\tools\gitleaks-<version>;" + $env:PATH
```

```bash
export PATH="$HOME/tools/gitleaks-<version>:$PATH"
```

**2. Prepare two synthetic folders**, each outside any Git repository:

```bash
python -m reposentinel demo gl-demo          # fake credentials that trigger every rule
mkdir gl-clean && echo "print('hello')" > gl-clean/app.py
```

For the `gitleaks:allow` test, save this as `make_allow.py` next to (not
inside) `gl-demo` and run `python make_allow.py`. It writes a fake token,
assembled at run time, followed by an allow comment:

```python
from pathlib import Path

token = "ghp_" + "0123456789" * 3 + "abcdef"
Path("gl-demo/allow.py").write_text(f'TOKEN = "{token}"  # gitleaks:allow\n')
```

**3. Run Gitleaks directly and record what it does.** Each row checks one of
the open questions listed under "Known gaps". Run the commands from a
temporary folder, not from inside `gl-demo`.

| # | Command | What to record | What RepoSentinel assumes |
|---|---|---|---|
| a | `gitleaks version` | The exact output | A version number such as `8.28.0` or `v8.28.0` appears in it |
| b | `gitleaks dir <abs>/gl-demo --report-format json --report-path demo.json --redact=100 --exit-code 42 --ignore-gitleaks-allow --no-banner` | Exit code; in `demo.json`: the field names, the `File` format (absolute or relative, `\` or `/`), `StartLine` for `app/settings.py`, and the `Secret` and `Match` values | Exit 42; `RuleID`, `Description`, `File`, `StartLine` exist; `StartLine` is 1-based (the `GITHUB_TOKEN` line of `app/settings.py` is line 3); `Secret` and `Match` are redacted |
| c | The same command without `--ignore-gitleaks-allow` | Whether `allow.py` disappears from the report | It disappears without the flag and is reported with it (if `allow.py` is not reported even in row b, this row proves nothing: retry with a value that row b did report) |
| d | `gitleaks dir <abs>/gl-clean --report-format json --report-path clean.json --exit-code 42 --no-banner` | Exit code and the exact content of `clean.json` | Exit 0; the report is `[]` or `null` |
| e | `gitleaks dir <abs>/gl-clean --no-such-option` | Exit code | 126 (unknown option) |
| f | `gitleaks dir <abs>/does-not-exist --report-format json --report-path missing.json --exit-code 42` | Exit code | 1 (error), not 42 |

**4. Run RepoSentinel with the integration** on the same folders:

```bash
python -m reposentinel scan gl-demo --integration gitleaks --format json -o rs-demo.json
python -m reposentinel scan gl-clean --integration gitleaks --format json -o rs-clean.json
```

Check that:

* the `gitleaks` check is *completed* (not failed or skipped), and its
  message names the version from step 3a;
* its findings are `gitleaks:<RuleID>` with paths relative to the scanned
  folder (`app/settings.py`, never absolute, never with `\`) and the same
  line numbers as in `demo.json`;
* none of the fake values appears anywhere in `rs-demo.json` (search it for
  `ghp_`, `AKIA` and `not-a-real-pass`);
* `rs-clean.json` reports a clean scan with the check completed.

Also check the failure path: with `gitleaks` removed from `PATH` again, the
check must be *skipped* with installation guidance. (Checking the
"too old" message needs a second download of a release before 8.19.0; it
is optional, because the version check is covered by the simulated tests.)

**5. Repeat on each platform.** The `File` format matters most on Windows,
so steps 3b and 4 should be done on Windows and on Linux or macOS.

**6. Record the result.** Note the Gitleaks version, the operating systems,
and every observed output in this section. Add a regression test to
`tests/test_integrations.py` that uses the observed report shape (with
synthetic, redacted values) and the observed exit codes. Only then change
the status in the table at the top of this page and in the README from
"experimental" to the verified version. If any observation differs from
the assumptions above, fix the adapter first and treat the difference as a
bug, not as a documentation change.

## Zizmor

Sources consulted: the Zizmor usage documentation (docs.zizmor.sh).

* `--format=json` (versioned as `json-v1`) and `--format=sarif` are available,
  with a documented compatibility policy for the JSON output.
* Exit codes: 0 means no findings, 1 an error, 2 an argument error, 3 that no
  inputs were collected, and 11 to 14 that findings were reported (by highest
  severity).
* It runs offline when no GitHub token is set. `--offline` forces this,
  which RepoSentinel should always pass.
* A local directory can be passed directly.

Zizmor is the natural next integration: it covers many more workflow risks
than RS-GHA-001 to 004. It was not integrated in version 0.1 because it could
not be run here to confirm the JSON shape, and an unverified second adapter
would add risk without evidence. It would reuse `integrations/process.py`
unchanged.

## OSV-Scanner

Sources consulted: the OSV-Scanner offline-mode documentation.

OSV-Scanner checks dependency lock files against the OSV vulnerability
database. By default it calls the osv.dev API. Offline mode (`--offline`)
avoids sending project information, but needs a local database that must be
downloaded first (`--download-offline-databases`). Both conflict with
RepoSentinel's rule of making no network requests, so an integration would need
an explicit, separately documented opt-in for the database download. It is
deferred until that design decision is made.

## Writing a new adapter

1. Subclass `Check` in `integrations/<tool>.py`. Accept a `finder` and a
   `runner` in `__init__` (defaulting to `find_executable` and `run_process`)
   so tests can inject fakes.
2. Raise `CheckSkipped` if the executable is missing. Raise
   `IntegrationError` (or any exception) for every other problem; the engine
   reports it as *failed*.
3. Run the tool from a temporary directory, write its report to a file there,
   and read the report defensively (size limit, JSON type checks).
4. Copy only non-secret fields into `Finding` objects, using IDs of the form
   `<tool>:<rule>`. Drop results outside RepoSentinel's file inventory.
5. Register it in `cli.INTEGRATION_CHECKS` and document the verified version.
