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
  this off), so a repository can hide some of its own Gitleaks results.
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

### Verifying the adapter (next step)

1. Install Gitleaks from the official releases page, a trusted package
   manager, or a source build, and confirm it with `gitleaks version`.
2. Create the demo repository: `python scripts/create_demo_repo.py <dir>`.
3. Run `gitleaks dir <dir> --report-format json --report-path out.json
   --redact=100` directly, and inspect `out.json` (field names, `File` format,
   line numbers).
4. Run `reposentinel scan <dir> --integration gitleaks --format json` and
   compare. Record the tested version here and add a regression test using
   the observed report shape.

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
