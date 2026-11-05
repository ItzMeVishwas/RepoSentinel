# RepoSentinel

**Find it. Fix it. Re-check it.**

RepoSentinel is a local-first security auditor for software repositories. It
checks the files in a repository folder for a small, carefully chosen set of
common problems (risky files, hard-coded credential patterns and unsafe GitHub
Actions workflows), explains each finding, and, after you change something,
tells you what is still detected, what is no longer detected, and what it
could not re-check.

It runs on your computer only, never executes code from the repository it
scans, never prints a matched secret, and sends nothing over the network.

> **Status: alpha (0.1.0).** The rules are few and their
> limits are documented. RepoSentinel is not a replacement for a dedicated
> secret scanner, dependency auditor or code review, and a clean result does
> **not** mean a repository is secure: it means only that these checks found
> nothing in the files they examined.

![The RepoSentinel overview for a synthetic demo project: what needs attention, what changed since the previous scan, coverage and next actions](docs/images/overview.png)

## The problem it addresses

Before publishing a repository, or after cleaning one up, a developer wants to
know: did I leave credentials, key files or risky CI workflows in it? And once
I have fixed something, is it really gone from what I am about to publish?
Most scanners answer the first question with a list. RepoSentinel also keeps
track of each finding across scans and is explicit about the limits of every
answer: what it checked, what it skipped, what it could not re-check, and
that a finding which is "no longer detected" is not proof that a credential
is safe (it may still be valid, and still be in Git history).

## What it does and does not do

RepoSentinel **does**:

* walk a directory safely (no symlinks or junctions; size, file-count and
  depth limits; default exclusions for `.git/`, virtual environments,
  dependency folders and build output);
* apply 12 native rules ([rules](#rules)) and report each finding with a
  stable rule ID, severity, confidence, redacted evidence, location and
  remediation;
* say clearly whether a scan was **clean**, had **findings**, or was
  **incomplete** (a check failed or was skipped, or a file could not be read);
* write terminal, JSON, standalone HTML and SARIF 2.1.0 reports;
* compare two scans conservatively ([`compare`](#comparing-two-scans-from-the-command-line));
* offer a local web interface ([`reposentinel ui`](#local-web-interface))
  with registered projects, opt-in scan history, one-click "scan again and
  compare", a findings explorer and exports;
* optionally run an installed [Gitleaks](https://github.com/gitleaks/gitleaks)
  (tested with Gitleaks 8.30.1 on Windows, Linux and macOS).

RepoSentinel **does not**:

* confirm that a credential is valid or that a vulnerability is exploitable;
  every finding is a *potential indicator* for a human to review;
* scan Git history (only the files currently in the directory);
* scan dependencies for known vulnerabilities, detect malware, or test a
  running application;
* send code, findings or metadata anywhere, download tools, or modify the
  scanned repository.

## Supported platforms

| | Status |
|---|---|
| Python | 3.12, 3.13 and 3.14 (`requires-python >= 3.12`). The test suite runs on all three in CI, on Ubuntu, Windows and macOS, and also with the lowest supported dependency versions. |
| Windows | CI (Windows Server runners) and local testing on Windows 11 (command line, web interface, packaging). |
| Linux | The GitHub Actions workflow runs the Python test suite, package build and installation, SARIF validation, the real-Gitleaks tests, and Chrome and Firefox browser tests on Ubuntu. |
| macOS | The GitHub Actions workflow runs the Python test suite and the real-Gitleaks tests on macOS. The web interface in a browser, packaging and everyday use have not been tested on macOS. |
| Browsers | Tested with Chrome, Edge and Firefox through automated end-to-end tests (in Firefox one check that needs Chrome's DevTools protocol is skipped). Safari and screen readers are not tested. |

## Installation

RepoSentinel needs Python 3.12 or newer. It is published on PyPI as
[`reposentinel-scanner`](https://pypi.org/project/reposentinel-scanner/) (the
shorter name was not available); the command and the Python package are
`reposentinel`:

```bash
pip install reposentinel-scanner
```

Installing it into its own virtual environment is recommended.

Windows (PowerShell):

```powershell
py -3 -m venv rs-env
.\rs-env\Scripts\python.exe -m pip install reposentinel-scanner
.\rs-env\Scripts\python.exe -m reposentinel --version
```

Linux and macOS:

```bash
python3 -m venv rs-env
rs-env/bin/python -m pip install reposentinel-scanner
rs-env/bin/python -m reposentinel --version
```

The last command prints `reposentinel 0.1.0`. The web interface
(`reposentinel ui`) is included; Node.js is only needed to work on
RepoSentinel itself (see "From a source checkout" below).

Basic usage, with the virtual environment's Python (or the installed
`reposentinel` command):

```bash
python -m reposentinel --help          # all commands and options
python -m reposentinel scan PATH       # scan a repository folder
python -m reposentinel ui              # the local web interface
```

`python -m reposentinel` always works; the installed `reposentinel` command
does the same. If PowerShell refuses to run the venv activation script, keep
using the full paths above; there is no need to change system settings. If
Windows Smart App Control blocks the newly created `reposentinel.exe`
launcher, use `python -m reposentinel`: it behaves identically. Do not turn
the protection off for this.

The optional Gitleaks integration needs Gitleaks itself, which RepoSentinel
never downloads; see [Optional Gitleaks integration](#optional-gitleaks-integration).

### From a source checkout

The source code is at
[github.com/ItzMeVishwas/RepoSentinel](https://github.com/ItzMeVishwas/RepoSentinel).
You need Python 3.12 or newer, and Node.js 22.12 or newer to build the web
interface (the command line works without it).

Windows (PowerShell):

```powershell
cd C:\path\to\reposentinel
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
cd frontend; npm ci --ignore-scripts; npm run build; cd ..   # optional: the web interface
.\.venv\Scripts\python.exe -m reposentinel --help
```

Linux and macOS:

```bash
cd /path/to/reposentinel
python3 -m venv .venv
.venv/bin/python -m pip install -e .
(cd frontend && npm ci --ignore-scripts && npm run build)   # optional: the web interface
.venv/bin/python -m reposentinel --help
```

To build installable release archives (wheel and source distribution), see
[docs/releasing.md](docs/releasing.md).

## Your first scan

1. Create the synthetic demo repository. Every credential in it is fake:

   ```bash
   python -m reposentinel demo demo-repo
   ```

2. Scan it:

   ```bash
   python -m reposentinel scan demo-repo
   ```

   The report lists each finding with its rule, severity, redacted evidence
   and what to do, then what could not be checked, then the exit code.

3. Save a JSON report, change something, scan again and compare:

   ```bash
   python -m reposentinel scan demo-repo -f json -o reposentinel-report-before.json
   # ... delete demo-repo/.env, for example ...
   python -m reposentinel scan demo-repo -f json -o reposentinel-report-after.json
   python -m reposentinel compare reposentinel-report-before.json reposentinel-report-after.json
   ```

Or do all of this in the browser: run `python -m reposentinel ui` and choose
**Try a synthetic demo project** on the first screen.

## Command-line usage

```bash
reposentinel scan PATH                                   # terminal report
reposentinel scan PATH -f json -o reposentinel-report.json
reposentinel scan PATH -f html -o reposentinel-report.html
reposentinel scan PATH -f sarif -o reposentinel.sarif    # SARIF 2.1.0
reposentinel scan PATH --fail-on high                    # only high findings fail
reposentinel scan PATH --integration gitleaks            # needs Gitleaks on PATH
reposentinel compare before.json after.json              # compare two JSON reports
reposentinel ui                                          # the local web interface
reposentinel demo FOLDER                                 # synthetic demo repository
reposentinel rules                                       # the rule catalogue
```

| Option | Default | Meaning |
|---|---|---|
| `--format`, `-f` | `text` | `text`, `json`, `html` or `sarif` (scan only; see [docs/sarif.md](docs/sarif.md)) |
| `--output`, `-o` | standard output | Write the report to a UTF-8 file |
| `--fail-on` | `low` | Lowest severity that makes the exit code 1 (`high`, `medium`, `low`, `info`, `never`) |
| `--max-file-size-kb` | `1024` | Files larger than this are skipped (and listed under Coverage) |
| `--max-files` | `50000` | Stop after this many files; the scan is then *incomplete* |
| `--integration` | none | Also run an installed external scanner (currently `gitleaks`) |
| `--no-color` | off | Plain terminal output (the `NO_COLOR` environment variable also works) |

**Windows tip:** in Windows PowerShell 5.1, `... --format json > file.json`
writes UTF-16. Use `--output file.json`, which always writes UTF-8.
Files named `reposentinel-report*` are excluded from scans, so a report saved
inside the repository is not re-scanned.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan complete; no finding at or above `--fail-on` |
| 1 | Scan complete; at least one finding at or above `--fail-on` |
| 2 | Invalid arguments or path (missing, not a directory, not readable) |
| 3 | Scan **incomplete**: a check failed or was skipped, a file could not be read or parsed, a limit was reached, the report could not be written, or an internal error occurred |

An incomplete scan returns 3 even if it also has findings, because results may
be missing. RepoSentinel never reports success for checks that did not run.
If a scan is interrupted with Ctrl+C, it exits with 130 and writes no report.

### Example output

Trimmed output from scanning the demo repository (the path is shortened; every
value is synthetic and redacted):

```text
RepoSentinel 0.1.0 scan report
Target:  C:\Users\you\AppData\Local\Temp\reposentinel-demo
Scanned: 2026-10-25T12:16:09+00:00

Findings
HIGH (7)
  RS-GHA-002  pull_request_target workflow checks out pull request code
      Location:   .github/workflows/preview.yml:9
      Summary:    Job 1, step 1: workflow is triggered by pull_request_target and checks out
                  pull request code.
      Evidence:   ref: refers to github.event.pull_request.head.*
      Confidence: medium
  RS-GHA-001  Untrusted input expanded inside a script
      Location:   .github/workflows/triage.yml:16
      Summary:    Job 1, step 3: github.event.issue.title is expanded directly into a shell
                  script.
      Evidence:   ${{ github.event.issue.title }}
      Confidence: medium
  RS-SEC-004  GitHub token
      Location:   app/settings.py:3
      Summary:    Possible GitHub token.
      Evidence:   ghp_[REDACTED]
      Confidence: high
  ...

How to fix
  RS-GHA-002  pull_request_target workflow checks out pull request code
      Use the pull_request trigger to build and test untrusted code. ...
  ...

Checks
  Check                          | Status    | Examined | Findings | Note
  -------------------------------+-----------+----------+----------+-----
  Risky files in the repository  | completed |        9 |        3 |
  Hard-coded credential patterns | completed |        9 |        7 |
  GitHub Actions workflows       | completed |        2 |        4 |

Coverage
  Files in scope: 9

Summary
  Findings: 14 (high 7, medium 7, low 0, info 0)
  Checks:   3 completed, 0 failed, 0 skipped
  FINDINGS: every check completed; review the findings listed.
  Findings are potential indicators for human review, not confirmed vulnerabilities. A clean
  result means only that the checks listed found nothing; it does not mean the repository is
  secure.
Exit code 1: findings at or above --fail-on=low.
```

A JSON finding looks like this (the full report also has `notes`, `summary`,
`checks`, `coverage`, `coverage_by_check`, `files` and `scan_config` sections;
`schema_version` is `1.1`):

```json
{
  "rule_id": "RS-SEC-004",
  "title": "GitHub token",
  "severity": "high",
  "confidence": "high",
  "summary": "Possible GitHub token.",
  "evidence": "ghp_[REDACTED]",
  "location": { "path": "app/settings.py", "line": 3 },
  "remediation": "Revoke the token in GitHub (Settings > Developer settings, ...) ...",
  "check": "secrets",
  "fingerprint": "rs1:3b27...51ed",
  "rule_version": 1
}
```

Schema 1.1 only added fields (`fingerprint`, `rule_version`,
`coverage_by_check`, `files`, `scan_config`); everything that was in 1.0 is
unchanged. **Privacy note:** a 1.1 report lists every file path in scope and
the paths each check examined, so share it only where you would share the
repository's file list.

## Reading a finding

Every finding has:

* a **rule** (for example `RS-SEC-004`) with a version; `reposentinel rules`
  lists them and [docs/rules.md](docs/rules.md) explains each one, including
  its known false positives;
* a **severity** (the likely impact if the finding is real) and a
  **confidence** (how likely the match is a real problem rather than, say,
  test data);
* a **location** (file and, where it applies, line) and **evidence** built by
  RepoSentinel itself: secret values are always hidden, and repository text
  such as workflow step names is never copied;
* **remediation**: what to do next.

Treat each finding as something to check, not as proof. A finding that is no
longer detected after you change something is only that: if it was a real
credential, it may still be valid and still be in Git history, so rotate or
revoke it.

## Configuration

RepoSentinel has no configuration file. Behaviour is set per run:

| Setting | How | Default |
|---|---|---|
| Report format and file | `--format`, `--output` | terminal text, standard output |
| Failing threshold for the exit code | `--fail-on` | `low` |
| File size and file count limits | `--max-file-size-kb`, `--max-files` (also under "Scan limits" in the web interface) | 1024 KiB, 50,000 files |
| Colour | `--no-color` or the `NO_COLOR` environment variable | colour in a terminal |
| Web interface port | `reposentinel ui --port N` | a free port |
| Local history folder | `reposentinel ui --data-dir FOLDER` or `REPOSENTINEL_DATA_DIR` | your user data folder |
| No history at all | `reposentinel ui --no-history` | history on for registered projects |

The default exclusions and limits are listed under
[Default exclusions and limits](#default-exclusions-and-limits).

## Comparing two scans from the command line

> **Tested internally only.** `compare` implements revision 3 of
> [docs/product-strategy.md](docs/product-strategy.md). It has automated tests
> and an internal walkthrough, but it has **not been tried by any external
> user yet**, so the wording and statuses may change. The web interface makes
> the same comparison automatically for registered projects.

After you fix something, `compare` tells you what changed between two saved
scans of the same folder, and what it could not check:

```powershell
reposentinel scan . --format json --output reposentinel-report-before.json
# ... edit your files ...
reposentinel scan . --format json --output reposentinel-report-after.json
reposentinel compare reposentinel-report-before.json reposentinel-report-after.json
```

It reads only the two report files: it does not scan, open the repository or
look at Git history. Both reports must be JSON schema 1.1 (made by this
version); older reports are refused with a message to scan again.

Each *tracked finding* (all occurrences of one rule in one file, or in one
workflow job, recognised by its `fingerprint`) gets one status:

| Status | Meaning |
|---|---|
| Still detected | Found in both scans (the occurrence count is shown when it changed, for example "2 to 1") |
| New | Found now; the old scan examined that file (or the file did not exist) and did not find it |
| New (not examined before) | Found now; the old scan did not examine that file with that check, so it may not be new |
| Not detected on re-check | Not found now, **and** the owning check completed, examined that file, with the same rule version and the same scan settings |
| Not detected: file removed | The file is gone, and the new scan listed the folder completely |
| Not re-checked | Not found now, but one of those conditions failed (the reason is shown, for example "larger than the size limit" or "the check was skipped") |
| Not comparable | The rule version or the scan settings (size, file or depth limits, exclusion lists) differ between the scans |

"Not detected on re-check" is the strongest result, and it still only means
that **this rule no longer matches in the files it examined**. Each such
result shows what the rule cannot see (for example a token that was split or
encoded). For credential findings that are no longer detected, the output
always reminds you to rotate or revoke the credential: removing it from the
current files does not remove it from Git history, and RepoSentinel cannot
confirm either step. Every summary states its scope and that Git history was
not scanned.

| Option | Default | Meaning |
|---|---|---|
| `--format`, `-f` | `text` | `text`, `json` (comparison schema 1.0) or `html` (self-contained page, no JavaScript) |
| `--output`, `-o` | standard output | Write to a UTF-8 file (it may not be one of the two input reports) |
| `--fail-on` | `low` | Lowest severity of a still-detected or new finding that gives exit code 1 |
| `--different-roots` | off | Allow reports made from different folder paths; you declare they are the same repository, RepoSentinel cannot check it |
| `--no-color` | off | Plain terminal output |

`compare` exit codes, in order (the first that applies wins):

| Code | Meaning |
|---|---|
| 2 | Invalid input: a report is missing, not valid JSON, larger than 64 MiB, of another schema, inconsistent, or made from a different folder path without `--different-roots`. No comparison is printed |
| 3 | Something is unknown: a finding is "Not re-checked" or "Not comparable", a check failed, was skipped or did not run in the new scan, or the new scan has a coverage error. This applies whatever `--fail-on` says, including `never` |
| 1 | Nothing unknown, and a still-detected or new finding is at or above `--fail-on` |
| 0 | None of the above |

Known limits of the prototype:

* Renaming a file or a workflow job shows the old finding as "Not detected:
  file removed" or "Not detected on re-check" and the renamed one as "New";
  RepoSentinel does not claim they are the same problem.
* Changing a secret value in place keeps the same tracked finding ("Still
  detected"); values are deliberately not part of the fingerprint.
* Gitleaks findings can be "Still detected" or "New", but never "Not detected
  on re-check": the integration does not record which files Gitleaks examined.
* The output of `compare --format json` is not a scan report and cannot be
  used as `compare` input. There is no history: you keep the report files.

## Local web interface

`reposentinel ui` starts a local console on `127.0.0.1` and opens a one-time
link in your browser. Everything it shows comes from the same Python engine
as the command line; the browser computes no findings or statuses itself.

```bash
python -m reposentinel ui                 # Ctrl+C to stop
python -m reposentinel ui --no-browser    # print the link only
python -m reposentinel ui --no-history    # one-off scans and comparisons only
```

* **Overview**: the current project, what needs attention (by severity, new,
  detected again, not re-checked), coverage, recent scans and next actions.
  Never a score.
* **Projects**: register the folders you check over time; scan again and
  compare in one click; rename, relocate, clear a project's history, or remove it.
* **Scan**: a registered project (saved and compared) or a one-off folder (not saved).
* **Findings**: search, filter, sort, group by file, keyboard navigation, and
  a detail panel with redacted evidence, remediation and each rule's limits.
* **History**: a timeline of saved scans with what changed each time; select
  two scans to compare them.
* **Compare**: saved scans, or two JSON report files.
* **Reports**: JSON, HTML and SARIF downloads.
* **Settings**: where local data is kept, deleting it, display preferences.

| | |
|---|---|
| ![First run with the synthetic demo option](docs/images/first-run.png) | ![Findings explorer with the detail panel](docs/images/findings.png) |
| ![History timeline and saved scans](docs/images/history.png) | ![Comparison summary with an explanation of each status](docs/images/compare.png) |

<img src="docs/images/phone.png" alt="The overview on a phone-sized screen" width="260">

*Screenshots of the real application with the synthetic demo project.*

**Local data.** History is opt-in: it is kept only for folders you register as
projects, in a SQLite database in your user data folder (on Windows
`%LOCALAPPDATA%\RepoSentinel`), never inside a scanned project. It stores the
redacted JSON reports, never file contents, secret values or session tokens.
Settings shows where it is and deletes it.

**Security model.** The server listens on 127.0.0.1 only; the page receives a
one-time launch code in the URL fragment and keeps its session token in
memory (no cookies or browser storage); every request is checked for Host,
Origin and a custom header; there is no CORS, and a strict
Content-Security-Policy allows nothing from other origins. Details and limits:
[docs/webui.md](docs/webui.md).

## Rules

Full descriptions, severity rationale, remediation and limitations for every
rule are in **[docs/rules.md](docs/rules.md)** (generated from the code).

| Rule | Severity | Confidence | What it looks for |
|---|---|---|---|
| RS-HYG-001 | medium (info if git-ignored) | medium | `.env`-style files (templates such as `.env.example` are ignored) |
| RS-HYG-002 | medium | medium | Private key and keystore file names (`id_rsa`, `*.p12`, `*.pfx`, `*.jks`, `*.ppk`, ...) |
| RS-HYG-003 | high | medium | Plain-text credential stores (`.git-credentials`, `.netrc`, `_netrc`, `.pgpass`) |
| RS-SEC-001 | high | high | PEM, OpenSSH and PGP private key headers |
| RS-SEC-002 | medium | high | AWS access key IDs (`AKIA...`, `ASIA...`) |
| RS-SEC-003 | high | medium | AWS secret access keys assigned to a recognisable name |
| RS-SEC-004 | high | high | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) |
| RS-SEC-005 | medium | medium | Passwords embedded in URLs (`scheme://user:password@host`) |
| RS-GHA-001 | high | medium | Attacker-controlled `${{ }}` expressions inside `run:` or `github-script` scripts |
| RS-GHA-002 | high | medium | `pull_request_target` workflows that check out pull request code |
| RS-GHA-003 | medium | high | Third-party actions referenced by tag or branch instead of a commit SHA |
| RS-GHA-004 | medium | high | `permissions: write-all` |

**Reading severity and confidence.** Severity is the likely impact *if* the
finding is real: `high` means credentials, code or CI could plausibly be
compromised directly; `medium` is a real weakness that usually needs another
factor; `low` is hardening; `info` is probably fine but worth knowing.
Confidence is how likely the pattern match is a true positive. Treat a
high-severity, high-confidence finding first.

## Safety, privacy and data handling

* **Offline.** RepoSentinel makes no network requests. There is no telemetry,
  analytics, update check or AI service.
* **Read-only and non-executing.** Files are only listed and read as bytes.
  Workflow YAML is parsed with PyYAML's safe loader and `${{ }}` expressions
  are treated as text. RepoSentinel deliberately does **not** run Git in the
  scanned repository, because repository configuration can make Git execute
  commands.
* **Repository text is not copied into findings.** Pattern-based redaction
  cannot recognise every credential (an unknown format, or a token glued to
  other text), so finding summaries and evidence are built only from
  RepoSentinel's own vocabulary, positions and line numbers. Workflow
  findings say "Job 2, step 3" instead of quoting job IDs or step names, show
  an expression only as the matched context (`${{ ... github.event.issue.title
  ... }}`), and never quote YAML values or action refs (except version tags
  such as `v4` and common branch names). Error messages from a failing check,
  from YAML parsing and from Gitleaks never quote file content or tool output.
* **Secrets are redacted twice.** Checks replace matched values before a
  finding is created; evidence keeps at most a type prefix such as `ghp_` or
  `AKIA`. Then the engine runs every finding, check message and coverage note
  through the same credential patterns again as a second safeguard.
* **What reports still show, and why.** Hidden: matched secrets, the user
  name, password *and host* of a URL with a password (a host name can reveal
  internal systems), URL schemes RepoSentinel does not know, workflow text,
  tool output and exception messages. Shown, because you need them to act:
  file and folder paths (including the scanned folder's full path, which can
  contain your user name), and the `owner/repo` of an action that is not
  pinned (which can name a private organisation or repository). A credential
  or private name written into one of these places would appear in reports,
  so share reports only where you would share the repository's file list.
* **Hostile text is neutralised.** File names and other repository text are
  escaped in HTML (autoescaping, plus a Content-Security-Policy that allows no
  scripts, resources, `<base>` or forms, and no JavaScript in the page). In
  terminal and HTML output, every non-printable character (terminal escape
  sequences, bidirectional overrides, zero-width and other invisible
  characters, line separators, undecodable bytes) is shown as a visible code
  such as `\x1b` or `\u200b`.
* **No tracebacks with data.** Unexpected errors are reported as one sanitised
  line (exit code 3) instead of a traceback that could include file contents.
* **Report files are untrusted input to `compare`.** They are size-limited,
  strictly validated, and their text is redacted and escaped again before it
  is shown. Error messages name the broken field but never quote its value.
  Nothing in a report is used to open, read or run anything.
* **Local history is opt-in and stays on this computer.** Only the web
  interface keeps history, and only for folders you register as projects. It
  stores the redacted JSON reports (never file contents, secret values or
  session tokens) in a SQLite database in your user data folder, outside every
  scanned project. Settings shows where it is and deletes it; see
  [docs/webui.md](docs/webui.md#local-data-and-privacy).
* **Fingerprints are identifiers, not secrets.** A fingerprint is the SHA-256
  of the rule ID, the file path and, for some rules, a structural name (a job
  ID, an action's `owner/repo`, a key type). Secret values, workflow
  expressions and file contents are never inputs, and every input is redacted
  first. Anyone who knows a path can recompute its fingerprint.
* **Stays inside the folder.** Symlinks and junctions are never followed. Each
  directory is re-checked just before it is listed, and each file is checked
  after it is opened (it must be the same regular file, by device and inode
  number, that was listed). This detects a file or folder being swapped for a
  link while the scan runs. File size, file count and directory depth are
  limited.

## Default exclusions and limits

Skipped by name anywhere in the tree: `.git`, `.hg`, `.svn`, `.venv`, `venv`,
`__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.nox`,
`.eggs`, `site-packages`, `node_modules`, `bower_components`, `vendor`,
`.terraform`, `build`, `dist`, `.next`, `.nuxt`, `.gradle`, `coverage`,
`htmlcov`, `.reposentinel`, `*.egg-info`, plus any directory containing a
`pyvenv.cfg` (a Python virtual environment) and files named
`reposentinel-report*`.

Limits: 1 MiB per file, 50,000 in-scope files and 64 directory levels. Excluded
directories are listed by name in the **Coverage** section, and oversized,
binary and linked paths are counted there. Unreadable or unparseable files,
files that changed during the scan, and reached limits make the scan
**incomplete**. Entries that are skipped do not count towards the file limit,
so a folder containing a very large number of skipped entries is still listed
in full.

Exclusions are by name, so they can hide files: a folder called `build` or
`vendor`, or any folder containing a `pyvenv.cfg` file, is not scanned even if
it holds hand-written code. Check the **Excluded** list in the report.

## Known limitations and false positives

* **Not a full secret scanner.** Only five credential formats are recognised.
  Many real secrets (other cloud providers, API keys without a distinctive
  prefix, passwords in arbitrary variables) are not detected. Use Gitleaks or
  a similar tool for broad coverage.
* **Current files only.** A secret that was committed and later deleted is
  still in Git history; RepoSentinel will not find it.
* **Test fixtures and documentation** commonly trigger the key and token rules.
  Values containing `EXAMPLE` (AWS documentation keys), tokens whose random
  part is one repeated character (`ghp_xxxx...`), and obvious URL password
  placeholders are ignored, which can also hide a real value that happens to
  look like a placeholder.
* **`.env` detection** cannot tell whether a file is tracked by Git. Only the
  root `.gitignore` is consulted, with simplified matching, to lower the
  severity of files that are probably local.
* **GitHub Actions rules** are pattern checks, not a full analysis. They
  recognise a fixed list of untrusted contexts and only literal patterns; they
  do not follow data through environment variables, step outputs or
  composite actions, and they do not evaluate who can trigger a workflow.
  Expressions that can only produce `true`/`false` are not reported.
* **Encodings.** UTF-8 and UTF-16 (with a byte-order mark) are decoded; other
  encodings are read as UTF-8 with replacement characters. Files with NUL
  bytes are treated as binary and not scanned.
* **Symbolic links are skipped, not followed**, so content reachable only
  through a link is not scanned.
* **Remaining file-system caveats.** A narrow race remains between a
  directory's last check and its listing. Hard links are ordinary files and
  are read, so a hard link to a file outside the folder is scanned like any
  other file. On Windows, reading a OneDrive "online-only" file makes Windows
  download it. Some file systems do not report file identities (inode 0), and
  the swap check is then skipped for those files.

## Optional Gitleaks integration

> **Tested with Gitleaks 8.30.1** on Windows, Linux and macOS, using official,
> checksum-verified releases (see [docs/integrations.md](docs/integrations.md)).
> Other releases from 8.19.0 on are accepted but untested. A `.gitleaksignore`
> file inside the scanned repository can still hide Gitleaks results in some
> situations (see "Known gaps" there); RepoSentinel's native rules are not
> affected. The check appears in reports as "Gitleaks secret scan".

`--integration gitleaks` runs a locally installed
[Gitleaks](https://github.com/gitleaks/gitleaks) (MIT licence) in directory
mode and imports its results as `gitleaks:<rule>` findings. RepoSentinel never
downloads it; if it is not on `PATH` the check is reported as *skipped* and the
scan as incomplete (exit code 3).

RepoSentinel runs `gitleaks version` first. Releases older than 8.19.0 (which
lack the `dir` command) make the check *skipped*.

How it is tested:

* **Real Gitleaks 8.30.1:** `tests/test_gitleaks_real.py` runs the official,
  checksum-verified 8.30.1 release (fetched by `scripts/fetch_gitleaks.py`) on
  Windows, Linux and macOS. It checks relative paths, line numbers (also with
  CRLF), that secrets stay redacted, that `gitleaks:allow` comments and the
  scanned repository's own `.gitleaks.toml` are ignored, that a `gitleaks`
  copy inside the scanned folder is never run, and the `.gitleaksignore`
  behaviour. The CI job `gitleaks` repeats these tests on all three systems
  for every change; it is not a required check.
* **Other releases:** releases from 8.19.0 on are accepted, but only 8.30.1
  has been tested. Without a real Gitleaks, the rest of the test suite uses a
  simulated one.

See [docs/integrations.md](docs/integrations.md) for the exact command line,
the security reasoning behind each flag, how to verify another release, and
why OSV-Scanner and Zizmor are not integrated yet.

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest                  # tests
.\.venv\Scripts\python.exe scripts\repeat_tests.py --runs 10 --out <folder>  # flakiness check
.\.venv\Scripts\python.exe -m ruff check .            # lint (includes bandit security rules)
.\.venv\Scripts\python.exe -m ruff format --check .   # formatting
.\.venv\Scripts\python.exe -m mypy                    # strict type checking
.\.venv\Scripts\python.exe scripts\generate_rules_doc.py   # after changing a rule
```

**Release builds** need Node.js 22.12+ and the release tools. The script builds
the web interface first, then the sdist and wheel (the sdist carries the
built interface, so a wheel built from it does not need Node.js), then runs
`twine check --strict` and `scripts/check_dist.py`:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[release]"
.\.venv\Scripts\python.exe scripts\build_release.py --outdir dist
```

To test an installed wheel, install it into a new virtual environment and
run `scripts/smoke_installed.py` with that environment's Python (from any
folder); it checks the CLI, all report formats, comparison exit codes and the
web interface.

Tests build every repository in a temporary directory and assemble fake
credentials at run time (`tests/synthetic.py`); no real credential is ever
used. A self-scan test checks that RepoSentinel's own source tree triggers no
rule, and an offline test makes every network call fail during a full scan.

Symbolic-link tests are skipped on Windows unless Developer Mode (or the
symlink privilege) is enabled; do not change system settings just for them.
The equivalent junction tests run on Windows without it. On Linux, where no
privilege is needed, CI sets `REPOSENTINEL_REQUIRE_SYMLINK_TESTS=1` so that a
symbolic-link test that cannot create its link fails instead of being skipped.

### Continuous integration

`.github/workflows/ci.yml` runs on every push to `main`/`master` and on every
pull request:

* **test**: Ubuntu, Windows and macOS on Python 3.12, 3.13 and 3.14: ruff
  (lint and formatting), strict mypy, pytest (symbolic-link tests are
  required on Linux), the rules-reference check and a RepoSentinel scan of
  this repository. On Ubuntu and Windows it also runs the tests of the
  publish workflow (`.github/workflow-tests/`).
* **frontend**: TypeScript check and production build of the web interface.
* **package**: a wheel without the web interface (every command but `ui` must
  work), then the release build (`twine check --strict`, `scripts/check_dist.py`),
  each installed into a fresh environment and smoke-tested.
* **browser**: the end-to-end test in the runner's Google Chrome.
* **browser-firefox**: the same end-to-end test in Firefox.
* **sarif**: SARIF output validated against the official schema.
* **gitleaks**: the real-Gitleaks tests on Ubuntu, Windows and macOS (see
  [Optional Gitleaks integration](#optional-gitleaks-integration)).
* **minimum-dependencies**: the tests against the lowest declared versions.
* **reference-build**: rebuilds the 0.1.0 release commit in the pinned
  release build environment and fails unless both archives have exactly
  the published SHA-256 values (see [docs/releasing.md](docs/releasing.md)).

The token can only read the repository, actions are pinned to full commit
SHAs, and no secrets are used. The macOS jobs, `browser-firefox`, `gitleaks`
and `reference-build` are not required checks; GitHub's macOS runners are
sometimes unavailable, and such a job is then cancelled without running.

Releases are published to PyPI by a separate, hand-started workflow,
`.github/workflows/publish.yml`; see [docs/releasing.md](docs/releasing.md).

Project layout:

```text
src/reposentinel/
  cli.py             command line (Typer)
  engine.py          runs checks in isolation, builds the report, exit codes
  models.py          Finding, Rule, CheckResult, ScanReport, ...
  webui/             optional local web interface: server.py (security
                     boundary), api.py (operations), static/ (generated build)
  identity.py        tracked-finding fingerprints
  history.py         local projects and scan history (SQLite, web interface only)
  demo.py            the synthetic demo repository
  report_loader.py   strict loading of saved JSON reports (for compare)
  compare.py         the comparison rules, independent of any output format
  walker.py          safe file inventory
  context.py         read-only file access for checks
  redact.py          secret masking and display sanitising
  checks/            hygiene.py, secrets.py, workflows.py (+ base.py interface)
  integrations/      process.py (safe subprocess), gitleaks.py
  reporting/         terminal.py, json_report.py, html_report.py, templates/,
                     sarif.py, compare_terminal.py, compare_json.py, compare_html.py
tests/               pytest suite
frontend/            web interface source (React, TypeScript, Vite) and e2e test
scripts/             release build, package checks, SARIF validation, demo and docs generators
docs/                architecture, rules, web interface, SARIF, integrations, research, releasing
.github/             CI and publish workflows, the release build action, Dependabot,
                     issue and pull-request templates
SECURITY.md          how to report a vulnerability privately
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit
together and how to add a rule.

## Roadmap

Done for 0.1.0:

* Hosted CI on every change (Ubuntu, Windows and macOS; see
  [Continuous integration](#continuous-integration)).
* The Gitleaks adapter tested against a real, checksum-verified Gitleaks
  release (8.30.1).
* Publication on PyPI as
  [`reposentinel-scanner`](https://pypi.org/project/reposentinel-scanner/),
  with trusted publishing.

Planned, **not implemented** (details and prerequisites in
[docs/feature-research.md](docs/feature-research.md)):

1. A usability session with developers who have not seen RepoSentinel.
2. Git-history secret scanning, read-only and without running Git (the next
   major capability).
3. Finding decisions (false positive, accepted risk with expiry) that never
   hide a finding without a visible record.
4. Importing other scanners' SARIF files; then optional offline dependency
   auditing with OSV-Scanner.
5. More GitHub Actions rules, or a Zizmor integration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md).
Bug reports with synthetic examples, documentation fixes and pull requests are
welcome. Contributions are accepted under the MIT License.

## Reporting a security problem

Please do not open a public issue; follow [SECURITY.md](SECURITY.md).

## License

RepoSentinel is released under the [MIT License](LICENSE).
Copyright (c) 2026 ItzMeVishwas.

RepoSentinel's Python dependencies (Typer, Rich, PyYAML, Jinja2) have their
own licenses and are installed separately. The built web interface includes
React, ReactDOM and Scheduler (MIT); their license texts are shipped in
[`src/reposentinel/webui/THIRD_PARTY_LICENSES.txt`](src/reposentinel/webui/THIRD_PARTY_LICENSES.txt).
