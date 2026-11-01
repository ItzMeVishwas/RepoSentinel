# RepoSentinel architecture

RepoSentinel is a pipeline with one direction of data flow. Each stage has a
single job, and every stage after the walker works only with RepoSentinel's
own data types, never with raw repository content it has not checked.

```text
 reposentinel scan PATH
          |
          v
 +-----------------+   validate PATH and options; exit 2 on a usage error
 | cli.py          |
 +-----------------+
          |
          v
 +-----------------+   collect_files(): safe, sorted file list + coverage issues
 | walker.py       |   (exclusions, no links, size/count/depth limits)
 +-----------------+
          |
          v
 +-----------------+   ScanContext: read-only access to the listed files
 | context.py      |   (size re-check, binary/UTF-16 detection, unreadable files)
 +-----------------+
          |
          v
 +-----------------+   run each Check in isolation -> CheckResult + Findings
 | engine.py       |   de-duplicate, sort, decide the Outcome and exit code
 +-----------------+
     |    |    |
     v    v    v
 hygiene secrets workflows  (+ optional integrations, e.g. gitleaks)
          |
          v
 +-----------------+   ScanReport (frozen) -> terminal / JSON / HTML
 | reporting/      |
 +-----------------+
```

`compare` is a second, separate pipeline. It never touches a repository:

```text
 reposentinel compare OLD.json NEW.json
          |
          v
 +------------------+   bounded, strict loading of each JSON report (schema 1.1)
 | report_loader.py |   -> ScanReport; any problem is exit 2 with no output
 +------------------+
          |
          v
 +------------------+   pure function: two ScanReports -> ComparisonResult
 | compare.py       |   (statuses, reasons, summary, exit-code precedence)
 +------------------+
          |
          v
 +------------------+   compare_terminal / compare_json / compare_html
 | reporting/       |
 +------------------+
```

## Command line (`cli.py`)

Built with Typer. `scan` validates the path (exists, is a directory, can be
listed) and the output location before any scanning starts, so usage problems
are reported immediately with exit code 2. It then builds the list of checks,
runs the engine, renders the chosen format, and exits with the code the engine
computes.

Two safety details live here. Typer's "pretty exceptions" are disabled, because
they print local variables that could contain file contents. Any unexpected
error is caught and reported as one sanitised line with exit code 3.

## File inventory (`walker.py`) and file access (`context.py`)

`collect_files` walks the tree with an explicit stack, sorting entries so the
result is identical on every run. It never follows symbolic links or Windows
junctions. On Windows, `DirEntry.is_symlink()` is **False** for a junction, so
`is_junction()` is checked explicitly. As a second safeguard, it refuses any
directory whose resolved path leaves the root, and it checks each directory
again immediately before listing it, in case it was replaced by a link after
its parent was listed. For every file it records the device and inode number
from `os.lstat` (on Windows, `DirEntry.stat()` reports zero for both).
Everything it skips is recorded as a `CoverageIssue` with a reason, so the
report can say exactly what was not scanned.

Checks never open files themselves. `ScanContext.read_text` opens with
`O_NOFOLLOW` and `O_NONBLOCK` where the platform supports them. It then uses
`fstat` to confirm that the open handle is a regular file with the same device
and inode number recorded at listing time. Windows has no `O_NOFOLLOW`, so this
is what stops a file, or a parent folder swapped for a junction, being read
from outside the root. It also enforces the size limit again (a file may grow
after listing), decodes UTF-8 or UTF-16 (BOM), treats NUL bytes as binary, and
records read errors. Unreadable, changed or unparseable files are *errors*
that make the scan incomplete; excluded, oversized, binary and linked paths
are *policy skips* that are reported but do not.

## Checks (`checks/`)

A check is a class implementing `checks.base.Check`:

```python
class Check(abc.ABC):
    id: ClassVar[str]  # stable, e.g. "secrets"
    name: ClassVar[str]  # shown in reports
    rules: ClassVar[tuple[Rule, ...]]  # every rule it can report

    def run(self, context: ScanContext) -> CheckOutput: ...
```

`run` returns a `CheckOutput` (findings, number of items examined, the exact
paths it examined, optional note) or raises `CheckSkipped` when it cannot run
(for example, a tool is not installed). The helper `Check.finding(rule, ...)`
fills a finding from the rule's defaults, records the rule version, and
refuses rules the check did not declare.

`examined_paths` is what lets `compare` say "not detected on re-check": only a
file listed there counts as re-checked. A check that leaves it as `None` (the
Gitleaks integration does) can never produce that status. A file is listed
only if the check really looked at it: the secrets check lists files it could
read as text, and the workflow check lists workflow files that parsed (empty,
or a mapping); an unparseable workflow is not listed.

`Check.finding(..., identity=...)` takes the rule-specific fingerprint inputs:

| Rule | Identity inputs (besides rule ID and path) |
|---|---|
| RS-HYG-001 to 003, RS-SEC-002 to 005 | none |
| RS-SEC-001 | `key_type=` the key type from the rule's fixed list (RSA, OPENSSH, ...; PKCS8 when unnamed) |
| RS-GHA-001 | `job=` job ID, `context=` the matched context with any index normalised to `[*]`, `sink=run` or `sink=github-script` |
| RS-GHA-002 | `job=` job ID |
| RS-GHA-003 | `action=` the action's `owner/repo`, lower case |
| RS-GHA-004 | `scope=workflow` or `job=` job ID |
| `gitleaks:*` | none |

Only RepoSentinel vocabulary and structural identifiers are allowed; never a
secret value, an expression, a script, a step name or file content.
`identity.fingerprint` redacts every input with the credential patterns,
normalises it to Unicode NFC and hashes a canonical JSON array with SHA-256
(`rs1:` prefix). Every finding of one tracked finding shares one fingerprint;
line numbers are not inputs, so inserted lines do not change it.

Each `Rule` also has a `version` (increase it whenever matching changes; the
comparison then reports "Not comparable") and `recheck_limits`, the text shown
with "Not detected on re-check".

| Check | File | Rules |
|---|---|---|
| `hygiene` | `checks/hygiene.py` | RS-HYG-001 to 003 (file names) |
| `secrets` | `checks/secrets.py` | RS-SEC-001 to 005 (line-by-line regular expressions) |
| `github-actions` | `checks/workflows.py` | RS-GHA-001 to 004 (YAML node tree) |

The workflow check parses YAML with `yaml.compose(..., Loader=SafeLoader)`.
This produces a node tree rather than Python objects. Nodes carry line numbers,
the key `on` stays a string (YAML 1.1 would otherwise read it as `True`),
aliases are shared nodes rather than copies, and nothing is ever constructed or
executed. Deeply nested YAML that exhausts PyYAML's recursion is recorded as
unparseable instead of crashing the scan.

### Adding a rule

1. Define a `Rule` next to the check that will report it. Choose the next free
   ID in its family and never reuse a retired one. Fill in every text field,
   including honest limitations and `recheck_limits`.
2. Add it to that module's `RULES` tuple and emit it with `self.finding(...)`.
   Redact any secret **before** calling `finding`. Pass `identity=` only if
   path and rule ID are not enough, using the allowed inputs above, and list
   them in the table above.
3. When you change how an existing rule matches, increase its `version`.
4. Add positive and negative tests using values built at run time.
5. Run `python scripts/generate_rules_doc.py` and add the rule to the README
   table (a test checks both).

## Finding model (`models.py`)

All types are frozen dataclasses, so nothing downstream can change a finding
after it is created.

* `Finding` holds `rule_id`, `title`, `severity`, `confidence`, `summary`,
  `evidence` (always redacted), `remediation`, `check_id`, and an optional
  `path` (POSIX-style, relative to the root) and 1-based `line`. Invalid
  combinations, such as a line without a path, raise `ValueError`.
* `Severity`: `high`, `medium`, `low`, `info`. `Confidence`: `high`,
  `medium`, `low`.
* `CheckResult` records each check's `status` (`completed`, `failed`,
  `skipped`), its finding count, how much it examined (`None` when unknown),
  and a note or sanitised error.
* `ScanReport` combines everything and derives the `Outcome`:
  * **incomplete** if there are no checks, any check did not complete, or any
    coverage error exists;
  * otherwise **findings** if there is at least one finding;
  * otherwise **clean**.

## Engine (`engine.py`)

`run_scan` builds the inventory and context, then runs each check inside its
own `try`. A `CheckSkipped` becomes a *skipped* result. Any other exception
becomes a *failed* result and the remaining checks still run. The failed
result shows only the exception's type (and an operating-system error's own
description), because an exception message can quote the file content being
processed. A `models.CheckError` (such as the Gitleaks adapter's
`IntegrationError`) is the exception: its message is written entirely by
RepoSentinel, so it is shown, redacted and sanitised.

Every finding's title, summary, evidence and remediation, every check
message, and every coverage detail then passes through `redact_known_secrets`
(`redact_finding`). This is a second safeguard: checks already mask what
they match, and they build summaries and evidence only from RepoSentinel
vocabulary, positions and line numbers (workflow findings say "Job 2, step 3"
rather than quoting a job ID or step name), because no pattern list can
recognise every credential in free repository text. Having one place
that every check and integration passes through means a new check cannot
forget this step. Findings are de-duplicated by (rule, path, line, evidence) and
sorted by severity, path, line and rule. The engine then computes each
finding's fingerprint and drops the raw identity inputs, so they never reach a
report, and records `ScanReport.files` (every in-scope path) and `scan_config`
(checks requested, rule versions, limits and default exclusion lists).

`exit_code_for(report, fail_on)` implements the exit-code policy: 3 if the
outcome is incomplete, otherwise 1 if any finding is at or above `fail_on`,
otherwise 0. The CLI uses 2 for usage errors.

## Reports (`reporting/`)

Renderers only read a `ScanReport`.

* **Terminal** (`terminal.py`, Rich): findings grouped by severity, a "How to
  fix" section with each rule's remediation once, then checks, coverage and a
  summary. Repository text is always wrapped in `rich.text.Text` (never parsed
  as markup) and passed through `redact.sanitize_text`, which replaces every
  character Python does not consider printable (controls, bidirectional and
  zero-width format characters, separators, surrogates, private-use and
  unassigned code points) with a visible escape such as `\u200b`.
* **JSON** (`json_report.py`): versioned by `schema_version`, keys in fixed
  order, ASCII-only output (`ensure_ascii`), deterministic apart from
  `scanned_at`. Lone surrogates are written as visible escape text so every
  string is valid Unicode.
* **HTML** (`html_report.py` + `templates/report.html.j2`): Jinja2 with
  autoescaping for the whole template, inline CSS, no JavaScript, no external
  resources, a `Content-Security-Policy` meta tag of `default-src 'none';
  style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`, and no link
  built from repository data. A meta tag is the only way a local file can carry
  a policy. If reports are ever served over HTTP, the server should send the
  same policy as a header.
* All three formats show the same caveats (`reporting/common.report_notes`,
  for example when no files were in scope). Terminal and HTML list the
  excluded directories by name.
* The comparison renderers (`compare_terminal.py`, `compare_json.py`,
  `compare_html.py` + `templates/compare.html.j2`) follow the same rules. The
  HTML pages share their security meta tags (CSP, referrer policy) through
  `templates/_security_meta.html.j2`, and the comparison page uses the same
  Jinja environment (`html_report.template_environment`). Shared wording and
  section names are in `reporting/compare_common.py`; every format lists every
  section, even when it is empty.

## Local web interface (`webui/`, `frontend/`)

`reposentinel ui` starts `webui.server` on 127.0.0.1. The browser page (React,
built into `webui/static/`) calls POST operations in `webui.api` (scan,
compare, exports, and the projects, history and local-data operations), which
call `engine.run_scan`, `history.HistoryStore`, `report_loader` and
`compare.compare_reports`, and the existing renderers for downloads. Two
operations support onboarding: `activity` (the newest saved scans of all
projects) and `demo/create`, which writes `demo.build_files()` into a new
folder created by `tempfile.mkdtemp` (never a path from the request) and
registers it as a project. The same synthetic repository is available as
`reposentinel demo FOLDER`. The page
displays those results and computes nothing itself. Strings sent for display
pass through `redact.sanitize_text`. The server uses only the Python standard
library, and `cli.py` imports it only inside the `ui` command, so the other
commands never load it. The session credential is a bearer token that the
page holds in memory and sends in an `Authorization` header; no cookie is
used, because browsers do not isolate cookies by port (RFC 6265, section 8.5).
The security model is in [webui.md](webui.md).

## Local history (`history.py`)

`HistoryStore` keeps registered projects and their saved scans in one SQLite
database (the standard library's `sqlite3`) in the per-user data folder
(`history.default_data_dir()`, overridden by `REPOSENTINEL_DATA_DIR` or
`reposentinel ui --data-dir`). Only the web interface uses it; the command
line never reads or writes history.

* **Schema (version 1).** `meta` (the schema version), `projects` (name,
  resolved path, a case-normalised path key that is unique, creation time),
  `scans` (summary columns plus the full JSON report, cascading on project
  deletion) and `scan_fingerprints` (one row per tracked finding, for
  "detected again" queries). A database with another schema version is
  refused and left unchanged; a future version must add an explicit,
  tested migration.
* **Writes.** Each operation is one transaction behind a lock. A
  `sqlite3.DatabaseError` becomes a `HistoryError` saying the database was
  not changed. Reading never creates the folder or the database.
* **Reads.** A stored report goes back through
  `report_loader.load_report_bytes`, so history is validated exactly like a
  report file. Comparisons between saved scans call `compare_reports` on two
  loaded reports; the browser computes nothing.
* **Placement.** `add_project`, `move_project` and `save_scan` refuse a
  project folder that contains the data folder or lies inside it, so history
  is never written into a scanned project.
* **Bounds.** 200 projects, 200 scans per project (oldest pruned), names of
  1 to 80 printable characters, paths up to 4096 characters, reports up to
  the loader's 64 MiB limit.

## SARIF export (`reporting/sarif.py`)

`report_to_sarif` maps a `ScanReport` to one SARIF 2.1.0 run: the rules of
the checks that ran, one result per finding with a relative `%SRCROOT%`
location, `invocations[0].executionSuccessful` false for an incomplete scan,
and RepoSentinel's outcome and scope as run properties. It reuses the
redacted finding text; it adds no snippets and no absolute paths. The
mapping is in [sarif.md](sarif.md).

## Comparison (`report_loader.py`, `compare.py`)

`report_loader.load_report` treats a report file as untrusted input: a regular
file of at most 64 MiB, strict UTF-8, JSON without `NaN`/`Infinity`, deep
nesting caught, exactly schema 1.1, every field type-checked, and internally
consistent (stated outcome, file count, rule versions and check list must
match). Free-text fields are redacted again. Error messages name the JSON
location but never quote a value, because redaction cannot recognise every
credential.

`compare.compare_reports(old, new)` is a pure function. Findings are grouped
into tracked findings by fingerprint. A tracked finding present in both is
"Still detected". One that is only in the new report is "New" if the old scan
examined that file with that check (or completely listed the folder without
it), otherwise "New (not examined before)". One that is only in the old
report is "Not detected on re-check" only if the new scan's owning check
completed, listed that file in `examined_paths`, has the same rule version,
and the scan limits and exclusion lists are unchanged. "Not detected: file
removed" needs the file to be absent from a complete listing (no limit
reached, no parent folder excluded, linked or unreadable). Every other case is
"Not re-checked" or "Not comparable", with the reason. The exit code follows
the fixed precedence 2 (invalid input, decided before comparing) > 3 (any
unknown) > 1 (still detected or new at the threshold) > 0.

## Integrations (`integrations/`)

An integration is a normal `Check`, so the engine isolates it and the reports
render it like any other check. `process.py` provides the safety layer:

* an executable lookup that ignores the current directory and relative `PATH`
  entries, rejects `PATH` folders and programs inside the scanned repository
  (even when they are links pointing elsewhere), and on Windows accepts only
  `.exe` files (not `.bat` or `.cmd`, which `cmd.exe` re-parses);
* a runner with no shell, closed standard input, a neutral temporary working
  directory, a timeout and truncated output.

`gitleaks.py` is the first adapter. The runner is injectable, so tests can
simulate Gitleaks without a binary. See [integrations.md](integrations.md).

## Key security decisions

| Decision | Reason |
|---|---|
| Never run Git in the target | Repository Git configuration (hooks, `core.fsmonitor`, diff drivers) can execute commands |
| Never follow links or junctions | Prevents reading outside the chosen directory and traversal loops |
| Redact before creating a finding, then again in the engine | Context text copied from the repository could itself contain a credential |
| Check file identity after opening | Detects a file or folder swapped for a link during the scan (Windows has no `O_NOFOLLOW`) |
| Escape all repository text on output, including invisible characters | File names and workflow text are attacker-controlled |
| `yaml.compose` with `SafeLoader` | No object construction, keeps line numbers, avoids the `on: True` quirk |
| Incomplete beats findings in the exit code | Missing results must never look like a pass |
| The web interface is an adapter, never a second engine | Statuses, findings and exit codes cannot diverge between the CLI and the browser |
| The local server checks Host, Origin, a bearer token (never a cookie) and a custom header on every API call | A website the user visits must not be able to use it (CSRF, DNS rebinding) |
| A comparison calls a finding "not detected" only with recorded evidence | A missing check, file or setting must never look like a fix; such cases are "not re-checked" or "not comparable" and give exit code 3 |
| Fingerprints use only RepoSentinel vocabulary and structural names, redacted | A fingerprint must never encode a secret, an expression or file content |
| Finding text never quotes free repository text (step names, job IDs, expressions, YAML values, tool output, exception messages) | Redaction patterns cannot recognise every credential; text that is not needed is not shown |
| No tracebacks to the user | Tracebacks can contain file contents |
| Custom executable lookup | `shutil.which` on Windows searches the current directory first |
