# SARIF export

RepoSentinel can write a scan report in SARIF 2.1.0 (OASIS Static Analysis
Results Interchange Format), the format code-scanning tools such as GitHub
code scanning read.

```
reposentinel scan PATH --format sarif --output reposentinel.sarif
```

The web interface offers the same file as "Download SARIF" for the open scan
and for any saved scan (Reports page). `reposentinel compare` does not write
SARIF: a comparison is not a list of results, so `compare --format sarif` is
refused with a usage error (exit code 2).

RepoSentinel never uploads anything. Uploading a SARIF file to GitHub (for
example with the `github/codeql-action/upload-sarif` action, or the REST API)
is a separate step you choose to take; it needs no RepoSentinel account and
RepoSentinel does not need a GitHub account.

## What the file contains

One run, with:

| SARIF property | RepoSentinel value |
|---|---|
| `$schema`, `version` | the OASIS 2.1.0 (errata 01) schema URL, `"2.1.0"` |
| `tool.driver` | `name: "RepoSentinel"`, `version` and `semanticVersion` |
| `tool.driver.rules` | every native rule of the checks that ran (id, title, description, help with remediation and limitations, default level, `security-severity`, precision, rule version), then any integration rule that reported a finding |
| `results[]` | one per finding: `ruleId`, `ruleIndex`, `level`, `message.text` (the finding's summary), one location, `partialFingerprints`, and properties (`confidence`, redacted `evidence`, `security-severity`) |
| `invocations[0]` | `executionSuccessful`, one notification per failed or skipped check, a warning when files could not be examined, `endTimeUtc` |
| `originalUriBaseIds` | `%SRCROOT%`, with a description only |
| `properties.reposentinel` | outcome, scope statement, disclaimer, files in scope, coverage counts, check statuses |

### Severity mapping

| RepoSentinel severity | SARIF `level` | `security-severity` | GitHub shows |
|---|---|---|---|
| high | `error` | `"8.0"` | High |
| medium | `warning` | `"5.5"` | Medium |
| low | `note` | `"3.0"` | Low |
| info | `note` | `"0.0"` | None |

GitHub documents `security-severity` as a string score: above 9.0 critical,
7.0 to 8.9 high, 4.0 to 6.9 medium, 0.1 to 3.9 low, 0.0 none. RepoSentinel has
no "critical" severity, so no result is shown as critical.

### Locations

Locations are relative paths under the base id `%SRCROOT%`, percent-encoded
as URI references (for example `dir%20with%20space/file.env`). The absolute
path of the scanned folder is not exported, because it often contains a user
name. A finding without a file (a whole-repository finding) has no location.
Line numbers are 1-based (`region.startLine`); RepoSentinel does not report
columns.

### Incomplete scans

An incomplete scan (a check failed or was skipped, or files could not be
read) is exported with `invocations[0].executionSuccessful: false` and a
notification explaining each problem, and `properties.reposentinel.outcome`
is `"incomplete"`. A consumer must not read an incomplete run as "nothing
found".

## What it never contains

- File contents, code snippets (`snippet`, `contextRegion`) or matched text.
  A result carries only RepoSentinel's own summary and the already-redacted
  evidence, the same text as the JSON report.
- Secret values (they are redacted before any report is rendered).
- The absolute scanned folder, file hashes or content hashes.

`partialFingerprints` holds RepoSentinel's tracked-finding fingerprint
(`reposentinelFingerprint/v1`, a SHA-256 of non-secret identity inputs; see
`identity.py`). RepoSentinel does not compute GitHub's
`primaryLocationLineHash`, which is derived from file contents; GitHub's
upload action computes it when it is missing.

## Validation status

### Schema validity: verified locally (2026-10-31)

`scripts/validate_sarif.py` produces SARIF with the real command line for six
synthetic repositories (an empty folder, a clean project, the demo repository
that triggers all 12 rules, repeated credentials, unusual file names, and an
incomplete scan) and validates every file against the official OASIS schema:

* schema: `sarif-schema-2.1.0.json`, errata 01
  (`https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`),
  SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`;
  the script refuses a schema file with any other hash;
* validator: `jsonschema` 4.25.1 (Draft 4 validator, as the schema declares),
  installed only for this check; it is not a RepoSentinel dependency;
* a self-test first proves the validator rejects a deliberately invalid log;
* result: all six files are valid, with no schema errors; none contains a
  synthetic secret, the absolute scanned folder, a snippet or non-ASCII text;
  the incomplete scan has `executionSuccessful: false`.

```bash
python -m pip install "jsonschema==4.25.1"
curl -L -o sarif-schema-2.1.0.json https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
python scripts/validate_sarif.py --schema sarif-schema-2.1.0.json
```

The CI workflow runs the same check (job `sarif`). Format-specific keywords
such as `uri` are only checked when the validator has the optional format
packages; structure, required properties, enumerations and value ranges are
always checked. `tests/test_sarif.py` additionally checks the mapping, the
consistency of `ruleIndex` and `ruleId`, relative URIs and redaction without
the schema.

### GitHub code scanning: reviewed against the documentation, not tested

Nothing has been uploaded to GitHub. Against GitHub's "SARIF support for code
scanning" page (read 2026-10-31), the script reports:

* **Met:** `$schema` and version 2.1.0; one run; `tool.driver.name` and
  `rules`; every rule has `id`, `shortDescription.text`,
  `fullDescription.text` and `help.text`; `name` under 255 characters; at most
  20 tags; `precision` and `security-severity` in the documented forms; every
  result has `message.text` and exactly one location with a relative URI;
  counts far below GitHub's limits.
* **Difference: file-level findings have no line.** Findings about a file as
  a whole (for example "a `.git-credentials` file is present") have a location
  without `region.startLine`. The SARIF schema allows that; GitHub's table
  lists `startLine` as required, so GitHub may not display such a result or
  may reject it. RepoSentinel does not invent a line number.
* **Difference: no `primaryLocationLineHash`.** RepoSentinel writes its own
  fingerprint (`reposentinelFingerprint/v1`); GitHub uses only
  `primaryLocationLineHash`, which the `upload-sarif` action computes from the
  file contents. An upload through the REST API without it may show duplicate
  alerts across runs.
* **Shared fingerprints.** Occurrences of one tracked finding (the same
  credential repeated in a file) share the RepoSentinel fingerprint, by design;
  each is still its own result.

Whether GitHub accepts and displays these files is **unverified** until an
authorised test upload to a repository the maintainer controls.
