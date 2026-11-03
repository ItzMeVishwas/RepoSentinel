# Changelog

All notable changes to RepoSentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
semantic versioning once a release is published.

## [Unreleased] - 0.1.0 (first public release, not yet published)

Nothing has been released yet. This entry describes the state prepared for
the first release.

### Command line

* `reposentinel scan PATH`: 12 native rules for risky files, hard-coded
  credential patterns and unsafe GitHub Actions workflows; text, JSON
  (schema 1.1), standalone HTML and SARIF 2.1.0 reports; coverage per check;
  exit codes 0, 1, 2 and 3.
* `reposentinel compare OLD.json NEW.json`: conservative comparison of two
  saved reports (still detected, new, no longer detected on re-check, not
  re-checked, not comparable), in text, JSON or HTML.
* `reposentinel ui`: the optional local web interface (see below).
* `reposentinel demo FOLDER`: creates a synthetic repository with fake
  credentials that triggers every rule.
* `reposentinel rules`: the rule catalogue.
* Experimental Gitleaks integration (`--integration gitleaks`), not yet
  verified against a real Gitleaks binary.

### Local web interface

* Served on 127.0.0.1 only, with a one-time launch link, an in-memory bearer
  token (no cookies or browser storage), Host and Origin checks and a strict
  Content-Security-Policy.
* Registered projects with opt-in scan history in a local SQLite database
  outside scanned projects; one-click "scan again and compare"; "detected
  again" for findings that return; history timeline; comparison of any two
  saved scans; JSON, HTML and SARIF downloads; deletion of one scan, one
  project's history, or all local data.
* Redesigned console: overview, projects, scan, findings explorer (search,
  filters, sorting, grouping by file, keyboard navigation, detail panel),
  history, compare, reports and settings; a synthetic demo project for first
  use; WCAG 2.2 AA as the design and test target.

### Security hardening

* Repository text is never copied into findings; secrets are redacted twice;
  file identity is re-checked to resist link swaps during a scan; hostile
  file names are neutralised in every output.
* The GitHub Actions check no longer analyses a workflow whose YAML aliases
  repeat its parts far more often than ordinary reuse (or form a cycle); it is
  reported as not analysed instead. Before, a small file with nested aliases
  could keep a scan busy for minutes and use hundreds of megabytes.
* `reposentinel demo` creates every folder and file itself with exclusive
  file creation, so it never overwrites or truncates an existing file, even
  if another user plants a file or link in the target folder while it runs
  (before, a planted link could redirect its writes and overwrite a file
  elsewhere). Remaining limitation: a link that replaces a folder the demo
  has just created can still redirect the creation of new demo files and
  folders into another folder, and the demo does not detect this.

### Project

* Released under the MIT License.
* The local server answers malformed requests and unsupported HTTP methods
  with the same security headers as every other response (405 with an
  `Allow` header for unsupported methods), never echoing request text.

### Known limitations

* Git history and dependencies are not scanned.
* On macOS only the automated Python tests run (in CI). Firefox, Safari and
  screen readers are not verified, and no external user has validated the
  product.

### Fixed after the first CI runs

* Type checking on Linux and macOS (Windows-only test helpers), tests that
  depended on the terminal width or the temporary-folder path, and the missing
  web interface build in CI test jobs.
* Python 3.12: error responses to malformed requests were sent without a status
  line or security headers; HTTP/0.9 requests are now refused.
* Web interface: pages showed "nothing yet" (or the first-run welcome) while
  their data was still loading; they now say that they are loading. Resizing a
  window to phone width no longer animates the sidebar across the page.
