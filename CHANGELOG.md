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

### Project

* Released under the MIT License.
* The local server answers malformed requests and unsupported HTTP methods
  with the same security headers as every other response (405 with an
  `Allow` header for unsupported methods), never echoing request text.

### Known limitations

* Git history and dependencies are not scanned.
* Hosted CI has not run yet; Linux, macOS, Firefox, Safari and screen readers
  are not verified; no external user has validated the product.
