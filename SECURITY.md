# Security policy

## Reporting a vulnerability in RepoSentinel

Please do **not** open a public issue for a security problem in RepoSentinel
itself. Examples:

* a way to make it print or save a secret it has matched;
* a way to make it read files outside the folder being scanned;
* a way to make it execute code from a scanned repository;
* a report that can run script or load remote content in a browser.
* a way for another website or local program to use the local web interface
  (`reposentinel ui`) or read its data (see `docs/webui.md`, "Security model").

Report it privately with GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. If that
option is not available, open an issue that says only that you have a security
report and asks the maintainer ([@ItzMeVishwas](https://github.com/ItzMeVishwas))
for a private channel. Do not include any details in the issue.

Please include the RepoSentinel version (`python -m reposentinel --version`),
your operating system and Python version, the exact command you ran, and a
minimal *synthetic* repository that reproduces the problem. Never include
real credentials.

This is a volunteer, alpha-stage project: there is no bug bounty, and
responses are best effort.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (alpha) | Yes |

## What is not a vulnerability

* **Missed or extra detections.** False negatives and false positives of the
  rules are documented limitations (see `docs/rules.md`). Please open a
  normal issue, with synthetic examples.
* **Problems in other tools.** Report vulnerabilities in Gitleaks or other
  third-party tools to those projects. RepoSentinel's Gitleaks integration
  and its known gaps are described in `docs/integrations.md`.
