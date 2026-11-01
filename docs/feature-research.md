# RepoSentinel feature research and roadmap

> **Design document.** Research and roadmap notes written during RepoSentinel's
> development; the roadmap lists planned work that is **not implemented**.

Status: research and recommendation, 2026-10-28. Sources were read on that
date (links at the end, and next to each claim). Labels used below:

* **Verified**: stated in the cited official documentation.
* **Interpretation**: a conclusion drawn from verified facts.
* **Assumption**: plausible, not yet checked.
* **Needs user validation**: only real users can settle it. No external user
  has used RepoSentinel yet, so every claim about user value is in this group.

Nothing here claims a capability is unique to RepoSentinel. Not finding a
feature in another tool's documentation does not mean the tool lacks it.

## 1. The landscape in one page

| Tool or service | What it does (Verified) | Where it overlaps with RepoSentinel |
|---|---|---|
| GitHub secret scanning | "scans your entire Git history on all branches" for hard-coded credentials, plus issues, pull requests and wikis. Free and automatic for public repositories; organisation-owned private repositories need GitHub Secret Protection ([about secret scanning][gh-secret]) | Secret findings, but only **after** the code is on GitHub |
| GitHub push protection | Blocks pushes that contain secrets "before they reach your repository"; on by default for user accounts pushing to public repositories; repository-level protection is off by default and needs Secret Protection for private repositories ([push protection][gh-push]) | Prevents new leaks at push time; does not review what is already in history |
| GitHub code scanning (SARIF) | Turns third-party SARIF 2.1.0 into alerts; requires `version` 2.1.0, rules with descriptions, results with `message.text` and a location; uses `partialFingerprints.primaryLocationLineHash`, which the upload action can compute from source ([SARIF support][gh-sarif-support], [SARIF files][gh-sarif]) | A destination for RepoSentinel results |
| Semgrep | Finding states Open, Reviewing, To fix, Fixed, Ignored; "Fixed findings were detected in a previous scan but are no longer detected in the most recent scan of that same branch"; ignore reasons such as false positive and acceptable risk; findings can be reopened ([triage][semgrep]) | Lifecycle and re-scan comparison, in a hosted platform |
| Trivy `fs` | Vulnerability and secret scanning on by default, misconfiguration and licence scanning optional; vulnerabilities from lock files such as `package-lock.json` ([filesystem][trivy-fs]); downloads its databases unless told to skip, with documented air-gapped use ([air gap][trivy-airgap]) | Secrets in current files; dependency vulnerabilities |
| OSV-Scanner | Scans lockfiles and SBOMs (`scan source`, `-r` for recursive), skips git-ignored files by default ([source][osv-source]); `--offline` uses a local database and "won't ... send any project or dependency information anywhere", but "Commit level scanning is not supported" offline ([offline][osv-offline]) | Dependency vulnerabilities, with a real offline mode |
| Gitleaks | `git`, `dir` and `stdin` commands; `git` mode runs `git log -p` over history; reports in JSON, CSV, JUnit, SARIF; `--redact`; baselines. MIT licence. The README states the project is feature complete and receives only security patches ([gitleaks][gitleaks]) | Secrets in history and files (RepoSentinel already has an experimental adapter for `dir`) |
| zizmor | Static audits of GitHub Actions workflows and actions; offline mode with `--offline`; online audits need a GitHub token; SARIF output; findings mapped to exit codes 11-14 ([zizmor usage][zizmor]) | Much deeper workflow analysis than RepoSentinel's 4 rules |
| OWASP DevSecOps guideline | Run SAST, SCA and secret scanning on every pull request; "absence of findings is not evidence of absence of flaws"; "Treat a clean scan as the start of review, not the end" ([secure code review][owasp]) | Supports RepoSentinel's refusal to call a clean scan "secure" |

**Interpretation.** RepoSentinel cannot compete on detection breadth: Trivy,
OSV-Scanner, Gitleaks, zizmor and GitHub's own scanning each go far deeper in
their area. What remains open for a small local tool is the **workflow**:
keeping a project's scan history on the developer's machine, re-checking after
a fix with honest statuses, stating exactly what was and was not examined, and
handing results to the bigger tools in a standard format.

## 2. Opportunities, scored

Rubric (each 1 to 3, higher is better; effort and risk are scored so that
*low* effort or risk scores 3):

* **Value**: how directly it helps "Find it. Fix it. Re-check it." (Needs user validation.)
* **Fit**: how well it uses what exists (fingerprints, coverage, comparison).
* **Effort**: 3 = days, 1 = weeks or more.
* **Risk**: security and privacy risk introduced; 3 = low.
* **Test**: how well it can be tested offline and deterministically.
* **Now**: suitability for the current stage (no users, no CI run yet).

| # | Opportunity | Value | Fit | Effort | Risk | Test | Now | Total | Decision |
|---|---|---|---|---|---|---|---|---|---|
| 2 | One-click re-check and comparison against a previous scan | 3 | 3 | 3 | 3 | 3 | 3 | **18** | Build now (needs 1) |
| 3 | SARIF 2.1.0 export | 2 | 3 | 3 | 3 | 3 | 3 | **17** | Build now |
| 1 | Local project workspaces and scan history | 3 | 3 | 2 | 2 | 3 | 3 | **16** | Build now (prerequisite of 2) |
| 8 | Pre-publication coverage and readiness summary | 3 | 3 | 2 | 2 | 3 | 2 | **15** | Partly now (overview checklist); full report with item 4 |
| 7 | Finding lifecycle (recurrence, false-positive and accepted-risk decisions with expiry) | 3 | 2 | 2 | 2 | 3 | 2 | **14** | Recurrence now (derived from history); decisions next |
| 4 | Git-history secret scanning | 3 | 2 | 1 | 1 | 2 | 2 | **11** | Next major capability (section 3) |
| 6 | Optional integrations (Gitleaks, zizmor) | 2 | 2 | 2 | 2 | 1 | 1 | **10** | Later, through SARIF import |
| 5 | Dependency vulnerability scanning | 2 | 1 | 2 | 1 | 2 | 1 | **9** | Later, through OSV-Scanner offline + SARIF import |

Per opportunity:

1. **Workspaces and history.** Problem: today a user must save JSON files and
   remember which is which to see what changed. Value: the fix-and-re-check
   loop works without file handling. Differentiation: hosted platforms keep
   history (Semgrep, GitHub); a *local* history that never leaves the machine
   is the point here (Interpretation). Effort: moderate. Risk: stored paths and
   findings are sensitive, so storage must be local, explicit, deletable and
   contain only already-redacted reports. Dependencies: none (Python's
   built-in SQLite). Offline: fully. Testable: yes.
2. **One-click comparison.** Problem: the comparison engine exists but needs
   two files. Value: the core promise becomes one action. Effort: low once 1
   exists; reuses `compare.compare_reports`. Risk: low.
3. **SARIF export.** Problem: results cannot flow into GitHub code scanning
   or other SARIF consumers. Value: interoperability; lets users keep
   RepoSentinel results next to other tools' results. Differentiation: none
   (most scanners export SARIF), which is exactly why it matters. Effort: low.
   Risk: low if snippets are not exported and paths stay relative. Note: GitHub
   expects `partialFingerprints.primaryLocationLineHash` (computed by its upload
   action from file contents if missing); RepoSentinel will not compute
   content hashes itself (a deliberate privacy choice, product strategy 6.6).
4. **Git-history secret scanning.** See section 3.
5. **Dependency vulnerabilities.** Problem: vulnerable packages before
   publication. Value: real, but Trivy and OSV-Scanner already do this well
   (Verified), and doing it natively needs a vulnerability database that must
   be kept current. Risk: online lookups send package names and versions to a
   third party (OSV-Scanner's online mode; what exactly is sent is not stated
   on the pages read, so treat it as disclosed). See section 4.
6. **Integrations.** Each live integration needs a binary installed by the
   user, version pinning, output parsing and a test against the real tool
   (RepoSentinel's Gitleaks adapter is still unverified against a real binary).
   Gitleaks is now in maintenance mode (Verified). A generic **SARIF import**
   would let users bring results from any of these tools into the same history
   and comparison without RepoSentinel running them (Interpretation).
7. **Finding lifecycle.** Problem: the same false positive returns on every
   scan; accepted risks are never revisited. Value: high once history exists
   (Semgrep's states show the established model). Effort: moderate. Risk: a
   decision must never hide a finding silently; every decision needs a reason,
   an author note and an expiry. Recurrence ("detected again") needs only
   history and fingerprints, so it is built now.
8. **Readiness summary.** Problem: "can I publish this?" has no honest answer
   from a scanner. Value: a text-led checklist of what ran, what was not
   examined and what remains unknown (never a score, never "ready"). Built now
   as the overview checklist; a complete pre-publication report needs item 4.

## 3. Git-history secret scanning (recommended next major capability)

**Why it ranks first among the larger items.** The person about to make a
private repository public is exactly who needs it, and GitHub's own history
scanning only starts once the code is on GitHub (Verified: it scans "your
entire Git history"; free for public repositories). A secret in an old commit
is exposed the moment the repository is published (Interpretation).

**Feasible architectures.**

| Option | How | Pros | Cons and risks |
|---|---|---|---|
| A. Run `git` | `git log -p --all` (what Gitleaks does) | Complete, fast, handles packs and deltas | Repository configuration can make Git run commands (hooks, `core.fsmonitor`, diff and text-conversion drivers). RepoSentinel has deliberately never run Git in a scanned repository. Would need a hardened invocation (empty global and system config, `-c core.fsmonitor=`, no textconv, `--no-ext-diff`) and still trusts the installed Git |
| B. Pure-Python object reader | Read `.git` directly: loose objects (zlib), pack files and pack indexes, delta resolution | No code execution; full control of limits and of what is reported | Substantial work; pack and delta parsing must be bounded against malformed or hostile data (decompression bombs, delta chains, huge objects) |
| C. Library (for example Dulwich, pure Python) | Read objects through the library | Proven parser | A new dependency in the security-critical path; licence and maintenance review needed (Assumption: not yet reviewed) |
| D. Delegate | Ask the user to run Gitleaks `git` mode and import its SARIF | Nothing to parse | Gitleaks is in maintenance mode; RepoSentinel would only display results |

**Recommendation: B, as a separate, explicitly labelled check**, after a
time-boxed spike that compares B and C on real repositories. Prerequisites:

1. The conservative Git metadata reader already specified in the product
   strategy (section 8.5): `.git` must be a real directory inside the root (no
   `gitdir:` pointer, no link), bounded `HEAD` and ref parsing, explicit
   "unknown" results for linked worktrees, submodules, reftable and anything
   unsupported.
2. A bounded object reader: maximum object size, maximum total decompressed
   bytes, maximum delta-chain depth, maximum object count, a time budget, and
   "incomplete" (never "clean") when any limit is reached.
3. A coverage record for history: which refs were walked, how many commits and
   blobs were inspected, which objects were skipped and why. Without it,
   "no historical secrets found" would be an unsupported claim.
4. A distinct finding type ("present in history: commit X, path Y") that is
   never confused with a current-file finding, with its own comparison rules
   and the rotate-or-revoke reminder.
5. Tests with hostile fixtures: corrupt packs, delta loops, zip bombs, very
   large blobs, symbolic refs pointing outside `.git`, linked worktrees.

**What must not ship:** a check that reads only the current branch's latest
commit, or scans some objects silently, and still says history was scanned.

## 4. Dependency vulnerability auditing

**Recommendation: do not build a native vulnerability database client.**
Offer it later in two steps, both explicitly optional:

1. **SARIF import** (general, offline): the user runs OSV-Scanner or Trivy and
   RepoSentinel stores, compares and explains the imported results with
   clearly labelled tool provenance.
2. **Optional OSV-Scanner integration in offline mode only by default**:
   `--offline` with a local database the user downloaded themselves, so no
   package names leave the machine (Verified: offline mode sends no project or
   dependency information). Any online mode must be an explicit, per-run
   choice that says what will be sent.

Risks: stale local databases (show the database date), and the same
installation, version-pinning and real-binary testing costs as Gitleaks.

## 5. Complementary scanners and standards

* **SARIF import before more native rules.** One importer could cover
  several tools: Gitleaks and zizmor document SARIF output on the pages read
  (Verified); for Trivy, OSV-Scanner and Semgrep the pages read did not cover
  output formats, so their SARIF support is an Assumption to check before
  building. It keeps RepoSentinel's value (history, honest comparison,
  coverage statements) without running third-party binaries. Imported results
  must be treated as untrusted input, like reports today.
* **zizmor** is a better source of workflow findings than more native
  `RS-GHA` rules; its offline mode fits RepoSentinel's model. Integrate only
  through import until a live integration can be tested in CI.
* **Gitleaks**: keep the existing experimental adapter; do not invest further
  while the project is in maintenance mode.

## 6. Roadmap

| Order | Milestone | Status |
|---|---|---|
| 1 | Local projects, scan history, one-click comparison, timeline, recurrence ("detected again"), SARIF 2.1.0 export, redesigned UI | **Implemented 2026-10-28** (tested internally; see docs/webui.md and docs/sarif.md) |
| 1b | Release preparation: audit, SARIF schema validation, redesigned console, synthetic demo, release documentation | **Done 2026-11-01** |
| 2 | First hosted CI run and a usability session with 3 to 5 developers (product strategy section 12.3) | Owner decision; prerequisite for everything below |
| 3 | Git-history secret scanning (section 3), starting with the metadata reader and a time-boxed reader spike | **Next major capability** |
| 4 | Finding decisions: false positive, accepted risk with expiry, notes; never hiding a finding without a visible record | After 3 or in parallel |
| 5 | SARIF import (provenance-labelled, untrusted input) | After 4 |
| 6 | Optional OSV-Scanner offline integration | After 5, only with evidence of need |

## 7. Accessibility target for the redesign

WCAG 2.2 is a W3C Recommendation (12 December 2024) ([WCAG 2.2][wcag]). New
criteria that matter for this interface (Verified): 2.4.11 Focus Not Obscured
(Minimum, AA), 2.5.7 Dragging Movements (AA), 2.5.8 Target Size (Minimum, AA:
"at least 24 by 24 CSS pixels", with exceptions), 3.2.6 Consistent Help (A),
3.3.7 Redundant Entry (A), 3.3.8 Accessible Authentication (Minimum, AA). The
redesign targets AA; automated checks (axe-core) cover only part of it, so
conformance is not claimed.

## Sources

* [gh-secret]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
* [gh-push]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
* [gh-sarif]: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files
* [gh-sarif-support]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
* SARIF 2.1.0 (OASIS, errata 01) and its JSON schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html, https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
* [semgrep]: https://docs.semgrep.dev/semgrep-code/triage-remediation
* [trivy-fs]: https://trivy.dev/docs/latest/guide/target/filesystem/
* [trivy-airgap]: https://trivy.dev/docs/v0.56/advanced/air-gap/ (versioned page; flags may differ in newer releases)
* [osv-source]: https://google.github.io/osv-scanner/usage/scan-source
* [osv-offline]: https://google.github.io/osv-scanner/usage/offline-mode
* [gitleaks]: https://github.com/gitleaks/gitleaks
* [zizmor]: https://docs.zizmor.sh/usage/
* [owasp]: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-2-Develop/2-2-3-Secure-Code-Review/
* [wcag]: https://www.w3.org/TR/WCAG22/

[gh-secret]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
[gh-push]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
[gh-sarif]: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files
[gh-sarif-support]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
[semgrep]: https://docs.semgrep.dev/semgrep-code/triage-remediation
[trivy-fs]: https://trivy.dev/docs/latest/guide/target/filesystem/
[trivy-airgap]: https://trivy.dev/docs/v0.56/advanced/air-gap/
[osv-source]: https://google.github.io/osv-scanner/usage/scan-source
[osv-offline]: https://google.github.io/osv-scanner/usage/offline-mode
[gitleaks]: https://github.com/gitleaks/gitleaks
[zizmor]: https://docs.zizmor.sh/usage/
[owasp]: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-2-Develop/2-2-3-Secure-Code-Review/
[wcag]: https://www.w3.org/TR/WCAG22/
