# Local web interface (optional, prototype)

`reposentinel ui` opens a local security console in your browser: register
the projects you check regularly, scan them, see what changed since the
previous scan, explore findings, look back through a project's history,
compare any two saved scans, and export reports (JSON, HTML, SARIF). It is a
thin layer over the Python engine: every finding, status, comparison and exit
code comes from the same code as `scan` and `compare`, and the downloads are
the same files those commands write.

> **Status: tested internally only.** It has automated server tests and an
> end-to-end test in a real Chromium-based browser (Chrome 156; earlier also
> Microsoft Edge) that includes keyboard interactions and automated
> accessibility rules for WCAG 2.2 AA (axe-core). WCAG 2.2 AA is the design
> and test target; automated rules cannot establish conformance. No external
> user has tried it yet, and it has not been tested in Firefox or Safari, with
> a screen reader, or by a person using only a keyboard.

## Starting and stopping

The interface has to be built once (it needs Node.js 22.12 or newer; the
packages are pinned in `frontend/package-lock.json`):

```powershell
cd frontend
npm ci
npm run build          # writes src/reposentinel/webui/static/
cd ..
.\.venv\Scripts\python.exe -m reposentinel ui
```

`reposentinel ui` prints a one-time link and opens it in your default browser
(`--no-browser` only prints it; `--port N` picks the port, default: a free
one; `--data-dir FOLDER` and `--no-history` are described under
[Local data and privacy](#local-data-and-privacy)). The link looks like `http://127.0.0.1:PORT/s/<random>/#launch=<code>`.
It works **once**: the page removes the code from the address bar and history
and exchanges it for a session that exists only in that tab's memory.

**Reloading or closing the tab ends the session** (nothing is stored in the
browser). Press **Enter** in the terminal for a new one-time link; opening it
starts a new session and ends the old one. A session lasts at most 8 hours.

**Stop it** with **Ctrl+C** in the terminal. One-off scans and uploaded
comparisons live in memory until you stop it (the last four of each are kept
for downloads). Scans of registered projects are saved in the local history
and are there again the next time you start it.

Without the build, `reposentinel ui` exits with code 3 and says how to build
it. `scan`, `compare` and `rules` never need it and never load any of its code.

## Using it

The sidebar has eight pages; on narrow screens it becomes a menu opened from
the top bar. The top bar shows where you are, the current project (choose
another one there), whether a scan is running, and a **Scan project** button
that scans the current project and compares it with its previous scan. Every
page works with real data only: before anything has been scanned, pages say
so instead of showing examples.

* **Overview.** On first use: what RepoSentinel does, and three ways to
  start: register a project, **try a synthetic demo project** (RepoSentinel
  creates a small repository with *fake* credentials in a new temporary
  folder, registers it and scans it), or scan a folder once. Afterwards: the
  current project with its last scan; **what needs attention** (findings by
  severity, and since the previous scan: new, detected again, still detected,
  not re-checked or not comparable, no longer detected in the files
  re-checked, plus the reminder to rotate credentials that are no longer
  detected); **coverage** (checks completed, files examined, unreadable and
  skipped files, and that Git history was not scanned); **next actions**; and
  the most recent saved scans of all projects. It is deliberately **not a
  score** and never says a repository is secure or ready to publish.
* **Projects.** Register a folder you scan regularly with a display name and
  its full path. Browsers cannot pick a folder on behalf of a local program,
  so there is no Browse button; this is deliberate rather than a missing
  feature. Each project card shows its folder (long paths are shortened in
  the middle; the full path is in the tooltip and read by screen readers),
  its last scan, finding counts and how many checks completed, with **Scan
  again and compare**, **Open latest** and **History**. Under **Manage**:
  rename, change location (after the folder moved), **clear history** (deletes
  the saved scans, keeps the project) and **remove project** (forgets the
  project and its scans; the folder is never touched), each explained and
  confirmed. A folder that no longer exists is flagged, and its history is kept.
* **Scan.** Scan a registered project (saved and compared with its previous
  scan) or make a one-off scan of any folder (not saved). The scan uses the
  native checks only (the experimental Gitleaks integration is not available
  here). While it runs, the buttons are disabled and an animated indicator is
  shown; there is no percentage, because RepoSentinel cannot measure progress
  accurately. The result states the outcome in words with its scope ("current
  files only; Git history was not scanned"), what changed since the previous
  scan, what could not be examined, and each check's status.
* **Findings.** Search and filter the open scan's findings by text, severity,
  rule, path and, for project scans, comparison status ("New", "Still
  detected", "Detected again"); sort by severity, path or rule; or group them
  by file. Filters only hide findings and always say how many are shown. The
  Up and Down arrow keys (and Home and End) move through the list. The detail
  panel shows what was found (with redacted evidence), the comparison status
  and why it was assigned, why the rule matters, what to do next, and the
  limits of the rule. Findings that are no longer detected are not in this
  list; they are in the comparison.
* **History.** A project's saved scans, newest first, with a chart of
  findings per scan (incomplete scans are marked with a question mark) and a
  table with the same numbers: outcome, findings by severity, coverage, and
  what changed compared with the scan before. Open any saved scan, delete one,
  scan the project again, or **select two scans and compare them**. A falling
  count is shown as a count, never as an improvement in security.
* **Compare.** Compare any two saved scans of a project without uploading
  files (the default), or compare two JSON report files (each up to 16 MiB
  here; use `reposentinel compare` for larger ones). A summary at the top
  counts the five outcomes (new, still detected, no longer detected, not
  re-checked, not comparable) and says what each means; below, every tracked
  finding with the reason for its status, and the same exit code the command
  line would return. The Git-history limitation is always shown.
* **Reports.** Download the open scan, the open comparison, or any saved
  scan, as files RepoSentinel itself renders: JSON (keep it to compare
  later), HTML, or SARIF 2.1.0 ([sarif.md](sarif.md)), each with its intended
  use and limits. Nothing is uploaded.
* **Settings.** Where local data is kept and how big it is, deleting all of
  it, a **reduce motion** option (it lasts until the page is closed, because
  the page stores nothing; the system's reduced-motion setting is always
  respected), the scan defaults and limits, privacy, and where to find the
  documentation.

Short notifications confirm completed actions (a scan saved, a project
registered or removed); they are announced to screen readers and disappear
after a few seconds.

### Words the console uses

"No longer detected" means the re-checked files no longer match a rule. It
never means "fixed" or "resolved": a credential that was removed from the
files may still be valid and may still be in Git history. "Detected again"
means a finding that the previous scan did not detect was detected in an
earlier saved scan. "Unknown", "not re-checked" and "not comparable" mean
RepoSentinel could not tell, and say why.

## Local data and privacy

Registering a project is how you turn on scan history; nothing is saved for
folders you scan once, and nothing is saved before you register a project
(the data folder is created then).

* **Where.** One SQLite database, `history.sqlite3`, in your user data
  folder: `%LOCALAPPDATA%\RepoSentinel` on Windows,
  `~/Library/Application Support/RepoSentinel` on macOS, and
  `$XDG_DATA_HOME/reposentinel` (default `~/.local/share/reposentinel`)
  elsewhere. `--data-dir FOLDER` or the `REPOSENTINEL_DATA_DIR` environment
  variable chooses another folder. It is never inside a scanned project:
  registering a project that contains the data folder (or lies inside it) is
  refused. `--no-history` starts the console with no history at all.
* **What is stored.** For each project: its display name, folder path and
  registration time. For each scan made through it: the JSON report exactly
  as `reposentinel scan --format json` writes it (findings with redacted
  evidence, file paths, coverage, settings and rule versions), a summary
  (counts and outcome), and the findings' fingerprints (hashes of non-secret
  identity inputs, used to notice findings that are detected again).
* **What is never stored.** File contents, matched secret values, the
  session token, the launch link, or anything from one-off scans and
  uploaded reports. Tests check the database's raw bytes for secret values
  and session tokens.
* **Limits.** At most 200 projects and 200 saved scans per project; beyond
  that, a project's oldest scans are removed.
* **Deleting.** One scan (History), one project's history (Projects, "Clear
  history"), a project with its history (Projects, "Remove project"), or
  everything (Settings, typing `DELETE` to confirm; this removes the database
  file and, if it is then empty, the folder). Deleting never touches your
  project folders or reports you downloaded. Deleted rows can remain in
  unused pages of the database file until it is deleted as a whole; they
  never contain secret values.
* **Damaged or newer data.** Every change is one transaction. A damaged
  database, or one written by a newer RepoSentinel (a newer schema version),
  is reported and left unchanged, never repaired or replaced silently. Every
  stored report is validated again when it is read, exactly like a report
  file given to `compare`; a damaged record is refused (and can be deleted)
  instead of being compared.
* **Who can read it.** Anyone with access to your user account can read the
  database, like any other file in your profile. On macOS and Linux the
  folder is created readable by you only (mode 700); on Windows it inherits
  your profile's permissions.

## Security model

The server is a security boundary: it runs on your computer while your
browser visits other websites.

| Threat | Control | Test |
|---|---|---|
| Other computers connect | Listens on `127.0.0.1` only; exclusive port binding on Windows; no reverse DNS lookup at start-up | `test_listens_on_loopback_only` |
| DNS rebinding (an attacker's domain made to point at 127.0.0.1) | Every request must have `Host: 127.0.0.1:PORT` or `localhost:PORT`; anything else gets 421 | `test_wrong_host_is_refused` |
| A website you visit calls the API (CSRF) | API calls are POST only, and need `Authorization: Bearer <token>` (256 random bits, compared in constant time), `Origin` equal to this server, the header `X-RepoSentinel-Request: 1`, and no cross-site `Sec-Fetch-Site`. A form, link or image cannot send these headers, and a script on another origin needs a CORS preflight, which is never granted (no CORS headers are ever sent) | `test_api_refuses_requests_missing_a_protection`, `test_form_style_requests_are_refused`, `test_api_never_grants_cors`; in the browser: "another website cannot call the API", "a form post from another local service is refused" |
| Another web service on 127.0.0.1 (another port) obtains the session | **No cookies are used.** Cookies are not isolated by port (RFC 6265, section 8.5), any port can set them (section 8.6), and `Path` is no protection (section 4.1.2.4); an earlier design scoped a cookie to a secret path, and a service that learned the path received the cookie. The credential is now a bearer token kept only in the page's memory and added by the page's own code to each request; a browser never attaches it by itself, so no navigation or request to another port can carry it, even when the base path is known. Cookies sent to the server are ignored | `tests/test_webui_session.py` (a spy service on another port, including at the secret base path; injected cookies; every operation without the token); in the browser: "another local service never receives a credential", "even at the secret base path, another local service receives no credential", "no cookie is set", "nothing is kept in browser storage" |
| The launch link or token leaks through URLs, history or logs | The launch code is in the URL **fragment**, which browsers never send to a server; the page removes it from the address bar and history before exchanging it (a POST with the same Origin and header checks). It works once and expires after 10 minutes; a new link (Enter in the terminal) invalidates the previous one, and each exchange issues a new token, ending the earlier session. The token is never in a URL, cookie, browser storage or log; request logging is off | `test_launch_code_works_once_and_sets_no_cookie`, `test_launch_code_exchange_needs_this_origin_and_the_header`, `test_a_new_link_ends_the_previous_tab_session`, `test_session_expires`, `test_a_token_from_another_launch_is_refused`, `test_ui_prints_the_whole_link_on_one_line`; in the browser: "the launch code is removed from the address bar", "the launch link works only once", "reloading the page ends the session" |
| Arbitrary file access or command execution | Five fixed operations: session info, scan a folder, export that scan, compare two uploaded reports, export that comparison. Unknown fields are rejected. No file browsing or reading, no shell, no subprocess; the scan uses the native checks and the existing walker (no links or junctions followed, limits applied). Static files come from a list built at start-up | `test_only_packaged_files_are_served`, `test_scan_request_validation`, `test_scan_through_the_ui_does_not_follow_a_junction` |
| Oversized or malformed requests | `application/json` only, `Content-Length` required, 64 KiB limit (about 43 MiB for a comparison upload), strict JSON (no `NaN`), each report through the same loader as `compare` | `test_unknown_operation_and_body_limits`, `test_compare_refuses_invalid_uploads`, `test_oversized_upload_is_refused` |
| Hostile repository or report text runs in the page | React renders text only (no `dangerouslySetInnerHTML`); the page's Content-Security-Policy allows scripts, styles and connections only from this server and no framing; every string sent for display goes through the same sanitiser as the terminal report, so invisible characters appear as codes such as `\u202e` | `test_invisible_characters_are_shown_as_codes`; in the browser: injected markup does not run, hostile names show as text |
| A refused request loses its error message | A request refused before its body is read (wrong Origin, too large) is answered, then the server reads and discards the rest of the body (bounded) before closing. Closing with unread data makes the system reset the connection, and the browser would show "not responding" instead of the reason | `test_rejected_requests_still_deliver_their_reply` (fails without the fix) |
| Errors expose repository content | Errors report the exception type only, never its message or a traceback | `test_internal_errors_never_quote_details` |
| Network traffic | No request leaves the computer: no fonts, scripts, analytics or update checks | `test_scan_and_compare_make_no_outside_connections`; the browser test records every response |

Known limits:

* The token is in the page's memory, so script running inside the page
  could use it. That is what the Content-Security-Policy (scripts only from
  this server) and React's text-only rendering prevent; a successful script
  injection would compromise the session under any design.
* The launch code appears in the terminal and, briefly, in the browser's
  address (it is removed at once and is useless after one use or 10 minutes).
  Software already running as you can read the terminal, the browser's memory
  and this process's memory: the interface does not defend against software
  already running on your account.
* The base path (`/s/<random>/`) is not a secret any more; it only keeps the
  app off the plain `http://127.0.0.1:PORT/`.
* Anyone with your Windows account can use the interface while it runs, the
  same as the command line.
* The browser-to-server connection is plain HTTP on the loopback interface. It
  never leaves the computer, so TLS would add no protection here.
* Reports and scans are kept in memory while the server runs.

## For developers

* Backend: `src/reposentinel/webui/server.py` (HTTP and security checks) and
  `api.py` (the operations, testable without HTTP). Python standard library
  only: no new runtime dependency.
* Frontend: `frontend/` (React 19, TypeScript, Vite 8, pinned exactly). It
  never computes findings, statuses or exit codes.
* Tests: `tests/test_webui_server.py` (pytest, no Node.js needed) and
  `frontend/e2e/run.mjs` (`npm run e2e`): the built interface in a real Chrome
  or Edge, driven by puppeteer-core against the real server, compared with
  the CLI's output, plus axe-core accessibility checks. It uses an installed
  browser and downloads nothing.
* The build in `src/reposentinel/webui/static/` is generated and git-ignored.
  `scripts/build_release.py` builds it before the Python archives; the sdist
  and the wheel both include it, and `scripts/check_dist.py` refuses archives
  without it (or whose `index.html` refers to a missing or non-relative
  file). The app uses relative URLs (`base: './'`), which keeps every request
  under the session's base path.
