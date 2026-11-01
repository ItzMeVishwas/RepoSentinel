import { useCallback, useEffect, useState } from 'react';
import { messageOf, post } from '../api';
import { ConfirmAction, ErrorNote, PageHeading, Section, formatBytes, plural } from '../common';
import { useApp } from '../state';
import type { DataInfo } from '../types';

export function SettingsPage() {
  const app = useApp();
  const [info, setInfo] = useState<DataInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!app.session.history) return;
    try {
      setInfo(await post<DataInfo>('api/data', {}));
      setError(null);
    } catch (failure) {
      setError(messageOf(failure));
    }
  }, [app.session.history]);

  useEffect(() => {
    void load();
  }, [load]);

  async function deleteAll() {
    await post('api/data/delete-all', { confirm: 'DELETE' });
    if (app.active?.source === 'project') app.setActive(null);
    app.setComparison(null);
    app.selectProject(null);
    setMessage('All local RepoSentinel data was deleted.');
    await app.refreshProjects();
    await load();
  }

  return (
    <div className="view">
      <PageHeading title="Settings" lede="Where RepoSentinel keeps data on this computer, and how to remove it." />
      <Section id="local-data" title="Local data">
        {!app.session.history ? (
          <p>
            Local history is off for this session (<code>--no-history</code>). Nothing is saved;
            one-off scans and report comparisons still work.
          </p>
        ) : !info && !error ? (
          <p className="loading" role="status">
            Loading local data details...
          </p>
        ) : info ? (
          <>
            <dl className="kv">
              <dt>Folder</dt>
              <dd>
                <code>{info.data_dir}</code>
              </dd>
              <dt>Database</dt>
              <dd>
                {info.exists ? (
                  <>
                    <code>{info.database}</code> ({formatBytes(info.bytes)})
                  </>
                ) : (
                  'Not created yet: it is created when you register your first project.'
                )}
              </dd>
              <dt>Contents</dt>
              <dd>
                {plural(info.projects, 'project', 'projects')}, {plural(info.scans, 'saved scan', 'saved scans')} (at most{' '}
                {info.max_scans_per_project} per project; older ones are removed)
              </dd>
              <dt>Format</dt>
              <dd>SQLite, history schema version {info.schema_version}</dd>
            </dl>
            <p className="hint">
              Change the folder by starting RepoSentinel with <code>--data-dir FOLDER</code> or the{' '}
              <code>REPOSENTINEL_DATA_DIR</code> environment variable. It must not be inside a
              project you scan.
            </p>
            <div className="danger-zone">
              <h3>Delete all local data</h3>
              <p>
                Removes every registered project and saved scan from this computer. Your project
                folders are not touched. Downloaded reports are separate files and are not removed.
              </p>
              <ConfirmAction
                label="Delete all local data"
                confirmLabel="Delete everything"
                question="Delete all RepoSentinel projects and saved scans from this computer? This cannot be undone."
                typed="DELETE"
                disabled={!info.exists}
                onConfirm={deleteAll}
              />
            </div>
          </>
        ) : null}
        <p className="status-line" role="status">
          {message ?? ''}
        </p>
        {error && <ErrorNote message={error} />}
      </Section>
      <Section id="preferences" title="Display">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={app.reduceMotion}
            onChange={(event) => app.setReduceMotion(event.target.checked)}
          />
          <span>
            Reduce motion: stop the scanning animation and transitions. Your system's
            reduced-motion setting is always respected. This choice lasts until the page is closed;
            RepoSentinel stores nothing in the browser.
          </span>
        </label>
      </Section>
      <Section id="scan-defaults" title="Scan defaults and limits">
        <dl className="kv">
          <dt>Skip files larger than</dt>
          <dd>
            {app.session.defaults.max_file_size_kb.toLocaleString()} KiB by default (up to{' '}
            {app.session.limits.max_file_size_kb.toLocaleString()} KiB)
          </dd>
          <dt>Stop after</dt>
          <dd>
            {app.session.defaults.max_files.toLocaleString()} files by default (up to{' '}
            {app.session.limits.max_files.toLocaleString()})
          </dd>
          <dt>Report uploads</dt>
          <dd>Up to {formatBytes(app.session.limits.max_upload_report_bytes)} per JSON report</dd>
          <dt>Checks</dt>
          <dd>
            The native checks only ({app.session.rules.length} rules). The experimental Gitleaks
            integration is available from the command line, not here.
          </dd>
        </dl>
        <p className="hint">
          Change the limits for one scan under "Scan limits" on the Scan page. Use the same limits
          for scans you want to compare.
        </p>
      </Section>
      <Section id="privacy" title="Privacy">
        <ul className="plain-list">
          <li>RepoSentinel runs on this computer only and makes no network requests.</li>
          <li>
            Saved for registered projects: the display name, the folder path, and each scan's
            redacted JSON report (findings with hidden secret values, file paths, coverage and
            settings). Never saved: file contents, secret values, this page's session token or the
            launch link.
          </li>
          <li>One-off scans and uploaded reports are kept in memory only, until RepoSentinel stops.</li>
          <li>
            This page stores nothing in the browser: no cookies, no local storage. Reloading it
            ends the session; press Enter in the terminal running <code>reposentinel ui</code> for a
            new link.
          </li>
        </ul>
      </Section>
      <Section id="about" title="About">
        <p>
          RepoSentinel {app.session.version}, {app.session.rules.length} rules. Findings are potential
          indicators for human review, not confirmed vulnerabilities.
        </p>
        <p>
          Documentation is in the RepoSentinel source folder: <code>README.md</code>,{' '}
          <code>docs/webui.md</code> (this interface and its security model),{' '}
          <code>docs/sarif.md</code>, <code>docs/rules.md</code> and <code>SECURITY.md</code> (how
          to report a vulnerability). The command line explains itself with{' '}
          <code>reposentinel --help</code>.
        </p>
      </Section>
    </div>
  );
}
