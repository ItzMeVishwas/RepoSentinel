import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { messageOf, post } from '../api';
import { openSavedScan, scanProject } from '../actions';
import { Empty, ErrorNote, OUTCOME_WORDS, PageHeading, StatusWord, formatDate, plural } from '../common';
import { Icon } from '../icons';
import { SentinelGlobe } from '../Sentinel';
import { comparisonOf, currentProject, useApp, type ActiveScan, type Page } from '../state';
import type { Project, ScanRecord } from '../types';

interface Activity {
  scan: ScanRecord;
  project_name: string;
}

export function OverviewPage() {
  const app = useApp();
  const [error, setError] = useState<string | null>(null);
  const [activity, setActivity] = useState<Activity[] | null>(null);
  const project = currentProject(app);
  const scan = app.active;

  const loadActivity = useCallback(async () => {
    if (!app.session.history) return;
    try {
      setActivity((await post<{ scans: Activity[] }>('api/activity', {})).scans);
    } catch (failure) {
      setError(messageOf(failure));
    }
  }, [app.session.history]);

  useEffect(() => {
    void loadActivity();
  }, [loadActivity, app.projects]);

  async function act(action: () => Promise<void>) {
    setError(null);
    try {
      await action();
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  if (!scan && !project) {
    return <FirstRun error={error} act={act} />;
  }
  const latest = project?.latest ?? null;
  const showsLatest = scan?.source === 'project' && scan.historyScanId === latest?.id;
  return (
    <div className="view">
      <PageHeading title="Overview" />
      {error && <ErrorNote message={error} />}
      <section className="hero" aria-labelledby="hero-title">
        <div className="hero-copy">
          <p className="eyebrow">{scan?.source === 'one-off' ? 'Open scan (one-off, not saved)' : 'Current project'}</p>
          <h2 id="hero-title" className="hero-title">
            {scan?.source === 'one-off' ? 'One-off scan' : (project?.name ?? scan?.project?.name)}
          </h2>
          <p className="hero-path">
            <code>{scan?.report.target ?? project?.path}</code>
          </p>
          <p className="hero-status">
            {scan
              ? `${scan.source === 'project' ? `Saved scan #${scan.historyScanId}, made` : 'Scanned'} ${formatDate(scan.report.scanned_at)}: ${OUTCOME_WORDS[scan.report.outcome]}.`
              : latest
                ? `Last scanned ${formatDate(latest.scanned_at)} (scan #${latest.id}): ${OUTCOME_WORDS[latest.outcome]}, ${plural(latest.findings, 'finding', 'findings')}.`
                : 'Not scanned yet.'}
            {project && !project.available && ' Its folder was not found; update its location on the Projects page.'}
          </p>
          <div className="button-row">
            {project && (
              <button
                type="button"
                className="primary"
                disabled={app.scanning || !project.available}
                aria-busy={app.scanning}
                onClick={() =>
                  act(async () => {
                    await scanProject(app, project);
                    app.notify(`Scan of ${project.name} finished and saved.`);
                  })
                }
              >
                <Icon name="play" size={14} />
                {app.scanning ? 'Scanning...' : latest ? 'Scan again and compare' : 'Run first scan'}
              </button>
            )}
            {project && latest && !showsLatest && (
              <button type="button" onClick={() => act(() => openSavedScan(app, latest.id))}>
                Open latest scan
              </button>
            )}
            {scan && (
              <button type="button" onClick={() => app.go('findings')}>
                Review findings
              </button>
            )}
          </div>
          {app.scanning && (
            <p className="hint" role="status">
              Scanning. Large folders can take a while; RepoSentinel shows no progress estimate
              because it cannot measure one accurately.
            </p>
          )}
        </div>
        <SentinelGlobe scanning={app.scanning} className="hero-globe" />
      </section>

      {scan ? (
        <>
          <Attention scan={scan} />
          <div className="two-col">
            <Coverage scan={scan} />
            <NextActions scan={scan} go={app.go} />
          </div>
          <p className="kv-note not-a-score">
            These sections describe what RepoSentinel's checks saw. They are not a score, and they
            do not show that the repository is secure or ready to publish.
          </p>
        </>
      ) : (
        <section className="section" aria-labelledby="no-open-scan">
          <h2 id="no-open-scan">No scan is open</h2>
          <p className="section-intro">
            {latest
              ? 'Open the latest saved scan to see what needs attention, or scan the project again.'
              : 'Run the first scan of this project to see what needs attention.'}
          </p>
        </section>
      )}

      {app.session.history && <RecentActivity activity={activity} act={act} />}
    </div>
  );
}

function FirstRun(props: { error: string | null; act: (action: () => Promise<void>) => Promise<void> }) {
  const app = useApp();
  const [creating, setCreating] = useState(false);

  async function createDemo() {
    setCreating(true);
    await props.act(async () => {
      const reply = await post<{ project: Project }>('api/demo/create', {});
      await app.refreshProjects();
      app.selectProject(reply.project.id);
      await scanProject(app, { ...reply.project, available: true, latest: null, created_at: '' });
      app.notify('Synthetic demo project created and scanned. Its credentials are fake.');
    });
    setCreating(false);
  }

  return (
    <div className="view">
      <PageHeading title="Overview" />
      <section className="hero hero-first" aria-labelledby="first-title">
        <div className="hero-copy">
          <p className="eyebrow">Welcome to RepoSentinel</p>
          <h2 id="first-title" className="hero-title">
            See what your checks found, and what they could not see, before you publish.
          </h2>
          <p className="lede">
            RepoSentinel reads a repository folder on this computer and looks for risky files,
            hard-coded credential patterns and unsafe GitHub Actions workflows. Fix what it finds,
            scan again, and it tells you what is still detected, what is no longer detected, and
            what it could not re-check.
          </p>
          {props.error && <ErrorNote message={props.error} />}
          <ol className="steps">
            {app.session.history && (
              <li>
                <strong>Register a project</strong>: a folder you check over time. Its scans are
                saved on this computer only.
              </li>
            )}
            <li>
              <strong>Scan it</strong> and review each finding. RepoSentinel never changes files.
            </li>
            <li>
              <strong>Fix, then scan again</strong> to see what changed.
            </li>
          </ol>
          <div className="button-row">
            {app.session.history && (
              <button type="button" className="primary" onClick={() => app.go('projects')}>
                <Icon name="plus" size={14} /> Register a project
              </button>
            )}
            {app.session.history && (
              <button type="button" onClick={createDemo} disabled={creating || app.scanning} aria-busy={creating}>
                {creating ? 'Creating the demo...' : 'Try a synthetic demo project'}
              </button>
            )}
            <button type="button" onClick={() => app.go('scan')}>
              Scan a folder once
            </button>
          </div>
          {app.session.history && (
            <p className="hint">
              The demo is a small repository with <strong>fake</strong> credentials, created in a
              new temporary folder and registered as a project, so you can try every feature
              without scanning your own code.
            </p>
          )}
        </div>
        <SentinelGlobe scanning={app.scanning || creating} className="hero-globe" />
      </section>
    </div>
  );
}

function Attention({ scan }: { scan: ActiveScan }) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of scan.report.findings) counts[finding.severity] += 1;
  const result = comparisonOf(scan.previous);
  const c = result?.comparison;
  const added = c ? (c.counts.new ?? 0) + (c.counts.new_not_examined_before ?? 0) : null;
  const gone = c && result ? result.groups.no_longer_detected.reduce((n, s) => n + (c.counts[s] ?? 0), 0) : null;
  const reminders = c ? c.findings.filter((f) => f.credential_reminder).length : 0;
  return (
    <section className="section" aria-labelledby="attention">
      <div className="section-head">
        <h2 id="attention">What needs attention</h2>
        <span className="count">{plural(scan.report.findings.length, 'finding', 'findings')}</span>
      </div>
      <ul className="metric-grid">
        <Metric tone="high" value={counts.high} label="High severity" />
        <Metric tone="medium" value={counts.medium} label="Medium severity" />
        <Metric tone="low" value={counts.low} label="Low severity" />
        <Metric tone="info" value={counts.info} label="Info" />
      </ul>
      {result && c ? (
        <>
          <h3 className="subhead">Since scan #{result.scan_id}</h3>
          <ul className="metric-grid">
            <Metric tone={added ? 'high' : 'neutral'} value={added ?? 0} label="New" />
            <Metric tone={result.recurring.length ? 'medium' : 'neutral'} value={result.recurring.length} label="Detected again" />
            <Metric tone="neutral" value={c.counts.still_detected ?? 0} label="Still detected" />
            <Metric tone={c.unknowns ? 'unknown' : 'neutral'} value={c.unknowns} label="Not re-checked or not comparable" />
            <Metric tone="neutral" value={gone ?? 0} label="No longer detected in the files re-checked" />
          </ul>
          {reminders > 0 && (
            <p className="note-bar note-unknown">
              <strong>Action needed:</strong> {plural(reminders, 'credential finding is', 'credential findings are')} no
              longer detected. A removed credential may still be valid and still be in Git
              history: rotate or revoke it. RepoSentinel cannot check this.
            </p>
          )}
        </>
      ) : (
        <p className="section-intro">
          {scan.source === 'one-off'
            ? 'This one-off scan is not compared with anything. Register the folder as a project to compare each scan with the previous one.'
            : "This is the project's first saved scan; scan again after changes to see what changed."}
        </p>
      )}
    </section>
  );
}

function Metric(props: { tone: string; value: number; label: string }) {
  return (
    <li className={`metric metric-${props.tone}`}>
      <span className="metric-value">{props.value}</span>
      <span className="metric-label">{props.label}</span>
    </li>
  );
}

function Coverage({ scan }: { scan: ActiveScan }) {
  const report = scan.report;
  const failed = report.checks.filter((check) => check.status !== 'completed');
  const unreadable = report.coverage.filter((issue) => issue.is_error).length;
  const skipped = report.coverage.filter((issue) => !issue.is_error).length;
  const rows: { tone: 'ok' | 'unknown' | 'neutral'; word: string; text: ReactNode }[] = [
    failed.length === 0
      ? { tone: 'ok', word: 'Completed', text: `All ${report.checks.length} checks completed.` }
      : {
          tone: 'unknown',
          word: 'Incomplete',
          text: `${failed.length} of ${report.checks.length} checks did not complete: ${failed.map((c) => `${c.name} (${c.status})`).join(', ')}.`,
        },
    { tone: 'neutral', word: 'Examined', text: `${plural(report.summary.files_in_scope, 'file', 'files')} in scope.` },
    unreadable
      ? { tone: 'unknown', word: 'Unreadable', text: `${plural(unreadable, 'file or folder', 'files or folders')} could not be read; problems there would not appear.` }
      : { tone: 'ok', word: 'Readable', text: 'Every file in scope could be read.' },
    {
      tone: 'neutral',
      word: 'Skipped',
      text: skipped
        ? `${plural(skipped, 'file or folder was', 'files or folders were')} skipped by policy (exclusions, size limit, binary files or links).`
        : 'Nothing was skipped by policy.',
    },
    { tone: 'unknown', word: 'Not scanned', text: 'Git history: only current files are examined. Earlier commits may still contain secrets.' },
  ];
  return (
    <section className="section" aria-labelledby="coverage">
      <h2 id="coverage">Coverage</h2>
      <ul className="checklist">
        {rows.map((row) => (
          <li key={row.word} className="check-item">
            <StatusWord tone={row.tone}>{row.word}</StatusWord>
            <p>{row.text}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}

function NextActions({ scan, go }: { scan: ActiveScan; go: (page: Page) => void }) {
  const result = comparisonOf(scan.previous);
  const high = scan.report.findings.filter((f) => f.severity === 'high').length;
  const actions: { label: string; detail: string; page: Page }[] = [];
  if (high) actions.push({ label: `Review ${plural(high, 'high-severity finding', 'high-severity findings')}`, detail: 'Start with these in the findings explorer.', page: 'findings' });
  else if (scan.report.findings.length) actions.push({ label: 'Review the findings', detail: 'Each is a potential problem for human review.', page: 'findings' });
  if (scan.report.outcome === 'incomplete') actions.push({ label: 'See what could not be checked', detail: 'The scan details list each problem.', page: 'scan' });
  if (result?.comparison.unknowns) actions.push({ label: 'Review what could not be re-checked', detail: 'The comparison explains each unknown.', page: 'compare' });
  if (result) actions.push({ label: 'Open the full comparison', detail: `What changed since scan #${result.scan_id}.`, page: 'compare' });
  if (scan.source === 'project') actions.push({ label: 'Compare other saved scans', detail: 'Pick any two scans in History.', page: 'history' });
  actions.push({ label: 'Export a report', detail: 'JSON, HTML or SARIF 2.1.0.', page: 'reports' });
  return (
    <section className="section" aria-labelledby="next-actions">
      <h2 id="next-actions">Next actions</h2>
      <ul className="action-list">
        {actions.map((action) => (
          <li key={action.label}>
            <button type="button" className="action-link" onClick={() => go(action.page)}>
              <span>
                <span className="action-label">{action.label}</span>
                <span className="action-detail">{action.detail}</span>
              </span>
              <Icon name="arrow" size={16} />
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function RecentActivity(props: { activity: Activity[] | null; act: (action: () => Promise<void>) => Promise<void> }) {
  const app = useApp();
  return (
    <section className="section" aria-labelledby="recent">
      <h2 id="recent">Recent scans</h2>
      {!props.activity || props.activity.length === 0 ? (
        <Empty>No saved scans yet.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Scan</th>
                <th scope="col">Project</th>
                <th scope="col">Outcome</th>
                <th scope="col" className="num">
                  Findings
                </th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {props.activity.map(({ scan, project_name }) => (
                <tr key={scan.id}>
                  <th scope="row">
                    #{scan.id}
                    <span className="cell-sub">{formatDate(scan.scanned_at)}</span>
                  </th>
                  <td>{project_name}</td>
                  <td className={`outcome-text-${scan.outcome}`}>{OUTCOME_WORDS[scan.outcome]}</td>
                  <td className="num">{scan.findings}</td>
                  <td>
                    <button
                      type="button"
                      className="small"
                      onClick={() =>
                        props.act(async () => {
                          await openSavedScan(app, scan.id);
                          app.selectProject(scan.project_id);
                        })
                      }
                    >
                      Open<span className="visually-hidden"> scan #{scan.id}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
