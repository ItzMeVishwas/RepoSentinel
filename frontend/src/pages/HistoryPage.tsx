import { useCallback, useEffect, useState } from 'react';
import { messageOf, post } from '../api';
import { openSavedScan, scanProject } from '../actions';
import { ConfirmAction, Empty, ErrorNote, OUTCOME_WORDS, PageHeading, Section, formatDate, plural } from '../common';
import { Icon } from '../icons';
import { currentProject, useApp } from '../state';
import type { CompareResponse, HistoryList, ScanRecord, TimelineChanges } from '../types';

export function HistoryPage() {
  const app = useApp();
  const projects = app.projects ?? [];
  const project = currentProject(app); // a removed project's id is ignored
  const projectId = project?.id ?? null;
  const [picked, setPicked] = useState<number[]>([]);
  const [comparing, setComparing] = useState(false);
  const [history, setHistory] = useState<HistoryList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (projectId === null) return;
    setLoading(true);
    setError(null);
    try {
      setHistory(await post<HistoryList>('api/history', { project_id: projectId }));
    } catch (failure) {
      setHistory(null);
      setError(messageOf(failure));
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function open(scanId: number) {
    setError(null);
    try {
      await openSavedScan(app, scanId);
      app.go('findings');
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  useEffect(() => setPicked([]), [projectId]);

  function togglePick(scanId: number) {
    // Keep at most two: picking a third replaces the earliest pick.
    setPicked((now) => (now.includes(scanId) ? now.filter((id) => id !== scanId) : [...now, scanId].slice(-2)));
  }

  async function comparePicked() {
    if (picked.length !== 2) return;
    setComparing(true);
    setError(null);
    try {
      const [a, b] = picked as [number, number];
      app.setComparison(
        await post<CompareResponse>('api/history/compare', {
          old_scan_id: Math.min(a, b),
          new_scan_id: Math.max(a, b),
        }),
      );
      app.go('compare');
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setComparing(false);
    }
  }

  async function scanAgain() {
    if (!project) return;
    setError(null);
    try {
      await scanProject(app, project);
      app.notify(`Scan of ${project.name} finished and saved.`);
      await load();
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  async function remove(scanId: number) {
    await post('api/history/delete', { scan_id: scanId });
    if (app.active?.historyScanId === scanId) app.setActive(null);
    setPicked((now) => now.filter((id) => id !== scanId));
    app.notify(`Deleted saved scan #${scanId}.`, 'info');
    await load();
    await app.refreshProjects();
  }

  if (projects.length === 0) {
    return (
      <div className="view">
        <PageHeading title="History" />
        <Empty>No projects are registered, so there is no history yet.</Empty>
        <button type="button" className="primary" onClick={() => app.go('projects')}>
          Register a project
        </button>
      </div>
    );
  }

  const scans = history?.scans ?? [];
  return (
    <div className="view">
      <PageHeading
        title="History"
        lede="Saved scans of a project, newest first, with what changed between each scan and the one before it. Counts come from RepoSentinel's comparison of the two saved reports."
      />
      <div className="toolbar">
        <label className="inline-field" htmlFor="history-project">
          Project
          <select
            id="history-project"
            value={projectId ?? ''}
            onChange={(event) => app.selectProject(Number(event.target.value))}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="primary"
          onClick={scanAgain}
          disabled={app.scanning || !project?.available}
          aria-busy={app.scanning}
        >
          <Icon name="play" size={14} />
          {app.scanning ? 'Scanning...' : 'Scan again and compare'}
        </button>
      </div>
      <p className="status-line" role="status">
        {loading ? 'Loading history...' : ''}
      </p>
      {error && <ErrorNote message={error} />}
      {history && scans.length === 0 && (
        <Empty>No saved scans for this project yet. Scan it from the Projects or Scan page.</Empty>
      )}
      {history && scans.length > 0 && (
        <>
          <Section
            id="timeline"
            title="Findings per saved scan"
            intro={`Oldest on the left. A question mark marks an incomplete scan, whose count may be missing findings. Up to ${history.max_scans} scans are kept per project; older ones are removed.`}
          >
            <Timeline scans={[...scans].reverse().map((entry) => entry.scan)} />
          </Section>
          <Section id="history-table" title="Saved scans" count={scans.length}>
            <div className="table-wrap">
              <table>
                <caption className="visually-hidden">Saved scans of {history.project.name}, newest first</caption>
                <thead>
                  <tr>
                    <th scope="col">
                      <span className="visually-hidden">Select for comparison</span>
                    </th>
                    <th scope="col">Scan</th>
                    <th scope="col">Outcome</th>
                    <th scope="col" className="num">
                      Findings
                    </th>
                    <th scope="col">By severity</th>
                    <th scope="col">Coverage</th>
                    <th scope="col">Compared with the scan before</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map(({ scan, changes }) => (
                    <tr key={scan.id} className={picked.includes(scan.id) ? 'picked' : undefined}>
                      <td className="pick">
                        <input
                          type="checkbox"
                          aria-label={`Select scan #${scan.id} for comparison`}
                          checked={picked.includes(scan.id)}
                          onChange={() => togglePick(scan.id)}
                        />
                      </td>
                      <th scope="row">
                        #{scan.id}
                        <span className="cell-sub">{formatDate(scan.scanned_at)}</span>
                      </th>
                      <td className={`outcome-text-${scan.outcome}`}>{OUTCOME_WORDS[scan.outcome]}</td>
                      <td className="num">{scan.findings}</td>
                      <td>
                        {scan.severity.high} high, {scan.severity.medium} medium, {scan.severity.low} low,{' '}
                        {scan.severity.info} info
                      </td>
                      <td>
                        {scan.checks_completed} of {scan.checks_total} checks
                        {scan.coverage_errors > 0 && `, ${plural(scan.coverage_errors, 'unreadable item', 'unreadable items')}`}
                        {scan.not_examined > 0 && `, ${scan.not_examined} skipped by policy`}
                      </td>
                      <td>
                        <ChangeText changes={changes} />
                      </td>
                      <td>
                        <div className="row-actions">
                          <button type="button" onClick={() => open(scan.id)}>
                            Open<span className="visually-hidden"> scan #{scan.id}</span>
                          </button>
                          <ConfirmAction
                            label={`Delete`}
                            confirmLabel={`Delete scan #${scan.id}`}
                            question={`Delete saved scan #${scan.id}? This cannot be undone.`}
                            onConfirm={() => remove(scan.id)}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
          <div className="compare-bar" role="group" aria-label="Compare selected scans">
            <p>
              {picked.length === 2
                ? `Compare scan #${Math.min(...picked)} (before) with scan #${Math.max(...picked)} (after).`
                : `Select two scans in the table to compare them (${picked.length} of 2 selected).`}
            </p>
            <button
              type="button"
              className="primary"
              disabled={picked.length !== 2 || comparing}
              aria-busy={comparing}
              onClick={comparePicked}
            >
              {comparing ? 'Comparing...' : 'Compare selected scans'}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ChangeText({ changes }: { changes: TimelineChanges | null }) {
  if (!changes) return <span className="muted">First saved scan (or comparison not computed)</span>;
  if ('error' in changes) return <span className="unknown-text">Not compared: {changes.error}</span>;
  const c = changes.counts;
  const added = (c.new ?? 0) + (c.new_not_examined_before ?? 0);
  const gone = (c.not_detected_on_recheck ?? 0) + (c.not_detected_file_removed ?? 0);
  const parts = [
    `${added} new`,
    `${c.still_detected ?? 0} still detected`,
    `${gone} no longer detected`,
  ];
  if (changes.unknowns) parts.push(`${changes.unknowns} unknown`);
  if (changes.recurring) parts.push(`${changes.recurring} detected again`);
  return <span>{parts.join(', ')} (vs #{changes.previous_scan_id})</span>;
}

/** Bars of findings per scan. The table above it carries the same numbers. */
function Timeline({ scans }: { scans: ScanRecord[] }) {
  const width = 640;
  const height = 160;
  const top = 22;
  const bottom = 24;
  const max = Math.max(1, ...scans.map((scan) => scan.findings));
  const slot = width / Math.max(scans.length, 1);
  const bar = Math.max(4, Math.min(36, slot - 2));
  const plot = height - top - bottom;
  const label = `${scans.length} saved scans, oldest first. Findings: ${scans.map((s) => s.findings).join(', ')}.`;
  return (
    <figure className="timeline">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
        <line x1="0" x2={width} y1={height - bottom} y2={height - bottom} className="axis" />
        <text x="0" y="12" className="axis-label">
          {plural(max, 'finding', 'findings')}
        </text>
        {scans.map((scan, index) => {
          const h = (scan.findings / max) * plot;
          const x = index * slot + (slot - bar) / 2;
          const y = height - bottom - h;
          return (
            <g key={scan.id} className="bar-group">
              <title>
                Scan #{scan.id}, {formatDate(scan.scanned_at)}: {plural(scan.findings, 'finding', 'findings')}
                {scan.outcome === 'incomplete' ? ' (incomplete scan)' : ''}
              </title>
              <rect x={index * slot} y={top} width={slot} height={plot} className="hit" />
              {h > 0 && (
                <path
                  d={`M${x},${height - bottom} V${y + Math.min(4, h)} Q${x},${y} ${x + Math.min(4, bar / 2)},${y} H${x + bar - Math.min(4, bar / 2)} Q${x + bar},${y} ${x + bar},${y + Math.min(4, h)} V${height - bottom} Z`}
                  className={`bar ${scan.outcome === 'incomplete' ? 'bar-incomplete' : ''}`}
                />
              )}
              {scan.outcome === 'incomplete' && (
                <text x={x + bar / 2} y={y - 4} textAnchor="middle" className="bar-mark">
                  ?
                </text>
              )}
              {(scans.length <= 12 || index === 0 || index === scans.length - 1) && (
                <text x={x + bar / 2} y={height - 8} textAnchor="middle" className="axis-label">
                  #{scan.id}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </figure>
  );
}
