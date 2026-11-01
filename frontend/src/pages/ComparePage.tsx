import { useEffect, useState, type FormEvent } from 'react';
import { messageOf, post } from '../api';
import { ErrorNote, HISTORY_LIMIT, PageHeading, Section, formatDate, plural } from '../common';
import { CompareResults, FAIL_ON, ImportCompareForm } from '../CompareView';
import { currentProject, useApp } from '../state';
import type { CompareResponse, HistoryList } from '../types';

export function ComparePage() {
  const app = useApp();
  return (
    <div className="view">
      <PageHeading
        title="Compare"
        lede="See what is still detected, what is no longer detected in the files that were re-checked, and what could not be re-checked. The comparison is made by RepoSentinel's comparison engine, the same as 'reposentinel compare'."
      />
      <p className="history-limit" role="note">
        {HISTORY_LIMIT}
      </p>
      <div className="split-forms">
        {app.session.history && <SavedCompareForm />}
        <ImportCompareForm session={app.session} onResult={app.setComparison} />
      </div>
      {app.comparison && <CompareResults response={app.comparison} />}
    </div>
  );
}

function SavedCompareForm() {
  const app = useApp();
  const projects = app.projects ?? [];
  const projectId = currentProject(app)?.id ?? null; // a removed project's id is ignored
  const [history, setHistory] = useState<HistoryList | null>(null);
  const [older, setOlder] = useState<number | null>(null);
  const [newer, setNewer] = useState<number | null>(null);
  const [failOn, setFailOn] = useState('low');
  const [differentRoots, setDifferentRoots] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (projectId === null) return;
    let cancelled = false;
    post<HistoryList>('api/history', { project_id: projectId })
      .then((list) => {
        if (cancelled) return;
        setHistory(list);
        setNewer(list.scans[0]?.scan.id ?? null);
        setOlder(list.scans[1]?.scan.id ?? null);
      })
      .catch((failure: unknown) => !cancelled && setError(messageOf(failure)));
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (running) return;
    if (older === null || newer === null) {
      setError('This project needs at least two saved scans to compare.');
      return;
    }
    setRunning(true);
    setError(null);
    try {
      app.setComparison(
        await post<CompareResponse>('api/history/compare', {
          // Scan ids increase with time, so the smaller id is the older scan.
          old_scan_id: Math.min(older, newer),
          new_scan_id: Math.max(older, newer),
          fail_on: failOn,
          different_roots: differentRoots,
        }),
      );
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setRunning(false);
    }
  }

  const scans = history?.scans ?? [];
  const option = (id: number) => {
    const entry = scans.find((s) => s.scan.id === id);
    return entry ? `#${id}, ${formatDate(entry.scan.scanned_at)} (${plural(entry.scan.findings, 'finding', 'findings')})` : `#${id}`;
  };
  return (
    <Section
      id="saved-compare"
      title="Compare two saved scans"
      intro="Pick any two saved scans of a project. If you pick them in the wrong order, the older one is used as 'before'."
    >
      {projects.length === 0 ? (
        <p>No projects are registered yet, so there are no saved scans to compare.</p>
      ) : (
        <form onSubmit={submit} noValidate className="form-grid">
          <label htmlFor="compare-project" className="wide">
            Project
            <select
              id="compare-project"
              value={projectId ?? ''}
              onChange={(event) => app.selectProject(Number(event.target.value))}
              disabled={running}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label htmlFor="compare-older">
            Before (older scan)
            <select
              id="compare-older"
              value={older ?? ''}
              onChange={(event) => setOlder(Number(event.target.value))}
              disabled={running || scans.length < 2}
            >
              {scans.map(({ scan }) => (
                <option key={scan.id} value={scan.id}>
                  {option(scan.id)}
                </option>
              ))}
            </select>
          </label>
          <label htmlFor="compare-newer">
            After (newer scan)
            <select
              id="compare-newer"
              value={newer ?? ''}
              onChange={(event) => setNewer(Number(event.target.value))}
              disabled={running || scans.length < 2}
            >
              {scans.map(({ scan }) => (
                <option key={scan.id} value={scan.id}>
                  {option(scan.id)}
                </option>
              ))}
            </select>
          </label>
          <details className="advanced wide">
            <summary>Options</summary>
            <div className="advanced-grid">
              <label htmlFor="saved-fail-on">
                Treat as failing
                <select
                  id="saved-fail-on"
                  value={failOn}
                  onChange={(event) => setFailOn(event.target.value)}
                  disabled={running}
                >
                  {FAIL_ON.map(([value, text]) => (
                    <option key={value} value={value}>
                      {text}
                    </option>
                  ))}
                </select>
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={differentRoots}
                  onChange={(event) => setDifferentRoots(event.target.checked)}
                  disabled={running}
                />
                The project's folder location changed between these scans, and I confirm they
                describe the same repository. RepoSentinel cannot check this.
              </label>
            </div>
          </details>
          <div className="wide">
            <button
              type="submit"
              className="primary"
              disabled={running || scans.length < 2}
              aria-busy={running}
            >
              {running ? 'Comparing...' : 'Compare saved scans'}
            </button>
            {history && scans.length < 2 && (
              <p className="hint">This project has {scans.length} saved scan(s); two are needed.</p>
            )}
          </div>
        </form>
      )}
      {error && <ErrorNote message={error} />}
    </Section>
  );
}
