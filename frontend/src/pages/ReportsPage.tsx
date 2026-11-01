import { useEffect, useState } from 'react';
import { messageOf, post } from '../api';
import { DownloadButtons, Empty, ErrorNote, PageHeading, Section, formatDate, plural } from '../common';
import { currentProject, useApp } from '../state';
import type { HistoryList } from '../types';

export function ReportsPage() {
  const app = useApp();
  const scan = app.active;
  return (
    <div className="view">
      <PageHeading
        title="Reports"
        lede="Every file here is rendered by RepoSentinel itself, exactly as the command line writes it. Reports list file paths from the scanned folder and the redacted evidence of each finding; share them only where you would share that list."
      />
      <Section id="formats" title="Formats">
        <ul className="format-cards">
          <li className="format-card">
            <h3>JSON</h3>
            <p>
              <strong>Use it for:</strong> keeping a scan and comparing it later, here or with{' '}
              <code>reposentinel compare</code>. The full report (schema 1.1).
            </p>
            <p className="hint">Contains the absolute scanned folder path and every file path.</p>
          </li>
          <li className="format-card">
            <h3>HTML</h3>
            <p>
              <strong>Use it for:</strong> reading or sharing a scan as one standalone page. It loads
              nothing from the network.
            </p>
            <p className="hint">Not machine-readable; it cannot be compared.</p>
          </li>
          <li className="format-card">
            <h3>SARIF 2.1.0</h3>
            <p>
              <strong>Use it for:</strong> code-scanning tools such as GitHub code scanning. Valid
              against the official SARIF 2.1.0 schema; RepoSentinel never uploads it.
            </p>
            <p className="hint">
              Relative paths only, no snippets or secret values. Upload to GitHub has not been
              tested; file-level findings have no line number.
            </p>
          </li>
        </ul>
      </Section>
      <Section id="open-scan-export" title="The open scan">
        {scan ? (
          <>
            <p>
              {scan.source === 'project'
                ? `Saved scan #${scan.historyScanId} of ${scan.project?.name ?? 'a project'}`
                : 'One-off scan (not saved)'}
              , {formatDate(scan.report.scanned_at)}.
            </p>
            {scan.source === 'project' && scan.historyScanId !== null ? (
              <DownloadButtons
                endpoint="api/history/export"
                body={{ scan_id: scan.historyScanId }}
                stem={`reposentinel-report-scan-${scan.historyScanId}`}
                formats={['json', 'html', 'sarif']}
                label="Download the open scan"
              />
            ) : scan.oneOffScanId !== null ? (
              <DownloadButtons
                endpoint="api/scan/export"
                body={{ scan_id: scan.oneOffScanId }}
                stem="reposentinel-report"
                formats={['json', 'html', 'sarif']}
                label="Download the open scan"
              />
            ) : null}
          </>
        ) : (
          <Empty>No scan is open.</Empty>
        )}
      </Section>
      <Section id="open-comparison-export" title="The open comparison">
        {app.comparison ? (
          <DownloadButtons
            endpoint="api/compare/export"
            body={{ comparison_id: app.comparison.comparison_id }}
            stem="reposentinel-comparison"
            formats={['json', 'html']}
            label="Download the open comparison"
          />
        ) : (
          <Empty>No comparison is open.</Empty>
        )}
      </Section>
      {app.session.history && <SavedScanExport />}
    </div>
  );
}

function SavedScanExport() {
  const app = useApp();
  const projects = app.projects ?? [];
  const projectId = currentProject(app)?.id ?? null; // a removed project's id is ignored
  const [history, setHistory] = useState<HistoryList | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (projectId === null) return;
    let cancelled = false;
    post<HistoryList>('api/history', { project_id: projectId })
      .then((list) => {
        if (cancelled) return;
        setHistory(list);
        setScanId(list.scans[0]?.scan.id ?? null);
      })
      .catch((failure: unknown) => !cancelled && setError(messageOf(failure)));
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  return (
    <Section id="saved-export" title="Any saved scan">
      {projects.length === 0 ? (
        <Empty>No projects are registered.</Empty>
      ) : (
        <>
          <div className="form-grid">
            <label htmlFor="export-project">
              Project
              <select
                id="export-project"
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
            <label htmlFor="export-scan">
              Saved scan
              <select
                id="export-scan"
                value={scanId ?? ''}
                onChange={(event) => setScanId(Number(event.target.value))}
                disabled={!history?.scans.length}
              >
                {history?.scans.map(({ scan }) => (
                  <option key={scan.id} value={scan.id}>
                    #{scan.id}, {formatDate(scan.scanned_at)} ({plural(scan.findings, 'finding', 'findings')})
                  </option>
                ))}
              </select>
            </label>
          </div>
          {scanId !== null ? (
            <DownloadButtons
              endpoint="api/history/export"
              body={{ scan_id: scanId }}
              stem={`reposentinel-report-scan-${scanId}`}
              formats={['json', 'html', 'sarif']}
              label="Download the chosen saved scan"
            />
          ) : (
            history && <Empty>This project has no saved scans.</Empty>
          )}
        </>
      )}
      {error && <ErrorNote message={error} />}
    </Section>
  );
}
