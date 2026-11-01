import { useState, type FormEvent } from 'react';
import { messageOf, post } from '../api';
import { ErrorNote, PageHeading, Section, plural } from '../common';
import { ChangesSummary, ChecksTable, CoverageSection, ScanOutcome } from '../ScanView';
import { scanProject } from '../actions';
import { SentinelGlobe } from '../Sentinel';
import { currentProject, fromOneOff, useApp } from '../state';
import type { ScanResponse } from '../types';

export function ScanPage() {
  const app = useApp();
  const [justScanned, setJustScanned] = useState(false);
  return (
    <div className="view">
      <PageHeading
        title="Scan"
        lede="RepoSentinel reads the files currently in a folder and looks for risky files, hard-coded credential patterns and unsafe GitHub Actions workflows. It never changes files, never runs code from the folder, and does not look at Git history."
      />
      <div className="split-forms">
        {app.session.history && <ProjectScanForm onDone={() => setJustScanned(true)} />}
        <OneOffScanForm onDone={() => setJustScanned(true)} />
      </div>
      <div className="scan-state" role="status" aria-live="polite">
        {app.scanning && (
          <div className="scanning-panel">
            <SentinelGlobe scanning size={120} />
            <div>
              <p className="scanning-title">Scanning</p>
              <p className="hint">
                Reading files on this computer. Large folders can take a while. RepoSentinel shows
                no percentage because it cannot measure progress accurately.
              </p>
            </div>
          </div>
        )}
      </div>
      {app.active && !app.scanning && <ScanResult focus={justScanned} />}
    </div>
  );
}

function Limits(props: {
  sizeKb: number;
  maxFiles: number;
  setSizeKb: (value: number) => void;
  setMaxFiles: (value: number) => void;
  disabled: boolean;
  idPrefix: string;
}) {
  const { session } = useApp();
  return (
    <details className="advanced">
      <summary>Scan limits</summary>
      <div className="advanced-grid">
        <label htmlFor={`${props.idPrefix}-size`}>
          Skip files larger than (KiB)
          <input
            id={`${props.idPrefix}-size`}
            type="number"
            min={1}
            max={session.limits.max_file_size_kb}
            value={props.sizeKb}
            onChange={(event) => props.setSizeKb(Number(event.target.value))}
            disabled={props.disabled}
          />
        </label>
        <label htmlFor={`${props.idPrefix}-files`}>
          Stop after this many files
          <input
            id={`${props.idPrefix}-files`}
            type="number"
            min={1}
            max={session.limits.max_files}
            value={props.maxFiles}
            onChange={(event) => props.setMaxFiles(Number(event.target.value))}
            disabled={props.disabled}
          />
        </label>
      </div>
      <p className="hint">
        Use the same limits for scans you want to compare: different limits make results "not
        comparable".
      </p>
    </details>
  );
}

/** Scan a registered project: saved to its history and compared with its previous scan. */
function ProjectScanForm({ onDone }: { onDone: () => void }) {
  const app = useApp();
  const projects = app.projects ?? [];
  const [chosen, setChosen] = useState<number | null>(app.selectedProject);
  const [sizeKb, setSizeKb] = useState(app.session.defaults.max_file_size_kb);
  const [maxFiles, setMaxFiles] = useState(app.session.defaults.max_files);
  const [error, setError] = useState<string | null>(null);
  // A removed project's id is ignored: fall back to the current project.
  const project = projects.find((p) => p.id === chosen) ?? currentProject(app);
  const projectId = project?.id ?? null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (app.scanning) return;
    if (!project) {
      setError('Register a project first (Projects page), or use a one-off scan.');
      return;
    }
    setError(null);
    try {
      await scanProject(app, project, { max_file_size_kb: sizeKb, max_files: maxFiles });
      app.notify(`Scan of ${project.name} finished and saved.`);
      onDone();
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  return (
    <Section
      id="project-scan"
      title="Scan a project and compare"
      intro="The result is saved in this project's local history and compared with its previous scan."
    >
      {projects.length === 0 ? (
        <>
          <p>No projects are registered yet.</p>
          <button type="button" className="primary" onClick={() => app.go('projects')}>
            Register a project
          </button>
        </>
      ) : (
        <form onSubmit={submit} noValidate>
          <label htmlFor="project-select">Project</label>
          <div className="path-row">
            <select
              id="project-select"
              value={projectId ?? ''}
              onChange={(event) => setChosen(Number(event.target.value))}
              disabled={app.scanning}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.available ? '' : ' (folder not found)'}
                </option>
              ))}
            </select>
            <button
              type="submit"
              className="primary"
              disabled={app.scanning}
              aria-busy={app.scanning}
            >
              {app.scanning ? 'Scanning...' : 'Scan again and compare'}
            </button>
          </div>
          {project && (
            <p className="hint">
              Folder: <code>{project.path}</code>
              {project.latest
                ? `. Compared with scan #${project.latest.id}.`
                : '. This will be its first saved scan.'}
            </p>
          )}
          <Limits
            sizeKb={sizeKb}
            maxFiles={maxFiles}
            setSizeKb={setSizeKb}
            setMaxFiles={setMaxFiles}
            disabled={app.scanning}
            idPrefix="project"
          />
        </form>
      )}
      {error && <ErrorNote message={error} />}
    </Section>
  );
}

/** Scan any folder once. Kept in memory only; nothing is saved. */
function OneOffScanForm({ onDone }: { onDone: () => void }) {
  const app = useApp();
  const [path, setPath] = useState('');
  const [sizeKb, setSizeKb] = useState(app.session.defaults.max_file_size_kb);
  const [maxFiles, setMaxFiles] = useState(app.session.defaults.max_files);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (app.scanning) return;
    const trimmed = path.trim();
    if (!trimmed) {
      setError('Enter the full path of the folder to scan.');
      return;
    }
    app.setScanning(true);
    setError(null);
    try {
      const result = await post<ScanResponse>('api/scan', {
        path: trimmed,
        max_file_size_kb: sizeKb,
        max_files: maxFiles,
      });
      app.setActive(fromOneOff(result));
      app.notify('One-off scan finished. It is not saved; download the report to keep it.', 'info');
      onDone();
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      app.setScanning(false);
    }
  }

  return (
    <Section
      id="one-off-scan"
      title="One-off scan of a folder"
      intro="Not saved: the result stays in this page until it is closed. Download the JSON report to keep it."
    >
      <form onSubmit={submit} noValidate>
        <label htmlFor="scan-path">Folder to scan (full path)</label>
        <div className="path-row">
          <input
            id="scan-path"
            name="path"
            type="text"
            spellCheck={false}
            autoComplete="off"
            placeholder="C:\path\to\your-repository"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            aria-describedby="scan-path-hint"
            disabled={app.scanning}
          />
          <button type="submit" className="primary" disabled={app.scanning} aria-busy={app.scanning}>
            {app.scanning ? 'Scanning...' : 'Scan folder'}
          </button>
        </div>
        <p id="scan-path-hint" className="hint">
          Type or paste the folder's full path, for example from File Explorer's address bar.
          Browsers cannot pick a folder for a local program, so there is no Browse button.
        </p>
        <Limits
          sizeKb={sizeKb}
          maxFiles={maxFiles}
          setSizeKb={setSizeKb}
          setMaxFiles={setMaxFiles}
          disabled={app.scanning}
          idPrefix="one-off"
        />
      </form>
      {error && <ErrorNote message={error} />}
    </Section>
  );
}

function ScanResult({ focus }: { focus: boolean }) {
  const app = useApp();
  const scan = app.active;
  if (!scan) return null;
  return (
    <div className="results">
      <ScanOutcome scan={scan} focus={focus} />
      <div className="button-row">
        <button type="button" className="primary" onClick={() => app.go('findings')}>
          Review {plural(scan.report.findings.length, 'finding', 'findings')}
        </button>
        {scan.previous && 'comparison' in scan.previous && (
          <button type="button" onClick={() => app.go('compare')}>
            Open the full comparison
          </button>
        )}
        <button type="button" onClick={() => app.go('reports')}>
          Export
        </button>
      </div>
      <ChangesSummary scan={scan} />
      <CoverageSection report={scan.report} />
      <ChecksTable report={scan.report} />
    </div>
  );
}
