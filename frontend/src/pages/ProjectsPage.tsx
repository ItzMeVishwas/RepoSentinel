import { useState, type FormEvent } from 'react';
import { messageOf, post } from '../api';
import { openSavedScan, scanProject } from '../actions';
import {
  ConfirmAction,
  Empty,
  ErrorNote,
  OUTCOME_WORDS,
  PageHeading,
  PathText,
  Section,
  StatusWord,
  formatDate,
  plural,
} from '../common';
import { Icon } from '../icons';
import { useApp } from '../state';
import type { Project } from '../types';

export function ProjectsPage() {
  const app = useApp();
  const projects = app.projects;
  return (
    <div className="view">
      <PageHeading
        title="Projects"
        lede="A project is a folder you scan regularly. Registering it is how you turn on scan history: each scan made through it is saved on this computer and compared with the one before. Nothing is saved for folders you only scan once."
      />
      <AddProject />
      {app.projectsError && <ErrorNote message={app.projectsError} />}
      <Section id="project-list" title="Registered projects" count={projects?.length ?? 0}>
        {projects === null ? (
          !app.projectsError && (
            <p className="loading" role="status">
              Loading projects...
            </p>
          )
        ) : projects.length === 0 ? (
          <Empty>No projects yet. Register a folder above to start its history.</Empty>
        ) : (
          <ul className="project-list">
            {projects.map((project) => (
              <ProjectCard key={project.id} project={project} />
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function AddProject() {
  const app = useApp();
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (!name.trim() || !path.trim()) {
      setError('Enter both a display name and the full path of the folder.');
      return;
    }
    setBusy(true);
    setError(null);
    setAdded(null);
    try {
      const reply = await post<{ project: { id: number; name: string } }>('api/projects/add', {
        name,
        path: path.trim(),
      });
      setAdded(reply.project.name);
      app.notify(`Registered "${reply.project.name}".`);
      app.selectProject(reply.project.id);
      setName('');
      setPath('');
      await app.refreshProjects();
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section
      id="add-project"
      title="Register a project"
      intro="Saved scans hold the redacted JSON report (findings with hidden secret values, file paths, coverage and settings). They never hold file contents or secret values, and they stay in your user data folder, outside the project. Settings shows where, and deletes it."
    >
      <form className="form-grid" onSubmit={submit} noValidate>
        <label htmlFor="project-name">
          Display name
          <input
            id="project-name"
            type="text"
            className="plain"
            maxLength={80}
            autoComplete="off"
            value={name}
            onChange={(event) => setName(event.target.value)}
            disabled={busy}
          />
        </label>
        <label htmlFor="project-path">
          Folder (full path)
          <input
            id="project-path"
            type="text"
            spellCheck={false}
            autoComplete="off"
            placeholder="C:\path\to\your-repository"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            aria-describedby="project-path-hint"
            disabled={busy}
          />
        </label>
        <p id="project-path-hint" className="hint wide">
          Paste the path from File Explorer's address bar. Browsers cannot pick a folder for a local
          program, so there is no Browse button.
        </p>
        <div className="wide">
          <button type="submit" className="primary" disabled={busy} aria-busy={busy}>
            {busy ? 'Registering...' : 'Register project'}
          </button>
        </div>
      </form>
      <p className="status-line" role="status">
        {added ? `Registered "${added}". Scan it from its card below or from the Scan page.` : ''}
      </p>
      {error && <ErrorNote message={error} />}
    </Section>
  );
}

function ProjectCard({ project }: { project: Project }) {
  const app = useApp();
  const [mode, setMode] = useState<'view' | 'rename' | 'move'>('view');
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const latest = project.latest;
  const headingId = `project-${project.id}`;

  async function run(action: () => Promise<unknown>, done?: string) {
    setError(null);
    setMessage(null);
    try {
      await action();
      if (done) setMessage(done);
      await app.refreshProjects();
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  async function scanAgain() {
    setError(null);
    try {
      await scanProject(app, project);
      app.notify(`Scan of ${project.name} finished and saved.`);
      app.go('scan');
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  async function submitEdit(event: FormEvent) {
    event.preventDefault();
    const endpoint = mode === 'rename' ? 'api/projects/rename' : 'api/projects/move';
    const body = mode === 'rename' ? { project_id: project.id, name: value } : { project_id: project.id, path: value.trim() };
    await run(async () => {
      await post(endpoint, body);
      setMode('view');
    }, mode === 'rename' ? 'Renamed.' : 'Folder location updated.');
  }

  return (
    <li className="project-card" aria-labelledby={headingId}>
      <div className="project-head">
        <h3 id={headingId}>{project.name}</h3>
        {project.available ? (
          <StatusWord tone="neutral">Folder found</StatusWord>
        ) : (
          <StatusWord tone="unknown">Folder not found</StatusWord>
        )}
      </div>
      <p className="project-path">
        <PathText path={project.path} />
      </p>
      {!project.available && (
        <p className="note-bar note-unknown">
          This folder no longer exists or cannot be opened. If it was moved or renamed, update its
          location under "Manage"; its history is kept.
        </p>
      )}
      {latest ? (
        <dl className="project-facts">
          <div>
            <dt>Last scan</dt>
            <dd>
              #{latest.id}, {formatDate(latest.scanned_at)}
            </dd>
          </div>
          <div>
            <dt>Outcome</dt>
            <dd className={`outcome-text-${latest.outcome}`}>{OUTCOME_WORDS[latest.outcome]}</dd>
          </div>
          <div>
            <dt>Findings</dt>
            <dd>
              {latest.findings}
              <span className="cell-sub">
                {latest.severity.high} high, {latest.severity.medium} medium, {latest.severity.low} low
              </span>
            </dd>
          </div>
          <div>
            <dt>Checks completed</dt>
            <dd>
              {latest.checks_completed} of {latest.checks_total}
              {latest.coverage_errors > 0 && <span className="cell-sub">{plural(latest.coverage_errors, 'unreadable item', 'unreadable items')}</span>}
            </dd>
          </div>
        </dl>
      ) : (
        <p className="project-latest">Not scanned yet.</p>
      )}
      {mode === 'view' ? (
        <>
          <div className="button-row">
            <button
              type="button"
              className="primary"
              onClick={scanAgain}
              disabled={app.scanning || !project.available}
              aria-busy={app.scanning}
            >
              <Icon name="play" size={14} />
              {app.scanning ? 'Scanning...' : latest ? 'Scan again and compare' : 'Run first scan'}
            </button>
            {latest && (
              <button
                type="button"
                onClick={() =>
                  run(async () => {
                    await openSavedScan(app, latest.id);
                    app.selectProject(project.id);
                    app.go('findings');
                  })
                }
              >
                Open latest<span className="visually-hidden"> scan of {project.name}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                app.selectProject(project.id);
                app.go('history');
              }}
            >
              History<span className="visually-hidden"> of {project.name}</span>
            </button>
          </div>
          <details className="manage">
            <summary>
              Manage<span className="visually-hidden"> {project.name}</span>
            </summary>
            <div className="manage-grid">
              <div>
                <p className="manage-title">Name and location</p>
                <div className="button-row">
                  <button
                    type="button"
                    onClick={() => {
                      setValue(project.name);
                      setMode('rename');
                    }}
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setValue(project.path);
                      setMode('move');
                    }}
                  >
                    Change location
                  </button>
                </div>
              </div>
              <div>
                <p className="manage-title">Clear history</p>
                <p className="hint">Deletes the saved scans. The project stays registered.</p>
                <ConfirmAction
                  label="Clear history"
                  confirmLabel="Delete its saved scans"
                  question={`Delete every saved scan of "${project.name}"? The project stays registered. This cannot be undone.`}
                  onConfirm={() =>
                    run(async () => {
                      await post('api/projects/clear-history', { project_id: project.id });
                      if (app.active?.project?.id === project.id) app.setActive(null);
                    }, 'Its saved scans were deleted.')
                  }
                />
              </div>
              <div>
                <p className="manage-title">Remove project</p>
                <p className="hint">Forgets the project and its saved scans. The folder itself is not touched.</p>
                <ConfirmAction
                  label="Remove project"
                  confirmLabel="Remove project and its history"
                  question={`Remove "${project.name}" and delete all of its saved scans? The folder itself is not touched. This cannot be undone.`}
                  onConfirm={async () => {
                    await post('api/projects/remove', { project_id: project.id });
                    if (app.active?.project?.id === project.id) app.setActive(null);
                    if (app.selectedProject === project.id) app.selectProject(null);
                    app.notify(`Removed "${project.name}" and its saved scans.`, 'info');
                    await app.refreshProjects();
                  }}
                />
              </div>
            </div>
          </details>
        </>
      ) : (
        <form className="inline-edit" onSubmit={submitEdit} noValidate>
          <label htmlFor={`${headingId}-edit`}>{mode === 'rename' ? 'New display name' : 'New folder location (full path)'}</label>
          <div className="path-row">
            <input
              id={`${headingId}-edit`}
              type="text"
              className={mode === 'rename' ? 'plain' : undefined}
              autoComplete="off"
              spellCheck={false}
              value={value}
              onChange={(event) => setValue(event.target.value)}
            />
            <button type="submit" className="primary">
              Save
            </button>
            <button type="button" onClick={() => setMode('view')}>
              Cancel
            </button>
          </div>
        </form>
      )}
      <p className="status-line" role="status">
        {message ?? ''}
      </p>
      {error && <ErrorNote message={error} />}
    </li>
  );
}
