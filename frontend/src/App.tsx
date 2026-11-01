import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import { ApiFailure, messageOf, post, startSession } from './api';
import { scanProject } from './actions';
import { ErrorNote, HISTORY_LIMIT, markNavigation } from './common';
import { Icon, LogoMark } from './icons';
import { ComparePage } from './pages/ComparePage';
import { FindingsPage } from './pages/FindingsPage';
import { HistoryPage } from './pages/HistoryPage';
import { OverviewPage } from './pages/OverviewPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScanPage } from './pages/ScanPage';
import { SettingsPage } from './pages/SettingsPage';
import { SentinelGlobe } from './Sentinel';
import {
  AppContext,
  PAGES,
  currentProject,
  useApp,
  type ActiveScan,
  type AppState,
  type Page,
} from './state';
import type { CompareResponse, Project, Session } from './types';

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [failure, setFailure] = useState<Error | null>(null);

  useEffect(() => {
    startSession()
      .then((started) => {
        if (!started) throw new ApiFailure('no launch code', 401);
        return post<Session>('api/session', {});
      })
      .then(setSession)
      .catch((error: unknown) =>
        setFailure(error instanceof Error ? error : new Error(messageOf(error))),
      );
  }, []);

  if (failure) {
    return (
      <Frame>
        <SessionProblem failure={failure} />
      </Frame>
    );
  }
  if (!session) {
    return (
      <Frame>
        <p className="loading" role="status">
          Connecting to RepoSentinel...
        </p>
      </Frame>
    );
  }
  return <Console session={session} />;
}

/** The page frame used before a session exists (no navigation yet). */
function Frame({ children }: { children: ReactNode }) {
  return (
    <div className="frame">
      <SentinelGlobe size={220} className="frame-globe" />
      <Brand />
      <main id="main" tabIndex={-1} className="frame-main">
        {children}
      </main>
    </div>
  );
}

function Brand() {
  return (
    <div className="brand">
      <LogoMark />
      <div>
        <p className="brand-name">
          Repo<span>Sentinel</span>
        </p>
        <p className="brand-motto">Find it. Fix it. Re-check it.</p>
      </div>
    </div>
  );
}

interface Toast {
  id: number;
  message: string;
  tone: 'ok' | 'info' | 'error';
}

function Console({ session }: { session: Session }) {
  const [page, setPage] = useState<Page>('overview');
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [active, setActive] = useState<ActiveScan | null>(null);
  const [comparison, setComparison] = useState<CompareResponse | null>(null);
  const [selectedProject, selectProject] = useState<number | null>(null);
  const [scanning, setScanning] = useState(false);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const firstNav = useRef<HTMLButtonElement>(null);

  const refreshProjects = useCallback(async () => {
    if (!session.history) return;
    try {
      const reply = await post<{ projects: Project[] }>('api/projects', {});
      setProjects(reply.projects);
      setProjectsError(null);
    } catch (error) {
      setProjectsError(messageOf(error));
    }
  }, [session.history]);

  useEffect(() => {
    void refreshProjects();
  }, [refreshProjects]);

  useEffect(() => {
    document.documentElement.dataset.motion = reduceMotion ? 'reduce' : 'system';
  }, [reduceMotion]);

  const go = useCallback((next: Page) => {
    markNavigation();
    setMenuOpen(false);
    setPage((current) => {
      if (current === next) {
        // The page is already open: move focus to its heading as a new page would.
        document.querySelector<HTMLElement>('main h1')?.focus();
      }
      return next;
    });
    window.scrollTo({ top: 0 });
  }, []);

  const notify = useCallback((message: string, tone: Toast['tone'] = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts((now) => [...now.slice(-2), { id, message, tone }]);
    setTimeout(() => setToasts((now) => now.filter((toast) => toast.id !== id)), 5000);
  }, []);

  // The off-canvas menu (narrow screens): focus moves into it and back out,
  // and Escape closes it.
  useEffect(() => {
    if (!menuOpen) return;
    firstNav.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
        menuButton.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [menuOpen]);

  const state: AppState = useMemo(
    () => ({
      session,
      projects,
      projectsError,
      refreshProjects,
      active,
      setActive,
      comparison,
      setComparison,
      selectedProject,
      selectProject,
      go,
      scanning,
      setScanning,
      notify,
      reduceMotion,
      setReduceMotion,
    }),
    [session, projects, projectsError, refreshProjects, active, comparison, selectedProject, go, scanning, notify, reduceMotion],
  );

  const pages = PAGES.filter((entry) => session.history || !entry.needsHistory);
  const label = PAGES.find((entry) => entry.id === page)?.label ?? '';

  return (
    <AppContext.Provider value={state}>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <div className={`console ${menuOpen ? 'menu-open' : ''}`}>
        <aside className="sidebar" id="sidebar" aria-label="RepoSentinel">
          <div className="sidebar-head">
            <Brand />
            <button
              type="button"
              className="icon-button sidebar-close"
              onClick={() => {
                setMenuOpen(false);
                menuButton.current?.focus();
              }}
            >
              <Icon name="close" />
              <span className="visually-hidden">Close menu</span>
            </button>
          </div>
          <button type="button" className="primary new-scan" onClick={() => go('scan')}>
            <Icon name="plus" /> New scan
          </button>
          <nav aria-label="Main">
            <ul className="nav">
              {pages.map((entry, index) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    className="nav-item"
                    ref={index === 0 ? firstNav : undefined}
                    aria-current={page === entry.id ? 'page' : undefined}
                    onClick={() => go(entry.id)}
                  >
                    <Icon name={entry.icon} />
                    <span className="nav-label">{entry.label}</span>
                    {entry.id === 'findings' && active && (
                      <span className="nav-count">
                        {active.report.findings.length}
                        <span className="visually-hidden"> findings</span>
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <div className="sidebar-foot">
            <p className="local-status">
              <span className="local-dot" aria-hidden="true" /> Runs on this computer only
            </p>
            <p className="version">Version {session.version}</p>
          </div>
        </aside>
        {menuOpen && <div className="scrim" aria-hidden="true" onClick={() => setMenuOpen(false)} />}
        <div className="workspace">
          <TopBar
            page={label}
            onMenu={() => setMenuOpen(true)}
            menuOpen={menuOpen}
            menuButton={menuButton}
          />
          <main id="main" tabIndex={-1}>
            <CurrentPage page={page} />
          </main>
          <footer className="footer">
            <p>{HISTORY_LIMIT}</p>
            <p>
              Findings are potential indicators for human review, not confirmed vulnerabilities.
              RepoSentinel never changes your files and sends nothing over the network.
            </p>
          </footer>
        </div>
      </div>
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.tone}`}>
            <span>{toast.message}</span>
            <button
              type="button"
              className="icon-button"
              onClick={() => setToasts((now) => now.filter((t) => t.id !== toast.id))}
            >
              <Icon name="close" size={14} />
              <span className="visually-hidden">Dismiss</span>
            </button>
          </div>
        ))}
      </div>
    </AppContext.Provider>
  );
}

/** Breadcrumb, project context, scan status and the scan action. */
function TopBar(props: {
  page: string;
  onMenu: () => void;
  menuOpen: boolean;
  menuButton: RefObject<HTMLButtonElement>;
}) {
  const app = useApp();
  const project = currentProject(app);
  const projects = app.projects ?? [];
  const [error, setError] = useState<string | null>(null);

  async function scanNow() {
    setError(null);
    if (!project || !project.available) {
      app.go('scan');
      return;
    }
    try {
      await scanProject(app, project);
      app.notify(`Scan of ${project.name} finished and saved.`);
      app.go('scan');
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  return (
    <header className="topbar">
      <button
        type="button"
        className="icon-button menu-button"
        ref={props.menuButton}
        aria-expanded={props.menuOpen}
        aria-controls="sidebar"
        onClick={props.onMenu}
      >
        <Icon name="menu" />
        <span className="visually-hidden">Open menu</span>
      </button>
      <nav aria-label="Breadcrumb" className="breadcrumb">
        <ol>
          <li>RepoSentinel</li>
          <li aria-current="page">{props.page}</li>
        </ol>
      </nav>
      <div className="topbar-tools">
        {app.scanning && (
          <span className="scan-chip" role="status">
            <span className="pulse" aria-hidden="true" /> Scanning
          </span>
        )}
        {app.session.history && projects.length > 0 && (
          <label className="project-switch">
            <span className="visually-hidden">Current project</span>
            <Icon name="folder" size={16} />
            <select
              value={project?.id ?? ''}
              onChange={(event) => app.selectProject(Number(event.target.value))}
              disabled={app.scanning}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          type="button"
          className="primary small"
          onClick={scanNow}
          disabled={app.scanning}
          aria-busy={app.scanning}
          title={project ? `Scan ${project.name} and compare with its previous scan` : 'Open the Scan page'}
        >
          <Icon name="play" size={14} />
          {app.scanning ? 'Scanning...' : project?.available ? 'Scan project' : 'New scan'}
        </button>
      </div>
      {error && (
        <div className="topbar-error">
          <ErrorNote message={error} />
        </div>
      )}
    </header>
  );
}


function CurrentPage({ page }: { page: Page }) {
  switch (page) {
    case 'overview':
      return <OverviewPage />;
    case 'projects':
      return <ProjectsPage />;
    case 'scan':
      return <ScanPage />;
    case 'findings':
      return <FindingsPage />;
    case 'history':
      return <HistoryPage />;
    case 'compare':
      return <ComparePage />;
    case 'reports':
      return <ReportsPage />;
    case 'settings':
      return <SettingsPage />;
  }
}

function SessionProblem({ failure }: { failure: Error }) {
  const noSession = failure instanceof ApiFailure && failure.status === 401;
  return (
    <div className="panel">
      <h1>{noSession ? 'This page is not connected' : 'RepoSentinel is not available'}</h1>
      {noSession ? (
        <p>
          For your safety, RepoSentinel keeps its session only in the tab that opened its one-time
          link, and forgets it when the page is reloaded or closed. To continue, press Enter in the
          terminal running <code>python -m reposentinel ui</code> and open the new link it prints.
        </p>
      ) : (
        <ErrorNote message={failure.message} />
      )}
    </div>
  );
}
