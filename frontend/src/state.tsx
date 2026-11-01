import { createContext, useContext } from 'react';
import type { IconName } from './icons';
import type {
  CompareResponse,
  Previous,
  Project,
  ScanReport,
  ScanResponse,
  Session,
  StoredScanResponse,
} from './types';

// State shared by the pages. It lives in memory only: reloading the page
// forgets it (and ends the session). Saved scans are kept by the Python
// server in the local history, never by the browser.

export type Page =
  | 'overview'
  | 'projects'
  | 'scan'
  | 'findings'
  | 'history'
  | 'compare'
  | 'reports'
  | 'settings';

export const PAGES: { id: Page; label: string; icon: IconName; needsHistory?: boolean }[] = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'projects', label: 'Projects', icon: 'projects', needsHistory: true },
  { id: 'scan', label: 'Scan', icon: 'scan' },
  { id: 'findings', label: 'Findings', icon: 'findings' },
  { id: 'history', label: 'History', icon: 'history', needsHistory: true },
  { id: 'compare', label: 'Compare', icon: 'compare' },
  { id: 'reports', label: 'Reports', icon: 'reports' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

/** The scan the Overview, Findings and Reports pages describe. */
export interface ActiveScan {
  source: 'project' | 'one-off';
  project: { id: number; name: string } | null;
  historyScanId: number | null; // a saved scan
  oneOffScanId: string | null; // an unsaved scan kept in the server's memory
  report: ScanReport;
  outcomeHeadline: string;
  exitCode: number;
  exitExplanation: string;
  previous: Previous | null;
}

export function fromStored(response: StoredScanResponse, project: Project | undefined): ActiveScan {
  return {
    source: 'project',
    project: project ? { id: project.id, name: project.name } : null,
    historyScanId: response.history_scan.id,
    oneOffScanId: null,
    report: response.report,
    outcomeHeadline: response.outcome_headline,
    exitCode: response.exit_code,
    exitExplanation: response.exit_explanation,
    previous: response.previous,
  };
}

export function fromOneOff(response: ScanResponse): ActiveScan {
  return {
    source: 'one-off',
    project: null,
    historyScanId: null,
    oneOffScanId: response.scan_id,
    report: response.report,
    outcomeHeadline: response.outcome_headline,
    exitCode: response.exit_code,
    exitExplanation: response.exit_explanation,
    previous: null,
  };
}

/** The previous-scan comparison, when there is one that worked. */
export function comparisonOf(previous: Previous | null): Extract<Previous, { comparison: unknown }> | null {
  return previous && 'comparison' in previous ? previous : null;
}

export interface AppState {
  session: Session;
  projects: Project[] | null; // null: not loaded (or history is off)
  projectsError: string | null;
  refreshProjects: () => Promise<void>;
  active: ActiveScan | null;
  setActive: (scan: ActiveScan | null) => void;
  comparison: CompareResponse | null;
  setComparison: (comparison: CompareResponse | null) => void;
  selectedProject: number | null;
  selectProject: (id: number | null) => void;
  go: (page: Page) => void;
  scanning: boolean;
  setScanning: (running: boolean) => void;
  /** A short confirmation shown in the corner and announced politely. */
  notify: (message: string, tone?: 'ok' | 'info' | 'error') => void;
  /** Session-only preference (nothing is stored in the browser). */
  reduceMotion: boolean;
  setReduceMotion: (reduce: boolean) => void;
}

export const AppContext = createContext<AppState | null>(null);

export function useApp(): AppState {
  const state = useContext(AppContext);
  if (!state) throw new Error('useApp outside the app');
  return state;
}

/**
 * The project the pages are about: the selected one if it still exists,
 * otherwise the first registered project (a removed project's id is ignored).
 */
export function currentProject(app: Pick<AppState, 'projects' | 'selectedProject'>): Project | undefined {
  const projects = app.projects ?? [];
  return projects.find((project) => project.id === app.selectedProject) ?? projects[0];
}
