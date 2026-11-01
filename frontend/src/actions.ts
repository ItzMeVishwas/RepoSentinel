import { post } from './api';
import { comparisonOf, fromStored, type AppState } from './state';
import type { Project, StoredScanResponse } from './types';

/**
 * Scan a registered project: the server saves the run and compares it with the
 * project's previous scan. The result becomes the open scan and comparison.
 * Throws ApiFailure with a message to show.
 */
export async function scanProject(
  app: AppState,
  project: Project,
  limits?: { max_file_size_kb: number; max_files: number },
): Promise<void> {
  if (app.scanning) return; // no accidental second scan
  app.setScanning(true);
  try {
    const result = await post<StoredScanResponse>('api/projects/scan', {
      project_id: project.id,
      ...limits,
    });
    app.setActive(fromStored(result, project));
    app.setComparison(comparisonOf(result.previous));
    app.selectProject(project.id);
    await app.refreshProjects();
  } finally {
    app.setScanning(false);
  }
}

/** Open a saved scan (with its comparison against the scan before it). */
export async function openSavedScan(app: AppState, scanId: number): Promise<void> {
  const result = await post<StoredScanResponse>('api/history/scan', { scan_id: scanId });
  const project = app.projects?.find((p) => p.id === result.history_scan.project_id);
  app.setActive(fromStored(result, project));
  app.setComparison(comparisonOf(result.previous));
}
