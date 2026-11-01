// Shapes of the data the local API returns. They mirror the Python renderers:
// report_to_dict (scan report schema 1.1) and comparison_to_dict (comparison
// schema 1.0). The browser only displays these values; it never computes a
// finding, a status or an exit code itself.

export type Severity = 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  confidence: string;
  version: number;
  description: string;
  severity_rationale: string;
  remediation: string;
  limitations: string;
  recheck_limits: string;
}

export interface Session {
  version: string;
  history: boolean; // projects and history available (not with --no-history)
  defaults: { max_file_size_kb: number; max_files: number };
  limits: { max_upload_report_bytes: number; max_file_size_kb: number; max_files: number };
  rules: Rule[];
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: string;
  summary: string;
  evidence: string;
  location: { path: string; line: number | null } | null;
  remediation: string;
  check: string;
  fingerprint: string;
  rule_version: number | null;
}

export interface CheckEntry {
  id: string;
  name: string;
  status: 'completed' | 'failed' | 'skipped';
  findings: number;
  examined: number | null;
  message: string;
}

export interface CoverageEntry {
  path: string;
  reason: string;
  detail: string;
  is_error?: boolean;
}

export interface ScanReport {
  schema_version: string;
  tool: { name: string; version: string };
  target: string;
  scanned_at: string;
  outcome: 'clean' | 'findings' | 'incomplete';
  disclaimer: string;
  notes: string[];
  summary: { files_in_scope: number; coverage_errors: number; total_findings: number };
  checks: CheckEntry[];
  findings: Finding[];
  coverage: CoverageEntry[];
}

export interface ScanResponse {
  scan_id: string;
  report: ScanReport;
  outcome_headline: string;
  exit_code: number;
  exit_explanation: string;
}

export interface TrackedFinding {
  fingerprint: string;
  status: string;
  status_text: string;
  explanation: string;
  rule_id: string;
  title: string;
  check: string;
  severity: Severity;
  confidence: string;
  path: string | null;
  old_lines: number[];
  new_lines: number[];
  old_occurrences: number;
  new_occurrences: number;
  evidence: string;
  remediation: string;
  recheck_limits: string;
  credential_reminder: string | null;
}

export interface ReportInfo {
  report: string;
  target: string;
  scanned_at: string;
  tool_version: string;
  outcome: string;
  files_in_scope: number;
}

export interface Comparison {
  comparison_schema_version: string;
  old: ReportInfo;
  new: ReportInfo;
  targets_match: boolean;
  different_roots_declared: boolean;
  scope: string;
  headline: string;
  summary: string[];
  disclaimer: string;
  fail_on: string;
  exit_code: number;
  exit_explanation: string;
  counts: Record<string, number>;
  unknowns: number;
  files_examined: number;
  findings: TrackedFinding[];
  checks: {
    id: string;
    name: string;
    old_status: string | null;
    new_status: string | null;
    old_examined: number | null;
    new_examined: number | null;
  }[];
  check_problems: string[];
  coverage_errors: CoverageEntry[];
  not_examined: CoverageEntry[];
  config_differences: string[];
  notes: string[];
}

export interface CompareResponse {
  comparison_id: string;
  comparison: Comparison;
  groups: { detected: string[]; unknown: string[]; no_longer_detected: string[] };
}

// --- local projects and history (history.py, via webui/api.py) -------------------

export interface ScanRecord {
  id: number;
  project_id: number;
  scanned_at: string;
  tool_version: string;
  outcome: 'clean' | 'findings' | 'incomplete';
  files_in_scope: number;
  findings: number;
  severity: Record<Severity, number>;
  checks_completed: number;
  checks_total: number;
  coverage_errors: number;
  not_examined: number;
}

export interface Project {
  id: number;
  name: string;
  path: string;
  created_at: string;
  available: boolean;
  latest: ScanRecord | null;
}

export type TimelineChanges =
  | { previous_scan_id: number; counts: Record<string, number>; unknowns: number; recurring: number }
  | { previous_scan_id: number; error: string };

export interface HistoryList {
  project: { id: number; name: string; path: string };
  scans: { scan: ScanRecord; changes: TimelineChanges | null }[];
  max_scans: number;
}

/** The comparison of a stored scan with the project's previous scan. */
export type Previous =
  | { scan_id: number; error: string }
  | (CompareResponse & {
      scan_id: number;
      changes: Record<string, string>; // fingerprint -> status, for findings in this scan
      recurring: string[]; // fingerprints also seen in a scan before the previous one
    });

export interface StoredScanResponse {
  history_scan: ScanRecord;
  scan_id: null;
  report: ScanReport;
  outcome_headline: string;
  exit_code: number;
  exit_explanation: string;
  previous: Previous | null;
}

export interface DataInfo {
  data_dir: string;
  database: string;
  exists: boolean;
  bytes: number;
  projects: number;
  scans: number;
  schema_version: number;
  max_scans_per_project: number;
}
