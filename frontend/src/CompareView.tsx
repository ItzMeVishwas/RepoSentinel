import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { fileToBase64, messageOf, post } from './api';
import {
  DownloadButtons,
  Empty,
  ErrorNote,
  FilterChips,
  HISTORY_LIMIT,
  Section,
  SeverityTag,
  formatBytes,
  formatDate,
  lineText,
  plural,
  toggled,
} from './common';
import type { CompareResponse, Session, Severity, TrackedFinding } from './types';
import { SEVERITIES } from './types';

// Comparison results come from compare.compare_reports on the server; this
// file only displays them. Statuses are never computed in the browser.

export const FAIL_ON = [
  ['low', 'Low and above (default)'],
  ['medium', 'Medium and above'],
  ['high', 'High only'],
  ['info', 'Everything, including info'],
  ['never', 'Never (only unknowns fail)'],
] as const;

/** Compare two JSON report files (from the command line or another computer). */
export function ImportCompareForm(props: {
  session: Session;
  onResult: (result: CompareResponse) => void;
}) {
  const { session } = props;
  const [oldFile, setOldFile] = useState<File | null>(null);
  const [newFile, setNewFile] = useState<File | null>(null);
  const [failOn, setFailOn] = useState('low');
  const [differentRoots, setDifferentRoots] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const limit = session.limits.max_upload_report_bytes;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (running) return;
    if (!oldFile || !newFile) {
      setError('Choose both reports: the earlier one (before) and the later one (after).');
      return;
    }
    const tooBig = [oldFile, newFile].find((file) => file.size > limit);
    if (tooBig) {
      setError(
        `${tooBig.name} is ${formatBytes(tooBig.size)}; the browser interface accepts reports up to ` +
          `${formatBytes(limit)}. Use "reposentinel compare" in a terminal for larger reports.`,
      );
      return;
    }
    setRunning(true);
    setError(null);
    try {
      props.onResult(
        await post<CompareResponse>('api/compare', {
          old: { name: oldFile.name, data_base64: await fileToBase64(oldFile) },
          new: { name: newFile.name, data_base64: await fileToBase64(newFile) },
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

  return (
    <Section
      id="import-compare"
      title="Compare two JSON report files"
      intro="For reports saved with 'Download JSON' or 'reposentinel scan PATH --format json'. The files are read by RepoSentinel on this computer and are not saved."
    >
        <form className="compare-form" onSubmit={submit} noValidate>
          <div className="file-pair">
            <FileField id="old-report" label="Before: the earlier JSON report" file={oldFile} onChange={setOldFile} disabled={running} />
            <FileField id="new-report" label="After: the later JSON report" file={newFile} onChange={setNewFile} disabled={running} />
          </div>
          <details className="advanced">
            <summary>Options</summary>
            <div className="advanced-grid">
              <label>
                Treat as failing
                <select value={failOn} onChange={(event) => setFailOn(event.target.value)} disabled={running}>
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
                The reports were made from different folder paths, and I confirm they describe
                the same repository. RepoSentinel cannot check this.
              </label>
            </div>
          </details>
          <button type="submit" className="primary" disabled={running} aria-busy={running}>
            {running ? 'Comparing...' : 'Compare reports'}
          </button>
        </form>
        <p className="status-line" role="status" aria-live="polite">
          {running ? 'Comparing the two reports...' : ''}
        </p>
        {error && <ErrorNote message={error} />}
    </Section>
  );
}

function FileField(props: {
  id: string;
  label: string;
  file: File | null;
  onChange: (file: File | null) => void;
  disabled: boolean;
}) {
  return (
    <div className="file-field">
      <label htmlFor={props.id}>{props.label}</label>
      <input
        id={props.id}
        type="file"
        accept=".json,application/json"
        disabled={props.disabled}
        onChange={(event) => props.onChange(event.target.files?.[0] ?? null)}
      />
      <p className="hint">
        {props.file
          ? `${props.file.name} (${formatBytes(props.file.size)})`
          : 'Saved with "Download JSON" or: reposentinel scan PATH --format json --output FILE'}
      </p>
    </div>
  );
}

export function CompareResults({ response }: { response: CompareResponse }) {
  const c = response.comparison;
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => headingRef.current?.focus(), [response.comparison_id]);
  const [statuses, setStatuses] = useState<Set<string>>(new Set());
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());

  const statusOptions = useMemo(() => {
    const labels = new Map<string, string>();
    for (const finding of c.findings) {
      if (!labels.has(finding.status)) labels.set(finding.status, finding.status.replace(/_/g, ' '));
    }
    return [...labels].map(([value, label]) => ({
      value,
      label,
      count: c.findings.filter((finding) => finding.status === value).length,
    }));
  }, [c.findings]);

  const shown = c.findings.filter(
    (finding) =>
      (statuses.size === 0 || statuses.has(finding.status)) &&
      (severities.size === 0 || severities.has(finding.severity)),
  );
  const inGroup = (group: string[]) => shown.filter((finding) => group.includes(finding.status));
  const detected = inGroup(response.groups.detected);
  const unknown = inGroup(response.groups.unknown);
  const noLonger = inGroup(response.groups.no_longer_detected);
  const reminders = shown.filter((finding) => finding.credential_reminder);
  const filtered = shown.length !== c.findings.length;

  return (
    <div className="results" aria-labelledby="compare-results-title">
      <div className={`outcome ${c.unknowns ? 'outcome-incomplete' : c.exit_code === 1 ? 'outcome-findings' : 'outcome-clean'}`}>
        <h2 id="compare-results-title" ref={headingRef} tabIndex={-1}>
          {c.headline}
        </h2>
        <p className="outcome-headline">{c.scope}</p>
        <p className="history-limit">{HISTORY_LIMIT}</p>
        <dl className="facts">
          <div>
            <dt>Before</dt>
            <dd>
              <code>{c.old.report}</code>, {formatDate(c.old.scanned_at)}, {c.old.outcome}
            </dd>
          </div>
          <div>
            <dt>After</dt>
            <dd>
              <code>{c.new.report}</code>, {formatDate(c.new.scanned_at)}, {c.new.outcome}
            </dd>
          </div>
          <div className="wide">
            <dt>Folder</dt>
            <dd>
              {c.targets_match ? (
                <code>{c.new.target}</code>
              ) : (
                <>
                  <code>{c.old.target}</code> and <code>{c.new.target}</code>: declared the same
                  repository by you
                </>
              )}
            </dd>
          </div>
        </dl>
        <p className="exit-line">{c.exit_explanation} (the same result as the command line)</p>
      </div>

      <ul className="status-strip" aria-label="Comparison summary">
        {[
          {
            tone: 'attention',
            label: 'New',
            count: (c.counts.new ?? 0) + (c.counts.new_not_examined_before ?? 0),
            why: 'Detected now, not in the earlier scan (or the file was not examined then).',
          },
          {
            tone: 'attention',
            label: 'Still detected',
            count: c.counts.still_detected ?? 0,
            why: 'Detected in both scans.',
          },
          {
            tone: 'neutral',
            label: 'No longer detected',
            count: (c.counts.not_detected_on_recheck ?? 0) + (c.counts.not_detected_file_removed ?? 0),
            why: 'Re-checked and not found in the files examined. Not proof that it is fixed.',
          },
          {
            tone: 'unknown',
            label: 'Not re-checked',
            count: c.counts.not_rechecked ?? 0,
            why: 'The later scan did not examine where it was (a check or file was not covered).',
          },
          {
            tone: 'unknown',
            label: 'Not comparable',
            count: c.counts.not_comparable ?? 0,
            why: 'The scans used different rules or settings, so absence means nothing.',
          },
        ].map((group) => (
          <li key={group.label} className={`strip-item strip-${group.tone}`}>
            <span className="strip-count">{group.count}</span>
            <span className="strip-label">{group.label}</span>
            <span className="strip-why">{group.why}</span>
          </li>
        ))}
      </ul>

      <div className="filters">
        <FilterChips
          label="Status"
          options={statusOptions}
          selected={statuses}
          onToggle={(value) => setStatuses((current) => toggled(current, value))}
        />
        <FilterChips
          label="Severity"
          options={SEVERITIES.map((severity) => ({
            value: severity,
            label: severity,
            count: c.findings.filter((finding) => finding.severity === severity).length,
          }))}
          selected={severities}
          onToggle={(value) => setSeverities((current) => toggled(current, value))}
        />
      </div>
      <p className="filter-status" role="status">
        Showing {shown.length} of {plural(c.findings.length, 'tracked finding', 'tracked findings')}.
        {filtered && (
          <>
            {' '}
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setStatuses(new Set());
                setSeverities(new Set());
              }}
            >
              Show all
            </button>
          </>
        )}
      </p>

      <Section id="cmp-detected" title="Still detected and new" count={detected.length} tone={detected.length ? 'attention' : 'quiet'}>
        {detected.length === 0 ? <Empty>None.</Empty> : <TrackedList findings={detected} reasonLabel="Why" />}
      </Section>

      <Section
        id="cmp-unknown"
        title="Still unknown"
        count={unknown.length + c.check_problems.length + c.coverage_errors.length}
        tone={c.unknowns ? 'unknown' : 'quiet'}
        intro="These could not be re-checked or compared. Each one says why and what would turn it into a real re-check."
      >
        {unknown.length + c.check_problems.length + c.coverage_errors.length === 0 && (
          <Empty>None: every finding in the earlier report was re-checked.</Empty>
        )}
        {unknown.length > 0 && <TrackedList findings={unknown} reasonLabel="Reason" />}
        {c.check_problems.length > 0 && (
          <ul className="plain-list">
            {c.check_problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        )}
        {c.coverage_errors.length > 0 && (
          <PathList caption="Files or folders the later scan could not cover" items={c.coverage_errors} />
        )}
      </Section>

      <Section id="cmp-not-examined" title="Not examined in the later scan" count={c.not_examined.length}>
        {c.not_examined.length === 0 ? (
          <Empty>Nothing was skipped by policy (exclusions, size limit, binary files, links).</Empty>
        ) : (
          <PathList caption="Skipped by policy" items={c.not_examined} />
        )}
      </Section>

      <Section id="cmp-reminders" title="Credential reminders" count={reminders.length}>
        {reminders.length === 0 ? (
          <Empty>None: no credential finding became less detected.</Empty>
        ) : (
          <>
            <p className="reminder">{reminders[0]?.credential_reminder}</p>
            <ul className="plain-list">
              {reminders.map((finding) => (
                <li key={finding.fingerprint}>
                  <code className="rule-id">{finding.rule_id}</code> <code>{where(finding)}</code> ({finding.status_text})
                </li>
              ))}
            </ul>
          </>
        )}
      </Section>

      <Section
        id="cmp-no-longer"
        title="No longer detected"
        count={noLonger.length}
        intro="Each of these was re-checked in the files examined. That is not proof that the problem is gone: read what the re-check does not show."
      >
        {noLonger.length === 0 ? <Empty>None.</Empty> : <TrackedList findings={noLonger} reasonLabel="Re-check" showLimits />}
      </Section>

      <Section id="cmp-checks" title="Checks and files examined" count={c.checks.length}>
        <p>Files examined by at least one check in the later scan: {c.files_examined}.</p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Check</th>
                <th scope="col">Before</th>
                <th scope="col">After</th>
                <th scope="col" className="num">Files examined (after)</th>
              </tr>
            </thead>
            <tbody>
              {c.checks.map((check) => (
                <tr key={check.id}>
                  <th scope="row">{check.name}</th>
                  <td>{check.old_status ?? 'did not run'}</td>
                  <td>{check.new_status ?? 'did not run'}</td>
                  <td className="num">{check.new_examined ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {(c.config_differences.length > 0 || c.notes.length > 0) && (
        <Section id="cmp-notes" title="Notes" tone="unknown">
          <ul className="plain-list">
            {c.config_differences.map((difference) => (
              <li key={difference}>
                <strong>Settings differ:</strong> {difference}
              </li>
            ))}
            {c.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </Section>
      )}

      <Section id="cmp-summary" title="Summary">
        {c.summary.map((sentence) => (
          <p key={sentence}>{sentence}</p>
        ))}
        <p className="kv-note">{c.disclaimer}</p>
      </Section>

      <Section
        id="cmp-downloads"
        title="Save this comparison"
        intro="Produced by RepoSentinel itself, the same as 'reposentinel compare --format json|html'."
      >
        <DownloadButtons
          endpoint="api/compare/export"
          body={{ comparison_id: response.comparison_id }}
          stem="reposentinel-comparison"
          formats={['json', 'html']}
          label="Download the comparison"
        />
      </Section>
    </div>
  );
}

function where(finding: TrackedFinding): string {
  if (!finding.path) return '(whole repository)';
  const parts: string[] = [];
  if (finding.new_lines.length) parts.push(lineText(finding.new_lines));
  if (finding.old_lines.length && finding.old_lines.join() !== finding.new_lines.join()) {
    parts.push(`before: ${lineText(finding.old_lines)}`);
  }
  return parts.length ? `${finding.path} (${parts.join('; ')})` : finding.path;
}

function TrackedList(props: { findings: TrackedFinding[]; reasonLabel: string; showLimits?: boolean }) {
  return (
    <ol className="finding-list">
      {props.findings.map((finding) => (
        <li key={finding.fingerprint} className={`finding tracked sev-border-${finding.severity}`}>
          <div className="tracked-head">
            <SeverityTag severity={finding.severity} />
            <span className="status-pill">{finding.status_text}</span>
            <span className="finding-title">
              <code className="rule-id">{finding.rule_id}</code> {finding.title}
            </span>
          </div>
          <dl className="kv">
            <dt>Location</dt>
            <dd>
              <code>{where(finding)}</code>
            </dd>
            <dt>Occurrences</dt>
            <dd>
              {finding.old_occurrences} before, {finding.new_occurrences} after
            </dd>
            <dt>{props.reasonLabel}</dt>
            <dd>{finding.explanation}</dd>
            {finding.evidence && (
              <>
                <dt>Evidence</dt>
                <dd>
                  <code>{finding.evidence}</code>
                </dd>
              </>
            )}
            {props.showLimits && (
              <>
                <dt>Does not show</dt>
                <dd>{finding.recheck_limits}</dd>
              </>
            )}
            {!props.showLimits && finding.new_occurrences > 0 && (
              <>
                <dt>What to do</dt>
                <dd>{finding.remediation}</dd>
              </>
            )}
          </dl>
        </li>
      ))}
    </ol>
  );
}

function PathList({ caption, items }: { caption: string; items: CompareResponse['comparison']['not_examined'] }) {
  return (
    <div className="table-wrap">
      <table>
        <caption>
          {caption} ({items.length})
        </caption>
        <thead>
          <tr>
            <th scope="col">Path</th>
            <th scope="col">Reason</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={`${item.path}:${item.reason}`}>
              <td>
                <code>{item.path}</code>
              </td>
              <td>{item.reason.replace('_', ' ')}</td>
              <td>{item.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
