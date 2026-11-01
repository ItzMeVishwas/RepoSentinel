import { useEffect, useRef } from 'react';
import { Empty, OUTCOME_WORDS, Section, formatDate, plural } from './common';
import type { ActiveScan } from './state';
import { comparisonOf } from './state';
import type { CoverageEntry, Finding, Rule, ScanReport } from './types';

// Pieces of a scan result, shared by the Scan, Findings and Overview pages.
// Every value shown comes from the Python report (report_to_dict).

export function findingLocation(finding: Finding): string {
  if (!finding.location) return '(whole repository)';
  return finding.location.line
    ? `${finding.location.path}, line ${finding.location.line}`
    : finding.location.path;
}

/** The outcome card: what was scanned, the outcome in words, and the exit code. */
export function ScanOutcome({ scan, focus = false }: { scan: ActiveScan; focus?: boolean }) {
  const report = scan.report;
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focus) headingRef.current?.focus();
  }, [focus, scan]);
  const notCompleted = report.checks.filter((check) => check.status !== 'completed');
  return (
    <section className={`outcome outcome-${report.outcome}`} aria-labelledby="scan-results-title">
      <p className="eyebrow">
        {scan.source === 'project'
          ? `Saved scan #${scan.historyScanId} of ${scan.project?.name ?? 'a project'}`
          : 'One-off scan (not saved to history)'}
      </p>
      <h2 id="scan-results-title" ref={headingRef} tabIndex={-1}>
        {OUTCOME_WORDS[report.outcome]}
      </h2>
      <p className="outcome-headline">{scan.outcomeHeadline}</p>
      <dl className="facts">
        <div className="wide">
          <dt>Folder</dt>
          <dd>
            <code>{report.target}</code>
          </dd>
        </div>
        <div>
          <dt>Files examined</dt>
          <dd>{report.summary.files_in_scope}</dd>
        </div>
        <div>
          <dt>Checks completed</dt>
          <dd>
            {report.checks.length - notCompleted.length} of {report.checks.length}
          </dd>
        </div>
        <div>
          <dt>Findings</dt>
          <dd>{report.findings.length}</dd>
        </div>
        <div>
          <dt>Scanned</dt>
          <dd>{formatDate(report.scanned_at)}</dd>
        </div>
      </dl>
      <p className="scope">
        Checked: current files only. Git history was not scanned.{' '}
        {report.outcome === 'clean' &&
          'This means only that these checks found nothing in the files they examined; it does not mean the repository is secure.'}
      </p>
      {report.notes.map((note) => (
        <p className="note" key={note}>
          {note}
        </p>
      ))}
      <p className="exit-line">{scan.exitExplanation} (the same result as the command line)</p>
    </section>
  );
}

/** What changed since the project's previous saved scan, in counts. */
export function ChangesSummary({ scan }: { scan: ActiveScan }) {
  if (scan.source !== 'project') return null;
  const previous = scan.previous;
  if (!previous) {
    return (
      <Section id="changes" title="Compared with the previous scan">
        <Empty>This is the project's first saved scan, so there is nothing to compare with yet.</Empty>
      </Section>
    );
  }
  const result = comparisonOf(previous);
  if (!result) {
    return (
      <Section id="changes" title="Compared with the previous scan" tone="unknown">
        <p>
          Scan #{scan.historyScanId} could not be compared with scan #{previous.scan_id}:{' '}
          {'error' in previous ? previous.error : ''}
        </p>
      </Section>
    );
  }
  const c = result.comparison;
  const count = (statuses: string[]) => statuses.reduce((sum, status) => sum + (c.counts[status] ?? 0), 0);
  const rows: [string, number, string][] = [
    ['New', (c.counts.new ?? 0) + (c.counts.new_not_examined_before ?? 0), 'attention'],
    ['Still detected', c.counts.still_detected ?? 0, 'attention'],
    ['Detected again after an earlier scan', result.recurring.length, 'attention'],
    ['No longer detected', count(result.groups.no_longer_detected), 'neutral'],
    ['Not re-checked or not comparable', c.unknowns, 'unknown'],
  ];
  return (
    <Section
      id="changes"
      title={`Compared with scan #${previous.scan_id}`}
      tone={c.unknowns ? 'unknown' : 'quiet'}
      intro={c.headline}
    >
      <ul className="tally">
        {rows.map(([label, value, tone]) => (
          <li key={label} className={`tally-${tone}`}>
            <span className="tally-value">{value}</span> <span className="tally-label">{label}</span>
          </li>
        ))}
      </ul>
      <p className="kv-note">
        "No longer detected" means the files that were re-checked no longer match; it does not
        mean the problem was fixed, and credentials may still be valid or in Git history.
      </p>
    </Section>
  );
}

export function CoverageSection({ report }: { report: ScanReport }) {
  const problems = report.coverage.filter((issue) => issue.is_error);
  const skipped = report.coverage.filter((issue) => !issue.is_error);
  const notCompleted = report.checks.filter((check) => check.status !== 'completed');
  const total = problems.length + notCompleted.length + skipped.length;
  return (
    <Section
      id="scan-unknown"
      title="What could not be checked"
      count={total}
      tone={report.outcome === 'incomplete' ? 'unknown' : 'quiet'}
      intro="Anything listed here was not examined, so problems in it would not appear as findings."
    >
      {total === 0 && <Empty>Every check completed and every file in scope was examined.</Empty>}
      {notCompleted.length > 0 && (
        <ul className="plain-list">
          {notCompleted.map((check) => (
            <li key={check.id}>
              <strong>
                {check.name}: {check.status}.
              </strong>{' '}
              {check.message}
            </li>
          ))}
        </ul>
      )}
      <CoverageTable caption="Problems that made the scan incomplete" issues={problems} />
      <CoverageTable
        caption="Skipped by policy (exclusions, size limit, binary files, links)"
        issues={skipped}
      />
    </Section>
  );
}

export function CoverageTable({ caption, issues }: { caption: string; issues: CoverageEntry[] }) {
  if (issues.length === 0) return null;
  return (
    <div className="table-wrap">
      <table>
        <caption>
          {caption} ({issues.length})
        </caption>
        <thead>
          <tr>
            <th scope="col">Path</th>
            <th scope="col">Reason</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {issues.map((issue) => (
            <tr key={`${issue.path}:${issue.reason}`}>
              <td>
                <code>{issue.path}</code>
              </td>
              <td>{issue.reason.replace(/_/g, ' ')}</td>
              <td>{issue.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ChecksTable({ report }: { report: ScanReport }) {
  return (
    <Section id="scan-checks" title="Checks" count={report.checks.length}>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Status</th>
              <th scope="col" className="num">
                Files examined
              </th>
              <th scope="col" className="num">
                Findings
              </th>
              <th scope="col">Note</th>
            </tr>
          </thead>
          <tbody>
            {report.checks.map((check) => (
              <tr key={check.id}>
                <th scope="row">{check.name}</th>
                <td className={`check-${check.status}`}>{check.status}</td>
                <td className="num">{check.examined ?? '-'}</td>
                <td className="num">{check.status === 'completed' ? check.findings : '-'}</td>
                <td>{check.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

/** Everything about one finding: what, why, what to do, and the rule's limits. */
export function FindingDetail(props: {
  finding: Finding;
  rule: Rule | undefined;
  status?: { text: string; explanation: string; recurring: boolean } | null;
}) {
  const { finding, rule, status } = props;
  return (
    <div className="detail-body">
      {status && (
        <div className="detail-block">
          <h3>Compared with the previous scan</h3>
          <p>
            <strong>{status.text}.</strong> {status.explanation}
          </p>
          {status.recurring && (
            <p>
              <strong>Detected again:</strong> this finding was also detected in a scan before the
              previous one, so it came back after it was last not detected.
            </p>
          )}
        </div>
      )}
      <div className="detail-block">
        <h3>What was found</h3>
        <p>{finding.summary}</p>
        <dl className="kv">
          <dt>Evidence</dt>
          <dd>
            <code>{finding.evidence}</code>
            <span className="kv-note"> Secret values are always hidden.</span>
          </dd>
          <dt>Location</dt>
          <dd>
            <code>{findingLocation(finding)}</code>
          </dd>
          <dt>Confidence</dt>
          <dd>
            {finding.confidence}: how likely this match is a real problem rather than, for
            example, test data.
          </dd>
          <dt>Rule</dt>
          <dd>
            <code>{finding.rule_id}</code>
            {finding.rule_version !== null && `, version ${finding.rule_version}`}
          </dd>
        </dl>
      </div>
      <div className="detail-block">
        <h3>Why it matters</h3>
        {rule ? (
          <>
            <p>{rule.description}</p>
            <p>
              <strong>Severity {finding.severity}:</strong> {rule.severity_rationale}
            </p>
          </>
        ) : (
          <p>This finding comes from a rule outside RepoSentinel's catalogue.</p>
        )}
      </div>
      <div className="detail-block">
        <h3>What you can do next</h3>
        <p>{finding.remediation}</p>
        <p className="kv-note">
          RepoSentinel does not change files. After you have made a change, scan again: a project
          scan is compared with the previous one automatically.
        </p>
      </div>
      {rule && (
        <div className="detail-block">
          <h3>Limits of this rule</h3>
          <p>{rule.limitations}</p>
          <p>
            <strong>After a re-check:</strong> {rule.recheck_limits}
          </p>
        </div>
      )}
    </div>
  );
}

export function findingCountText(report: ScanReport): string {
  return plural(report.findings.length, 'finding', 'findings');
}
