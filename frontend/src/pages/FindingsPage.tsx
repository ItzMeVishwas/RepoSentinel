import { useEffect, useMemo, useRef, useState } from 'react';
import { Empty, FilterChips, PageHeading, SeverityTag, plural, toggled } from '../common';
import { FindingDetail, findingLocation } from '../ScanView';
import { comparisonOf, useApp } from '../state';
import { SEVERITIES, type Severity, type TrackedFinding } from '../types';

const NARROW = '(max-width: 960px)';

export function FindingsPage() {
  const app = useApp();
  const scan = app.active;
  const ruleById = useMemo(
    () => new Map(app.session.rules.map((rule) => [rule.id, rule])),
    [app.session.rules],
  );
  const result = comparisonOf(scan?.previous ?? null);
  const tracked = useMemo(() => {
    const map = new Map<string, TrackedFinding>();
    for (const finding of result?.comparison.findings ?? []) map.set(finding.fingerprint, finding);
    return map;
  }, [result]);
  const recurring = useMemo(() => new Set(result?.recurring ?? []), [result]);

  const [query, setQuery] = useState('');
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [ruleFilter, setRuleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [pathFilter, setPathFilter] = useState('');
  const [sort, setSort] = useState<'severity' | 'path' | 'rule'>('severity');
  const [grouped, setGrouped] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const detailRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    setSelected(scan && scan.report.findings.length ? 0 : null);
  }, [scan]);

  if (!scan) {
    return (
      <div className="view">
        <PageHeading title="Findings" />
        <Empty>No scan is open. Run a scan, or open a saved scan from History.</Empty>
        <div className="button-row">
          <button type="button" className="primary" onClick={() => app.go('scan')}>
            Go to Scan
          </button>
          {app.session.history && (
            <button type="button" onClick={() => app.go('history')}>
              Go to History
            </button>
          )}
        </div>
      </div>
    );
  }

  const findings = scan.report.findings;
  const statusOf = (fingerprint: string): string | null => {
    if (!result) return null;
    if (recurring.has(fingerprint)) return 'recurring';
    return tracked.get(fingerprint)?.status ?? null;
  };
  const statusLabel: Record<string, string> = {
    new: 'New',
    new_not_examined_before: 'New (not examined before)',
    still_detected: 'Still detected',
    recurring: 'Detected again',
  };
  const needle = query.trim().toLowerCase();
  const visible = findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => {
      const text = [finding.rule_id, finding.title, finding.summary, finding.location?.path ?? '']
        .join(' ')
        .toLowerCase();
      return (
        (!needle || text.includes(needle)) &&
        (severities.size === 0 || severities.has(finding.severity)) &&
        (!ruleFilter || finding.rule_id === ruleFilter) &&
        (!statusFilter || statusOf(finding.fingerprint) === statusFilter) &&
        (!pathFilter || (finding.location?.path ?? '').toLowerCase().includes(pathFilter.toLowerCase()))
      );
    });
  const rank = { high: 0, medium: 1, low: 2, info: 3 } as const;
  const pathOf = (finding: (typeof findings)[number]) => finding.location?.path ?? '';
  visible.sort((a, b) => {
    const bySeverity = rank[a.finding.severity] - rank[b.finding.severity];
    const byPath = pathOf(a.finding).localeCompare(pathOf(b.finding));
    const byRule = a.finding.rule_id.localeCompare(b.finding.rule_id);
    if (sort === 'path' || grouped) return byPath || bySeverity || byRule || a.index - b.index;
    if (sort === 'rule') return byRule || bySeverity || byPath || a.index - b.index;
    return bySeverity || byPath || byRule || a.index - b.index;
  });
  const groups = new Map<string, typeof visible>();
  for (const entry of visible) {
    const key = pathOf(entry.finding) || '(whole repository)';
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  }
  const filtered = visible.length !== findings.length;

  /** Up/Down/Home/End move between findings (and open the one focused). */
  function onListKey(event: React.KeyboardEvent) {
    const rows = [...(listRef.current?.querySelectorAll<HTMLButtonElement>('.finding-row') ?? [])];
    const at = rows.indexOf(document.activeElement as HTMLButtonElement);
    if (at < 0) return;
    const next =
      event.key === 'ArrowDown' ? at + 1 : event.key === 'ArrowUp' ? at - 1 : event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1 : null;
    if (next === null) return;
    event.preventDefault();
    const target = rows[Math.max(0, Math.min(rows.length - 1, next))];
    if (!target) return;
    target.focus(); // the selection follows; focus stays in the list
    setSelected(Number(target.dataset.index));
  }

  const row = ({ finding, index }: (typeof visible)[number]) => {
    const status = statusOf(finding.fingerprint);
    return (
      <li key={index}>
        <button
          type="button"
          className={`finding-row sev-border-${finding.severity}`}
          aria-current={selected === index ? 'true' : undefined}
          aria-controls="finding-detail"
          data-index={index}
          onClick={() => choose(index)}
        >
          <span className="row-top">
            <SeverityTag severity={finding.severity} />
            <code className="rule-id">{finding.rule_id}</code>
            {status && <span className={`status-chip st-${status}`}>{statusLabel[status] ?? status}</span>}
          </span>
          <span className="finding-title">{finding.title}</span>
          <code className="finding-where">{grouped ? (finding.location?.line ? `line ${finding.location.line}` : 'whole file') : findingLocation(finding)}</code>
        </button>
      </li>
    );
  };
  const ruleIds = [...new Set(findings.map((finding) => finding.rule_id))].sort();
  const statuses = [...new Set(findings.map((finding) => statusOf(finding.fingerprint)))].filter(
    (status): status is string => status !== null,
  );
  const current = selected !== null ? findings[selected] : undefined;
  const currentStatus = current ? statusOf(current.fingerprint) : null;
  const currentTracked = current ? tracked.get(current.fingerprint) : undefined;
  const noLonger = result
    ? result.comparison.findings.filter((f) => result.groups.no_longer_detected.includes(f.status)).length
    : 0;

  function choose(index: number) {
    setSelected(index);
    if (window.matchMedia(NARROW).matches) setTimeout(() => detailRef.current?.focus(), 0);
  }

  function reset() {
    setQuery('');
    setSeverities(new Set());
    setRuleFilter('');
    setStatusFilter('');
    setPathFilter('');
  }

  return (
    <div className="view">
      <PageHeading
        title="Findings"
        lede={
          <>
            {plural(findings.length, 'finding', 'findings')} in{' '}
            {scan.source === 'project'
              ? `saved scan #${scan.historyScanId} of ${scan.project?.name ?? 'a project'}`
              : 'a one-off scan'}{' '}
            of <code>{scan.report.target}</code>. Each is a potential problem for you to review, not a
            confirmed vulnerability.
          </>
        }
      />
      {result && noLonger > 0 && (
        <p className="note-bar">
          {plural(noLonger, 'earlier finding is', 'earlier findings are')} no longer detected and
          therefore not listed here.{' '}
          <button type="button" className="link-button" onClick={() => app.go('compare')}>
            See them in the comparison
          </button>
        </p>
      )}
      {scan.report.outcome === 'incomplete' && (
        <p className="note-bar note-unknown">
          This scan is incomplete: some files or checks were not examined, so this list may be
          missing findings. The Scan page lists what could not be checked.
        </p>
      )}
      {findings.length === 0 ? (
        <Empty>No findings from the checks that ran.</Empty>
      ) : (
        <>
          <div className="filters" role="search" aria-label="Filter findings">
            <label className="inline-field grow" htmlFor="finding-search">
              Search
              <input
                id="finding-search"
                type="search"
                value={query}
                placeholder="Rule, title, summary or path"
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
            <label className="inline-field" htmlFor="finding-rule">
              Rule
              <select id="finding-rule" value={ruleFilter} onChange={(event) => setRuleFilter(event.target.value)}>
                <option value="">All rules</option>
                {ruleIds.map((id) => (
                  <option key={id} value={id}>
                    {id} {ruleById.get(id)?.title ?? ''}
                  </option>
                ))}
              </select>
            </label>
            {result && (
              <label className="inline-field" htmlFor="finding-status">
                Compared with previous
                <select
                  id="finding-status"
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                >
                  <option value="">Any status</option>
                  {statuses.map((status) => (
                    <option key={status} value={status}>
                      {statusLabel[status] ?? status}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="inline-field" htmlFor="finding-path">
              Path contains
              <input
                id="finding-path"
                type="search"
                value={pathFilter}
                onChange={(event) => setPathFilter(event.target.value)}
              />
            </label>
            <label className="inline-field" htmlFor="finding-sort">
              Sort by
              <select id="finding-sort" value={sort} onChange={(event) => setSort(event.target.value as typeof sort)} disabled={grouped}>
                <option value="severity">Severity</option>
                <option value="path">File path</option>
                <option value="rule">Rule</option>
              </select>
            </label>
            <label className="checkbox inline-check">
              <input type="checkbox" checked={grouped} onChange={(event) => setGrouped(event.target.checked)} />
              Group by file
            </label>
            <FilterChips
              label="Severity"
              options={SEVERITIES.map((severity) => ({
                value: severity,
                label: severity,
                count: findings.filter((finding) => finding.severity === severity).length,
              }))}
              selected={severities}
              onToggle={(value) => setSeverities((now) => toggled(now, value))}
            />
          </div>
          <p className="filter-status" role="status">
            Showing {visible.length} of {plural(findings.length, 'finding', 'findings')}.
            {filtered && (
              <>
                {' '}
                <button type="button" className="link-button" onClick={reset}>
                  Show all
                </button>
              </>
            )}
          </p>
          <div className="explorer">
            <div className="finding-list-wrap" ref={listRef} onKeyDown={onListKey}>
              <p className="kv-note keys-hint">Use the Up and Down arrow keys to move between findings.</p>
              {visible.length === 0 ? (
                <Empty>No finding matches these filters.</Empty>
              ) : grouped ? (
                <ul className="finding-groups" aria-label="Findings grouped by file">
                  {[...groups].map(([path, entries]) => (
                    <li key={path} className="finding-group">
                      <p className="group-head">
                        <code>{path}</code> <span className="count">({entries.length})</span>
                      </p>
                      <ol className="finding-rows" aria-label={`Findings in ${path}`}>
                        {entries.map(row)}
                      </ol>
                    </li>
                  ))}
                </ul>
              ) : (
                <ol className="finding-rows" aria-label="Findings">
                  {visible.map(row)}
                </ol>
              )}
            </div>
            <aside
              id="finding-detail"
              className="detail-panel"
              aria-labelledby="finding-detail-title"
              tabIndex={0} // it scrolls on its own, so it must be reachable by keyboard
            >
              {current ? (
                <>
                  <div className="detail-head">
                    <SeverityTag severity={current.severity} />
                    <h2 id="finding-detail-title" ref={detailRef} tabIndex={-1}>
                      {current.title}
                    </h2>
                    <code className="finding-where">{findingLocation(current)}</code>
                  </div>
                  <FindingDetail
                    finding={current}
                    rule={ruleById.get(current.rule_id)}
                    status={
                      currentTracked && currentStatus
                        ? {
                            text: currentTracked.status_text,
                            explanation: currentTracked.explanation,
                            recurring: currentStatus === 'recurring',
                          }
                        : null
                    }
                  />
                </>
              ) : (
                <h2 id="finding-detail-title" className="detail-empty">
                  Select a finding to see its details
                </h2>
              )}
            </aside>
          </div>
        </>
      )}
    </div>
  );
}
