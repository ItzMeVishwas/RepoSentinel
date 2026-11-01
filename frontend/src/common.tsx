import { useEffect, useRef, useState, type ReactNode } from 'react';
import { download, messageOf } from './api';
import type { Severity } from './types';

// All repository-derived text is rendered as React text nodes, which React
// escapes. No component in this app uses dangerouslySetInnerHTML.

export const HISTORY_LIMIT =
  'Git history has not been scanned. A finding no longer detected in current files does not ' +
  'establish that a credential was revoked or removed from Git history.';

const SEVERITY_WORDS: Record<Severity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`tag sev-${severity}`}>{SEVERITY_WORDS[severity]}</span>;
}

let navigated = false;

/** Called when the person moves to another page: that page's heading then takes focus. */
export function markNavigation() {
  navigated = true;
}

/**
 * A page's heading. It takes focus when the person opens the page, so the
 * change is announced (but not on first load, where focus starts at the top).
 */
export function PageHeading(props: { title: string; lede?: ReactNode; actions?: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (navigated) ref.current?.focus();
  }, []);
  return (
    <header className="page-head">
      <div>
        <h1 ref={ref} tabIndex={-1}>
          {props.title}
        </h1>
        {props.lede && <p className="lede">{props.lede}</p>}
      </div>
      {props.actions && <div className="page-actions">{props.actions}</div>}
    </header>
  );
}

export function Section(props: {
  id: string;
  title: string;
  count?: number;
  tone?: 'attention' | 'unknown' | 'quiet';
  children: ReactNode;
  intro?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className={`section tone-${props.tone ?? 'quiet'}`} aria-labelledby={props.id}>
      <div className="section-head">
        <h2 id={props.id}>
          {props.title}
          {props.count !== undefined && <span className="count"> ({props.count})</span>}
        </h2>
        {props.actions}
      </div>
      {props.intro && <p className="section-intro">{props.intro}</p>}
      {props.children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/** An error message that takes focus when it appears, so it is announced. */
export function ErrorNote({ message }: { message: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => ref.current?.focus(), [message]);
  return (
    <div className="error-note" role="alert" tabIndex={-1} ref={ref}>
      <strong>Could not complete this: </strong>
      {message}
    </div>
  );
}

export function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

export function lineText(lines: number[]): string {
  if (lines.length === 0) return '';
  const shown = lines.slice(0, 10).join(', ');
  const more = lines.length > 10 ? ` and ${lines.length - 10} more` : '';
  return `${lines.length === 1 ? 'line' : 'lines'} ${shown}${more}`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export const OUTCOME_WORDS = {
  clean: 'Nothing found by these checks',
  findings: 'Findings to review',
  incomplete: 'Incomplete scan',
} as const;

/** Toggle buttons for filtering; every option stays visible with its count. */
export function FilterChips<T extends string>(props: {
  label: string;
  options: { value: T; label: string; count: number }[];
  selected: Set<T>;
  onToggle: (value: T) => void;
}) {
  return (
    <div className="chips" role="group" aria-label={props.label}>
      <span className="chips-label" aria-hidden="true">
        {props.label}:
      </span>
      {props.options.map((option) => (
        <button
          key={option.value}
          type="button"
          className="chip"
          aria-pressed={props.selected.has(option.value)}
          onClick={() => props.onToggle(option.value)}
        >
          {option.label} <span className="chip-count">{option.count}</span>
        </button>
      ))}
    </div>
  );
}

export function toggled<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

/**
 * A destructive action behind an explicit second step. With ``typed``, the
 * person must type that word first (used for deleting all data).
 */
export function ConfirmAction(props: {
  label: string;
  confirmLabel: string;
  question: ReactNode;
  onConfirm: () => Promise<void>;
  typed?: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const openerRef = useRef<HTMLButtonElement>(null);
  const id = useRef(`confirm-${Math.random().toString(36).slice(2)}`).current;

  useEffect(() => {
    if (open) (props.typed ? inputRef.current : confirmRef.current)?.focus();
  }, [open, props.typed]);

  function close() {
    setOpen(false);
    setText('');
    setError(null);
    setTimeout(() => openerRef.current?.focus(), 0);
  }

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await props.onConfirm();
      setOpen(false);
      setText('');
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        className="danger-quiet"
        ref={openerRef}
        disabled={props.disabled}
        onClick={() => setOpen(true)}
      >
        {props.label}
      </button>
    );
  }
  const ready = !props.typed || text === props.typed;
  return (
    <div
      className="confirm"
      role="group"
      aria-labelledby={`${id}-q`}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && !busy) close();
      }}
    >
      <p id={`${id}-q`}>{props.question}</p>
      {props.typed && (
        <label className="confirm-typed">
          Type <code>{props.typed}</code> to confirm
          <input
            ref={inputRef}
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={text}
            onChange={(event) => setText(event.target.value)}
            disabled={busy}
          />
        </label>
      )}
      <div className="button-row">
        <button
          type="button"
          className="danger"
          ref={confirmRef}
          disabled={!ready || busy}
          aria-busy={busy}
          onClick={confirm}
        >
          {busy ? 'Working...' : props.confirmLabel}
        </button>
        <button type="button" onClick={close} disabled={busy}>
          Cancel
        </button>
      </div>
      {error && <ErrorNote message={error} />}
    </div>
  );
}

export type ExportFormat = 'json' | 'html' | 'sarif';

const FORMAT_TYPES: Record<ExportFormat, string> = {
  json: 'application/json',
  html: 'text/html',
  sarif: 'application/sarif+json',
};
const FORMAT_LABELS: Record<ExportFormat, string> = {
  json: 'JSON',
  html: 'HTML',
  sarif: 'SARIF',
};

/** Buttons that download files rendered by RepoSentinel itself (never by the page). */
export function DownloadButtons(props: {
  endpoint: string;
  body: Record<string, string | number>;
  stem: string;
  formats: ExportFormat[];
  label?: string;
}) {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save(format: ExportFormat) {
    setBusy(format);
    setError(null);
    try {
      await download(
        props.endpoint,
        { ...props.body, format },
        `${props.stem}.${format}`,
        FORMAT_TYPES[format],
      );
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="button-row" role="group" aria-label={props.label ?? 'Download'}>
        {props.formats.map((format) => (
          <button
            key={format}
            type="button"
            onClick={() => save(format)}
            disabled={busy !== null}
            aria-busy={busy === format}
          >
            {busy === format ? 'Preparing...' : `Download ${FORMAT_LABELS[format]}`}
          </button>
        ))}
      </div>
      {error && <ErrorNote message={error} />}
    </div>
  );
}

const CHECK_MARK = String.fromCharCode(0x2713);
const EN_DASH = String.fromCharCode(0x2013);

/** A short status word, always text first; the colour only reinforces it. */
export function StatusWord(props: { tone: 'ok' | 'attention' | 'unknown' | 'neutral'; children: ReactNode }) {
  const marks = { ok: CHECK_MARK, attention: '!', unknown: '?', neutral: EN_DASH } as const;
  return (
    <span className={`status-word status-${props.tone}`}>
      <span aria-hidden="true" className="status-mark">
        {marks[props.tone]}
      </span>
      {props.children}
    </span>
  );
}

/** Shorten a long path in the middle, keeping its start and its last folders. */
export function truncateMiddle(text: string, max = 64): string {
  if (text.length <= max) return text;
  const keep = max - 3;
  return `${text.slice(0, Math.ceil(keep * 0.4))}...${text.slice(text.length - Math.floor(keep * 0.6))}`;
}

/** A path shown shortened, with the full path in a tooltip and for screen readers. */
export function PathText({ path, max = 64 }: { path: string; max?: number }) {
  const short = truncateMiddle(path, max);
  if (short === path) return <code className="path-text">{path}</code>;
  return (
    <code className="path-text" title={path}>
      <span aria-hidden="true">{short}</span>
      <span className="visually-hidden">{path}</span>
    </code>
  );
}
