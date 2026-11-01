// The only way the page talks to RepoSentinel: POST requests to this same
// origin, to paths relative to the page.
//
// Authentication uses a bearer token held ONLY in this module's memory: never
// in a cookie (browsers share cookies across ports), localStorage,
// sessionStorage or a URL. The browser never attaches it on its own; only
// these functions add it. Reloading or closing the tab forgets it, which ends
// the session; the terminal running `reposentinel ui` gives a new link.

export class ApiFailure extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

let token: string | null = null;
let starting: Promise<boolean> | null = null;

/**
 * Take the one-time launch code from the address (#launch=...), remove it from
 * the address bar and history at once, and exchange it for the session token.
 * Returns false when the page was opened without a code. Safe to call twice.
 */
export function startSession(): Promise<boolean> {
  starting ??= exchangeLaunchCode();
  return starting;
}

async function exchangeLaunchCode(): Promise<boolean> {
  const match = /^#launch=([A-Za-z0-9_-]{1,256})$/.exec(window.location.hash);
  // Remove the fragment before anything else, whether or not it is valid.
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname);
  }
  if (!match?.[1]) return false;
  const response = await send('api/session/start', { launch_code: match[1] }, false);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object' || !('token' in data) || typeof data.token !== 'string') {
    throw new ApiFailure('RepoSentinel returned an unexpected answer.', 0);
  }
  token = data.token;
  return true;
}

async function send(path: string, body: unknown, authenticated = true): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-RepoSentinel-Request': '1',
  };
  if (authenticated && token) headers.Authorization = `Bearer ${token}`;
  let response: Response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      credentials: 'omit', // there are no cookies, and none should be sent
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    throw new ApiFailure(
      'RepoSentinel is not responding. Is "reposentinel ui" still running in the terminal?',
      0,
    );
  }
  if (!response.ok) {
    let message = `Request failed (HTTP ${response.status}).`;
    try {
      const data: unknown = await response.json();
      if (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string') {
        message = data.error;
      }
    } catch {
      // keep the generic message
    }
    throw new ApiFailure(message, response.status);
  }
  return response;
}

export async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await send(path, body);
  return (await response.json()) as T;
}

/** Ask the server for a file it rendered, and save it with the given name. */
export async function download(path: string, body: unknown, filename: string, type: string) {
  const response = await send(path, body);
  const blob = new Blob([await response.arrayBuffer()], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** File contents as base64, read in chunks so large reports do not overflow the stack. */
export async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}
