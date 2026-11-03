// End-to-end test of the BUILT web interface in a real browser.
//
//   npm run build && npm run e2e
//
// Starts the real `python -m reposentinel ui --no-browser` (with a temporary
// REPOSENTINEL_DATA_DIR), drives it with
// puppeteer-core using an installed Chrome or Edge (override with CHROME_PATH;
// nothing is downloaded), or Firefox with E2E_BROWSER=firefox (override with
// FIREFOX_PATH; driven over WebDriver BiDi), and compares what the page shows
// and downloads with the command line's own output for the same synthetic repositories. Every
// browser request is recorded and must stay on this computer.
//
// Writes screenshots and results.json to E2E_OUT (default: a new temp folder).
// Exits 1 if any check fails.

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import axe from 'axe-core';
import puppeteer from 'puppeteer-core';

const here = dirname(fileURLToPath(import.meta.url));
const project = join(here, '..', '..');
const python =
  process.env.PYTHON ??
  [join(project, '.venv', 'Scripts', 'python.exe'), join(project, '.venv', 'bin', 'python')].find(existsSync);
// Firefox is driven without Chrome's DevTools protocol: the few checks that
// need it (emulated media features) are reported as skipped, never as passed,
// and E2E_CPU_SLOWDOWN is refused.
const firefox = process.env.E2E_BROWSER === 'firefox';
const browserPaths = (
  firefox
    ? [
        process.env.FIREFOX_PATH,
        'C:/Program Files/Mozilla Firefox/firefox.exe',
        '/usr/bin/firefox',
        '/Applications/Firefox.app/Contents/MacOS/firefox',
      ]
    : [
        process.env.CHROME_PATH,
        'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
        'C:/Program Files/Google/Chrome/Application/chrome.exe',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
      ]
)
  .filter(Boolean)
  .filter((path) => existsSync(path));
let browserPath = browserPaths[0];
if (!python || !browserPath) {
  const wanted = firefox ? 'Firefox (set FIREFOX_PATH)' : 'a Chrome or Edge browser (set CHROME_PATH)';
  console.error(`Missing ${python ? wanted : 'Python (set PYTHON)'}.`);
  process.exit(2);
}

const out = process.env.E2E_OUT ?? mkdtempSync(join(tmpdir(), 'reposentinel-e2e-'));
mkdirSync(out, { recursive: true });
const work = mkdtempSync(join(out, 'work-'));
const downloads = join(work, 'downloads');
mkdirSync(downloads, { recursive: true });
mkdirSync(out, { recursive: true });

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail: String(detail) });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` - ${detail}` : ''}`);
}
// A check this browser cannot perform: listed as skipped, neither passed nor failed.
function skip(name, reason) {
  results.push({ name, ok: true, skipped: true, detail: reason });
  console.log(`SKIP  ${name} - ${reason}`);
}

// --- synthetic repositories (all values assembled at run time) -----------------
const TOKEN = 'ghp' + '_' + '0123456789' + 'abcdefghijklmnopqrstuvwxyz';
const UNKNOWN = 'Kq7-' + 'unrecognised' + '-Pw9';
const RLO = String.fromCharCode(0x202e);

function cli(args, options = {}) {
  const run = spawnSync(python, ['-m', 'reposentinel', ...args], { cwd: work, encoding: 'utf-8', ...options });
  return run;
}
function write(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, 'utf-8');
}

const demo = join(work, 'demo');
spawnSync(python, [join(project, 'scripts', 'create_demo_repo.py'), demo], { encoding: 'utf-8' });
const before = join(work, 'before.json');
const after = join(work, 'after.json');
cli(['scan', demo, '--format', 'json', '--output', before]);
rmSync(join(demo, '.env'));
write(join(demo, 'tools', 'release.py'), `RELEASE = "${TOKEN}"\n`);
cli(['scan', demo, '--format', 'json', '--output', after]);
const cliScan = JSON.parse(readFileSync(after, 'utf-8'));
const cliCompare = JSON.parse(cli(['compare', before, after, '--format', 'json']).stdout);
// A second copy in the "before" state, registered as a project in the UI.
const projectDir = join(work, 'project-app');
spawnSync(python, [join(project, 'scripts', 'create_demo_repo.py'), projectDir], { encoding: 'utf-8' });
// The local history goes to a temporary folder, never the real user data folder.
const dataDir = join(work, 'appdata');
const serverEnv = { ...process.env, REPOSENTINEL_DATA_DIR: dataDir };

const hostile = join(work, 'hostile');
const stepName = `deploy-with-pw ${UNKNOWN} x${TOKEN} <img src=x onerror=alert(1)> & 'q' ${RLO}`;
write(
  join(hostile, '.github', 'workflows', 'ci.yml'),
  [
    'on: issues',
    'permissions: write-all',
    'jobs:',
    `  "build-${UNKNOWN}":`,
    '    runs-on: ubuntu-latest',
    '    steps:',
    `      - name: "${stepName.replace(/"/g, '')}"`,
    `        run: echo "\${{ github.event.issue.title || ${UNKNOWN} }}"`,
    '',
  ].join('\n'),
);
write(join(hostile, `docs`, `Q&A 'draft' ${RLO}txt.md`), `token = "${TOKEN}"\n`);
write(join(hostile, '<b>bold</b>.env'.replace(/[<>]/g, '_')), 'A=1\n');

// --- start the real server -----------------------------------------------------------
const server = spawn(python, ['-m', 'reposentinel', 'ui', '--no-browser'], { cwd: work, env: serverEnv });
let server2 = null; // the restarted server (a returning user)
let serverLog = '';
const launchUrl = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('server did not start')), 20000);
  server.stderr.on('data', (chunk) => {
    serverLog += chunk.toString();
    const match = serverLog.match(/(http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]+\/#launch=\S+)/);
    if (match) {
      clearTimeout(timer);
      resolve(match[1]);
    }
  });
});
const origin = new URL(launchUrl).origin;

// Another web service on 127.0.0.1 (a different port). Browsers do not isolate
// cookies by port (RFC 6265, 8.5), so this is where a cookie credential would
// leak. It records every request's headers.
const spyCookies = [];
const spy = createServer((request, response) => {
  spyCookies.push({ path: request.url, cookie: request.headers.cookie ?? '', authorization: request.headers.authorization ?? '' });
  response.writeHead(200, { 'Content-Type': 'text/html' });
  response.end('<!doctype html><title>other local service</title><p>other service</p>');
});
await new Promise((resolve) => spy.listen(0, '127.0.0.1', resolve));
const spyOrigin = `http://127.0.0.1:${spy.address().port}`;
const spyGotCredential = () => spyCookies.filter((c) => c.cookie !== '' || c.authorization !== '');
check('server listens on 127.0.0.1', origin.startsWith('http://127.0.0.1:'), origin);

// The first installed browser that starts is used (an installation can be
// broken, for example during an update); the one used is recorded in results.json.
async function launchBrowser() {
  const problems = [];
  for (const candidate of browserPaths) {
    try {
      // A fresh profile per attempt: a failed start can leave its profile locked.
      const userDataDir = join(work, `profile-${browserPaths.indexOf(candidate)}`);
      const launched = await puppeteer.launch({ ...launchOptions, executablePath: candidate, userDataDir });
      browserPath = candidate;
      return launched;
    } catch (error) {
      problems.push(`${candidate}: ${error.message.split('\n')[0]}`);
    }
  }
  server.kill();
  spy.close();
  throw new Error(`no browser could start: ${problems.join('; ')}`);
}
const launchOptions = firefox
  ? {
      browser: 'firefox',
      headless: true,
      extraPrefsFirefox: {
        // Downloads go to the test's own folder, never the user's Downloads.
        // (puppeteer's downloadBehavior option reaches only new browser
        // contexts over WebDriver BiDi, not the default one used here.)
        'browser.download.dir': downloads,
        'browser.download.folderList': 2,
        'browser.download.useDownloadDir': true,
        // Like Chrome's host-resolver rules below: only this computer is
        // reachable. Everything else goes to a proxy port nothing listens on
        // (Firefox never sends 127.0.0.1 to a proxy), and no background
        // service connects out.
        'network.proxy.type': 1,
        'network.proxy.http': '127.0.0.1',
        'network.proxy.http_port': 1,
        'network.proxy.ssl': '127.0.0.1',
        'network.proxy.ssl_port': 1,
        'network.proxy.no_proxies_on': '127.0.0.1',
        'network.proxy.allow_hijacking_localhost': false,
        'browser.safebrowsing.malware.enabled': false,
        'browser.safebrowsing.phishing.enabled': false,
        'app.update.enabled': false,
        'datareporting.policy.dataSubmissionEnabled': false,
        'browser.download.always_ask_before_handling_new_types': false,
      },
    }
  : {
      headless: true,

      args: [
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', // only this computer resolves
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-sync',
        '--disable-extensions',
        // Hosted Linux CI runners may not allow Chrome's sandbox; opt in explicitly there.
        ...(process.env.E2E_CHROME_NO_SANDBOX === '1' ? ['--no-sandbox'] : []),
      ],
    };
const browser = await launchBrowser();
console.log(`browser: ${browserPath}`);

const requests = [];
const responses = [];
const failures = [];
const consoleMessages = [];
const tokens = []; // every session token the server issued, to search outputs for
async function newPage() {
  const page = await browser.newPage();
  page.on('request', (request) => requests.push(request.url()));
  page.on('response', (response) => {
    responses.push(response.url());
    if (response.url().endsWith('api/session/start') && response.ok()) {
      response.json().then((body) => tokens.push(body.token)).catch(() => {});
    }
  });
  page.on('requestfailed', (request) => failures.push(`${request.url()} (${request.failure()?.errorText})`));
  page.on('console', (message) => consoleMessages.push(`${message.type()}: ${message.text()}`));
  page.on('pageerror', (error) => {
    // Firefox reports requests that the CSP or CORS blocked (as the security
    // checks below intend) as page errors; Chrome does not. Record them as
    // console errors: still searched for leaked values, not counted as uncaught.
    const blocked = firefox && /^(Content-Security-Policy|Cross-Origin Request Blocked): /.test(error.message);
    consoleMessages.push(`${blocked ? 'error' : 'pageerror'}: ${error.message}`);
  });
  // E2E_CPU_SLOWDOWN=4 runs the page 4 times slower, like a small CI runner, to
  // reveal checks that only pass because a fast machine wins a race.
  const slowdown = Number(process.env.E2E_CPU_SLOWDOWN ?? 1);
  if (!firefox) {
    // Firefox gets its download folder from its preferences (launchOptions).
    const cdp = await page.createCDPSession();
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
    if (slowdown > 1) await cdp.send('Emulation.setCPUThrottlingRate', { rate: slowdown });
  } else if (slowdown > 1) {
    throw new Error('E2E_CPU_SLOWDOWN needs Chrome or Edge');
  }
  // E2E_API_DELAY_MS=400 holds every API request that long, like a slow server,
  // to reveal checks that read data before the page has received it.
  const apiDelay = Number(process.env.E2E_API_DELAY_MS ?? 0);
  if (apiDelay > 0) {
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      if (request.isInterceptResolutionHandled()) return;
      if (request.url().includes('/api/')) setTimeout(() => request.continue(), apiDelay);
      else request.continue();
    });
  }
  return page;
}

async function axeCheck(page, label) {
  await page.evaluate(axe.source); // DevTools evaluation is not subject to the page's CSP
  const report = await page.evaluate(() =>
    window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] }),
  );
  const serious = report.violations.filter((v) => ['serious', 'critical'].includes(v.impact));
  check(
    `accessibility (axe-core, WCAG 2.2 AA rules): ${label}`,
    serious.length === 0,
    report.violations.map((v) => `${v.impact} ${v.id} (${v.nodes.length})`).join('; ') || 'no violations',
  );
}

async function waitForDownload(name) {
  const path = join(downloads, name);
  for (let i = 0; i < 100; i += 1) {
    // Chrome writes .crdownload and Firefox .part files until a download is complete.
    if (existsSync(path) && !readdirSync(downloads).some((f) => /\.(crdownload|part)$/.test(f))) return path;
    await new Promise((r) => setTimeout(r, 100));
  }
  return null;
}

const exited = (child) =>
  child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve()
    : new Promise((resolve) => child.once('exit', resolve));

const visibleText = (page) => page.evaluate(() => document.body.innerText);

async function fill(page, selector, text) {
  await page.click(selector);
  await page.keyboard.down('Control');
  await page.keyboard.press('KeyA');
  await page.keyboard.up('Control');
  await page.keyboard.press('Backspace');
  await page.type(selector, text);
}

async function waitOrExplain(page, selector) {
  try {
    await page.waitForSelector(selector, { timeout: 60000 });
  } catch (error) {
    const alert = await page.evaluate(() => document.querySelector('[role=alert]')?.textContent ?? '(no alert)');
    throw new Error(`${selector} did not appear; on-screen alert: ${alert}`);
  }
}

// Waits for the page to stop announcing a loading state (role=status ".loading"),
// i.e. for data requested from the server to arrive; then the page shows either
// the data or an honest empty or error state.
const settled = (page) =>
  page.waitForFunction(() => !document.querySelector('main .loading[role=status]'));
const heading = (page) => page.evaluate(() => document.querySelector('main h1')?.textContent ?? '');
// What a click on the menu button would actually hit: null when it is the button
// itself, otherwise a short description of the element covering it.
const menuButtonCover = (page) =>
  page.evaluate(() => {
    const box = document.querySelector('.menu-button').getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    return hit?.closest('.menu-button') ? null : (hit?.outerHTML.slice(0, 80) ?? 'nothing');
  });
async function goTo(page, label) {
  // On narrow screens the navigation is in a menu that opens from the top bar.
  if (await page.$eval('.menu-button', (el) => getComputedStyle(el).display !== 'none')) {
    // A click on a covered button would silently hit something else.
    const cover = await menuButtonCover(page);
    if (cover) throw new Error(`goTo(${label}): the menu button is covered by ${cover}`);
    await page.click('.menu-button');
    // Wait until the menu has finished sliding in, as a person would.
    await page.waitForFunction(() => {
      const box = document.querySelector('.menu-open .sidebar')?.getBoundingClientRect();
      return box && box.left >= 0;
    });
  }
  await page.click(`xpath/.//nav[@aria-label="Main"]//button[starts-with(normalize-space(.),"${label}")]`);
  await page.waitForFunction((t) => document.querySelector('main h1')?.textContent === t, { timeout: 10000 }, label);
  // On narrow screens the menu closes after navigating; wait until it is out of the way.
  await page.waitForFunction(() => {
    const menuButton = document.querySelector('.menu-button');
    return getComputedStyle(menuButton).display === 'none' || getComputedStyle(document.querySelector('.sidebar')).visibility === 'hidden';
  });
}
const button = (text) => `xpath/.//main//button[normalize-space(.)="${text}"]`;
async function clickButton(page, text) {
  await page.waitForSelector(button(text), { timeout: 60000 });
  await page.click(button(text));
}
async function noOverflow(page, label) {
  const narrow = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth - window.innerWidth,
    // Elements that stick out of the page, ignoring content that scrolls inside
    // a container which itself fits (a wide table in its scrolling wrapper).
    widest: [...document.querySelectorAll('body *')]
      .filter((el) => el.getBoundingClientRect().right > window.innerWidth + 1)
      .filter((el) => {
        for (let up = el.parentElement; up; up = up.parentElement) {
          const style = getComputedStyle(up);
          if (['auto', 'scroll', 'hidden'].includes(style.overflowX) && up.getBoundingClientRect().right <= window.innerWidth + 1) return false;
        }
        return true;
      })
      .filter((el) => ![...el.children].some((c) => c.getBoundingClientRect().right > window.innerWidth + 1))
      .slice(0, 4)
      .map((el) => `${el.tagName.toLowerCase()}.${el.className}: ${Math.round(el.getBoundingClientRect().right)}px`),
  }));
  check(`no horizontal scrolling at 375 px: ${label}`, narrow.overflow <= 0 && narrow.widest.length === 0, `page overflow ${narrow.overflow}px; ${narrow.widest.join('; ') || 'nothing sticks out'}`);
}
let log2 = ''; // the restarted server's terminal output
let origin2 = 'http://127.0.0.1:0';
const dbBytes = () => (existsSync(dataDir) ? readdirSync(dataDir).map((f) => readFileSync(join(dataDir, f))) : []);

try {
  const page = await newPage();
  await page.setViewport({ width: 1280, height: 900 });

  // Launch link: the code is in the fragment (never sent); the page exchanges it for an in-memory token.
  await page.goto(launchUrl, { waitUntil: 'networkidle0' });
  const basePath = new URL(page.url()).pathname;
  check('launch link redirects to the app under a secret base path', /^\/s\/[A-Za-z0-9_-]{22,}\/$/.test(basePath), basePath.replace(/\/s\/.+\//, '/s/<prefix>/'));
  check('session secret is not in the address bar', !page.url().includes('launch'));
  await page.waitForSelector('nav[aria-label=Main]');
  check('the launch code is removed from the address bar', new URL(page.url()).hash === '' && !page.url().includes('launch='));
  check('no cookie is set', (await page.cookies()).length === 0 && (await page.evaluate(() => document.cookie)) === '');
  check('nothing is kept in browser storage', await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0));

  // First run: the Overview explains what to do; nothing has been written yet.
  check('first run opens the Overview', (await heading(page)) === 'Overview');
  await settled(page); // the project list has loaded (and is empty)
  check('first run shows how to get started', (await visibleText(page)).includes('Register a project'));
  check('no local data is created before a project is registered', !existsSync(dataDir));
  await page.keyboard.press('Tab');
  check('first Tab focuses "Skip to main content"', await page.evaluate(() => document.activeElement?.textContent === 'Skip to main content'));
  await axeCheck(page, 'first-run overview');

  // Every navigation item opens a page (no dead items), and moves focus to its heading.
  const navLabels = await page.$$eval('nav[aria-label=Main] button', (els) => els.map((e) => e.textContent.trim()));
  check('navigation has the eight sections', JSON.stringify(navLabels) === JSON.stringify(['Overview', 'Projects', 'Scan', 'Findings', 'History', 'Compare', 'Reports', 'Settings']), navLabels.join(', '));
  for (const label of navLabels) {
    await goTo(page, label);
    const focused = await page.evaluate(() => document.activeElement?.tagName === 'H1');
    const current = await page.$eval('nav [aria-current=page]', (el) => el.textContent.trim());
    check(`"${label}" opens its page, marks it current and focuses its heading`, focused && current === label);
  }
  await goTo(page, 'Settings');
  await settled(page);
  check('Settings shows where data would be kept', (await visibleText(page)).includes('Not created yet'));
  await axeCheck(page, 'settings (no data yet)');

  // --- a one-off scan: shown, never saved ----------------------------------------------
  await goTo(page, 'Scan');
  await page.click(button('Scan folder'));
  await page.waitForSelector('[role=alert]');
  check('empty path is explained', (await visibleText(page)).includes('Enter the full path'));
  await page.type('#scan-path', join(work, 'does-not-exist'));
  await page.click(button('Scan folder'));
  await page.waitForFunction(() => document.querySelector('[role=alert]')?.textContent?.includes('path not found'));
  check('missing folder is explained', true);
  await fill(page, '#scan-path', demo);
  await page.click(button('Scan folder'));
  await waitOrExplain(page, '#scan-results-title');
  check('focus moves to the result heading', await page.evaluate(() => document.activeElement?.id === 'scan-results-title'));
  let text = await visibleText(page);
  check('one-off scan is labelled as not saved', text.includes('One-off scan (not saved to history)'));
  check('scope statement is visible', text.includes('Git history was not scanned'));
  check('exit code matches the CLI', text.includes('Exit code 1'));
  check('a one-off scan writes no local data', !existsSync(dataDir));
  await page.screenshot({ path: join(out, 'scan-one-off.png'), fullPage: true });

  // --- findings explorer ------------------------------------------------------------------
  await goTo(page, 'Findings');
  const rows = await page.$$eval('.finding-row', (items) => items.length);
  check('finding count equals the CLI', rows === cliScan.findings.length, `${rows} vs ${cliScan.findings.length}`);
  const shownRules = await page.$$eval('.finding-row .rule-id', (els) => els.map((e) => e.textContent).sort());
  check('rule IDs equal the CLI', JSON.stringify(shownRules) === JSON.stringify(cliScan.findings.map((f) => f.rule_id).sort()));
  const highCount = cliScan.findings.filter((f) => f.severity === 'high').length;
  const [highChip] = await page.$$('xpath/.//main//button[contains(@class,"chip")][starts-with(normalize-space(.),"high")]');
  await highChip.click();
  const filtered = await page.$$eval('.finding-row', (items) => items.length);
  check('severity filter shows only high findings', filtered === highCount, `${filtered} vs ${highCount}`);
  check('filter states what is hidden', (await visibleText(page)).includes(`Showing ${highCount} of ${cliScan.findings.length}`));
  await highChip.click();
  const searchRule = cliScan.findings[0].rule_id;
  await page.type('#finding-search', searchRule);
  const searched = await page.$$eval('.finding-row .rule-id', (els) => els.map((e) => e.textContent));
  check('search narrows the list', searched.length > 0 && searched.every((r) => r === searchRule), `${searched.length} rows for ${searchRule}`);
  await page.click(button('Show all'));
  await page.select('#finding-sort', 'path');
  const paths = await page.$$eval('.finding-row .finding-where', (els) => els.map((e) => e.textContent.split(',')[0]));
  check('findings can be sorted by path', JSON.stringify(paths) === JSON.stringify([...paths].sort((a, b) => a.localeCompare(b))));
  await page.click('xpath/.//label[contains(.,"Group by file")]/input');
  const groupCount = await page.$$eval('.finding-group', (els) => els.length);
  check('findings can be grouped by file', groupCount === new Set(cliScan.findings.map((f) => f.location?.path ?? '')).size, `${groupCount} groups`);
  await page.click('xpath/.//label[contains(.,"Group by file")]/input');
  await page.select('#finding-sort', 'severity');
  const firstRow = await page.$('.finding-row');
  await firstRow.focus();
  await page.keyboard.press('ArrowDown');
  const arrowed = await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.finding-row')];
    return rows.indexOf(document.activeElement) === 1 && rows[1].getAttribute('aria-current') === 'true';
  });
  check('the Down arrow moves to and selects the next finding', arrowed);
  const rowButtons = await page.$$('.finding-row');
  await rowButtons[1].focus();
  await page.keyboard.press('Enter');
  const selected = await page.evaluate((el) => el.getAttribute('aria-current'), rowButtons[1]);
  const detailText = await page.$eval('#finding-detail', (el) => el.innerText.toUpperCase());
  check('a finding opens in the side panel with the keyboard', selected === 'true');
  check('detail explains what, why, what to do and the limits', ['WHAT WAS FOUND', 'WHY IT MATTERS', 'WHAT YOU CAN DO NEXT', 'LIMITS OF THIS RULE'].every((h) => detailText.includes(h)));
  check('evidence is redacted in the detail panel', !(await page.content()).includes(TOKEN));
  await page.screenshot({ path: join(out, 'findings-desktop.png'), fullPage: false });
  await axeCheck(page, 'findings explorer');

  // --- exports of the one-off scan (the server's renderers) --------------------------------
  await goTo(page, 'Reports');
  await clickButton(page, 'Download JSON');
  const jsonPath = await waitForDownload('reposentinel-report.json');
  const downloaded = jsonPath ? JSON.parse(readFileSync(jsonPath, 'utf-8')) : null;
  const strip = (r) => JSON.stringify({ ...r, scanned_at: undefined });
  check('downloaded JSON equals the CLI report (apart from the time)', downloaded && strip(downloaded) === strip(cliScan));
  await clickButton(page, 'Download HTML');
  const htmlPath = await waitForDownload('reposentinel-report.html');
  check('downloaded HTML is the standalone report', htmlPath && readFileSync(htmlPath, 'utf-8').includes("default-src 'none'"));
  await clickButton(page, 'Download SARIF');
  const sarifPath = await waitForDownload('reposentinel-report.sarif');
  const sarifText = sarifPath ? readFileSync(sarifPath, 'utf-8') : '';
  const sarif = sarifText ? JSON.parse(sarifText) : null;
  check('downloaded SARIF is version 2.1.0 with every finding', sarif?.version === '2.1.0' && sarif.runs[0].results.length === cliScan.findings.length);
  check('SARIF has no secret value and no absolute folder path', !sarifText.includes(TOKEN) && !sarifText.includes(JSON.stringify(demo).slice(1, -1)) && !sarifText.includes(demo));

  // --- register a project, scan, change, scan again and compare -------------------------
  await goTo(page, 'Projects');
  await page.click(button('Register project'));
  await page.waitForSelector('[role=alert]');
  check('registering without a name or path is explained', (await visibleText(page)).includes('Enter both a display name'));
  await page.type('#project-name', 'Demo app');
  await page.type('#project-path', 'relative\\folder');
  await page.click(button('Register project'));
  await page.waitForFunction(() => document.querySelector('[role=alert]')?.textContent?.includes('full path'));
  check('a relative project path is refused', true);
  await fill(page, '#project-path', projectDir);
  await page.click(button('Register project'));
  await page.waitForSelector('.project-card');
  check('the project is registered', (await visibleText(page)).includes('Registered "Demo app"'));
  check('local data is created outside the project', existsSync(join(dataDir, 'history.sqlite3')) && !readdirSync(projectDir).some((f) => /sqlite|reposentinel/i.test(f)));
  await axeCheck(page, 'projects with one project');
  await clickButton(page, 'Run first scan');
  await page.waitForFunction(() => document.querySelector('main h1')?.textContent === 'Scan' && document.body.innerText.includes('Saved scan #'), { timeout: 60000 });
  text = await visibleText(page);
  check('a project scan is saved to its history', text.includes('Saved scan #1 of Demo app'));
  check('the first saved scan says there is nothing to compare yet', text.includes("This is the project's first saved scan"));

  rmSync(join(projectDir, '.env'));
  write(join(projectDir, 'tools', 'release.py'), `RELEASE = "${TOKEN}"\n`);
  await clickButton(page, 'Scan again and compare');
  await page.waitForFunction(() => document.body.innerText.includes('Saved scan #2 of Demo app'), { timeout: 60000 });
  text = await visibleText(page);
  check('scan again compares with the previous scan', text.includes('Compared with scan #1'));
  const changeText = (await page.$eval('section[aria-labelledby=changes]', (el) => el.innerText)).replace('it does not mean the problem was fixed', '');
  check('the change summary never says fixed or resolved', !/fixed|resolved/i.test(changeText));
  await page.screenshot({ path: join(out, 'scan-again-compare.png'), fullPage: true });
  await axeCheck(page, 'project scan with comparison');

  await clickButton(page, 'Open the full comparison');
  await page.waitForFunction(() => document.querySelector('main h1')?.textContent === 'Compare');
  let compareText = await visibleText(page);
  check('the automatic comparison has the CLI headline', compareText.includes(cliCompare.headline), cliCompare.headline);
  for (const status of ['Not detected: file removed', 'New', 'Still detected']) {
    check(`comparison status shown: ${status}`, compareText.includes(status));
  }
  check('history limitation is visible on Compare', compareText.includes('Git history has not been scanned. A finding no longer detected'));

  await goTo(page, 'Findings');
  check('findings show their comparison status', (await page.$$eval('.status-chip', (els) => els.map((e) => e.textContent))).includes('New'));
  check('findings note what is no longer detected', (await visibleText(page)).includes('no longer detected and therefore not listed here'));

  await goTo(page, 'Overview');
  text = await visibleText(page);
  const lower = text.toLowerCase();
  check('overview shows what needs attention and what changed', lower.includes('what needs attention') && lower.includes('since scan #1') && text.includes('Detected again'));
  check('overview shows coverage and next actions', text.includes('Coverage') && text.includes('Next actions') && text.includes('All 3 checks completed.'));
  // The recent scans are loaded after the page opens: wait for that, then count.
  await settled(page);
  check('overview lists recent saved scans', (await page.$$eval('section[aria-labelledby=recent] tbody tr', (rows) => rows.length)) === 2);
  const claims = text.replace('They are not a score, and they do not show that the repository is secure or ready to publish.', '');
  check('overview has the not-a-score statement', text.includes('They are not a score'));
  check('overview never scores or calls the repository secure or ready', !/score|ready to publish|is secure|\d+\s*\/\s*100|%/i.test(claims));
  check('overview states that Git history was not scanned', text.includes('Git history') && text.includes('Not scanned'));
  await page.screenshot({ path: join(out, 'overview-desktop.png'), fullPage: true });
  await axeCheck(page, 'overview checklist');

  // --- history timeline, opening a saved scan, comparing saved scans ---------------------
  await goTo(page, 'History');
  await page.waitForSelector('#history-table ~ * tbody tr, section[aria-labelledby=history-table] tbody tr');
  const historyRows = await page.$$eval('section[aria-labelledby=history-table] tbody tr', (els) => els.length);
  check('history lists both saved scans', historyRows === 2, `${historyRows} rows`);
  check('the timeline chart has a text alternative and a table', await page.evaluate(() => Boolean(document.querySelector('.timeline svg[role=img][aria-label]'))) && historyRows === 2);
  check('the history table states the change from the scan before', (await visibleText(page)).includes('(vs #1)'));
  await page.screenshot({ path: join(out, 'history-desktop.png'), fullPage: true });
  await axeCheck(page, 'history');
  await page.click('xpath/.//input[@aria-label="Select scan #1 for comparison"]');
  await page.click('xpath/.//input[@aria-label="Select scan #2 for comparison"]');
  await clickButton(page, 'Compare selected scans');
  await page.waitForSelector('#compare-results-title');
  check('two scans selected in History are compared', (await heading(page)) === 'Compare' && (await visibleText(page)).includes(cliCompare.headline));
  const summary = await page.$eval('.status-strip', (el) => el.innerText);
  check('the comparison summary explains each status', ['New', 'Still detected', 'No longer detected', 'Not re-checked', 'Not comparable', 'Not proof that it is fixed'].every((t) => summary.includes(t)));
  await goTo(page, 'History');
  await page.waitForSelector('section[aria-labelledby=history-table] tbody tr');
  await clickButton(page, 'Open scan #1');
  await page.waitForFunction(() => document.querySelector('main h1')?.textContent === 'Findings');
  check('opening a saved scan shows its findings', (await visibleText(page)).includes('saved scan #1 of Demo app'));

  await goTo(page, 'Compare');
  await page.waitForFunction(() => document.querySelectorAll('#compare-older option').length === 2);
  await page.click(button('Compare saved scans'));
  await page.waitForFunction(() => document.querySelector('#compare-results-title'));
  compareText = await visibleText(page);
  check('comparing two saved scans needs no file upload and matches the CLI', compareText.includes(cliCompare.headline));
  await page.screenshot({ path: join(out, 'compare-saved.png'), fullPage: true });
  await axeCheck(page, 'compare saved scans');

  // Report import still works, and a malformed report is refused.
  const [oldInput, newInput] = await Promise.all([page.$('#old-report'), page.$('#new-report')]);
  await oldInput.uploadFile(before);
  await newInput.uploadFile(after);
  await clickButton(page, 'Compare reports');
  await page.waitForFunction((h) => document.body.innerText.includes(h) && document.body.innerText.includes('before.json'), {}, cliCompare.headline);
  check('comparing two uploaded JSON reports equals the CLI', (await visibleText(page)).includes(`Exit code ${cliCompare.exit_code}`));
  const broken = join(work, 'broken.json');
  writeFileSync(broken, '{ not json', 'utf-8');
  await oldInput.uploadFile(broken);
  await clickButton(page, 'Compare reports');
  await page.waitForFunction(() => document.querySelector('[role=alert]')?.textContent?.includes('not valid JSON'));
  check('malformed report is refused with a clear message', true);

  // SARIF of any saved scan.
  await goTo(page, 'Reports');
  await page.waitForFunction(() => document.querySelectorAll('#export-scan option').length === 2);
  await page.select('#export-scan', (await page.$$eval('#export-scan option', (o) => o.map((x) => x.value)))[1]);
  await page.click('xpath/.//section[@aria-labelledby="saved-export"]//button[normalize-space(.)="Download SARIF"]');
  const savedSarif = await waitForDownload('reposentinel-report-scan-1.sarif');
  check('a saved scan exports as SARIF', savedSarif && JSON.parse(readFileSync(savedSarif, 'utf-8')).version === '2.1.0');

  // --- hostile repository and hostile project name -----------------------------------------
  await goTo(page, 'Projects');
  await fill(page, '#project-name', '<img src=x onerror=alert(1)> & co');
  await fill(page, '#project-path', hostile);
  await page.click(button('Register project'));
  await page.waitForFunction(() => document.querySelectorAll('.project-card').length === 2);
  await page.click('xpath/.//li[contains(@class,"project-card")][.//h3[contains(.,"onerror")]]//button[normalize-space(.)="Run first scan"]');
  await page.waitForFunction(() => document.body.innerText.includes('Saved scan #3'), { timeout: 60000 });
  await goTo(page, 'Findings');
  const hostileText = await visibleText(page);
  const hostileHtml = await page.content();
  check('hostile scan: unknown credential not shown', !hostileText.includes(UNKNOWN) && !hostileHtml.includes(UNKNOWN));
  check('hostile scan: token not shown', !hostileHtml.includes(TOKEN));
  check('hostile scan: step name not shown', !hostileHtml.includes('deploy-with-pw'));
  check('hostile scan and project name: no injected elements', (await page.$$('main img, main script, main iframe, aside img')).length === 0);
  check('hostile project name is shown as text', hostileText.includes('<img src=x onerror=alert(1)> & co'));
  check('hostile file name shown as text', hostileText.includes("Q&A 'draft' \\u202etxt.md"));
  const stored = Buffer.concat(dbBytes());
  check('the local database holds no secret or hostile repository text', !stored.includes(TOKEN) && !stored.includes(UNKNOWN) && !stored.includes('deploy-with-pw') && stored.length > 0);

  // --- narrow screens and reduced motion ----------------------------------------------------
  await page.setViewport({ width: 375, height: 800 });
  // Regression: crossing the breakpoint used to animate the desktop sidebar off
  // the screen, covering the menu button for the duration of the slide.
  const coverAfterResize = await menuButtonCover(page);
  check('after resizing to a phone width the menu button is usable at once', coverAfterResize === null, coverAfterResize ?? 'not covered');
  await noOverflow(page, 'findings');
  await page.screenshot({ path: join(out, 'findings-phone.png'), fullPage: false });
  for (const label of ['Overview', 'Projects', 'Scan', 'History', 'Compare', 'Reports', 'Settings']) {
    await goTo(page, label);
    await noOverflow(page, label.toLowerCase());
  }
  await goTo(page, 'Projects');
  await page.screenshot({ path: join(out, 'projects-phone.png'), fullPage: true });
  await axeCheck(page, 'projects at 375 px');
  // The navigation menu on a phone: it opens, takes focus, and Escape closes it.
  await page.setViewport({ width: 375, height: 800 });
  await page.click('.menu-button');
  await page.waitForSelector('.menu-open .sidebar');
  const menuFocus = await page.evaluate(() => document.activeElement?.closest('.sidebar') !== null);
  await page.keyboard.press('Escape');
  const menuClosed = await page.evaluate(() => !document.querySelector('.menu-open') && document.activeElement?.classList.contains('menu-button'));
  check('the phone menu takes focus, and Escape closes it and returns focus', menuFocus && menuClosed);
  await page.setViewport({ width: 820, height: 1000 });
  for (const label of ['Overview', 'Findings', 'History', 'Compare']) {
    await goTo(page, label);
    await noOverflow(page, `${label.toLowerCase()} at 820 px`);
  }
  await page.setViewport({ width: 1280, height: 900 });
  await goTo(page, 'Settings');
  await page.click('xpath/.//label[contains(.,"Reduce motion")]/input');
  check('the reduce-motion preference applies to the page', await page.evaluate(() => document.documentElement.dataset.motion === 'reduce'));
  await page.click('xpath/.//label[contains(.,"Reduce motion")]/input');
  if (firefox) {
    skip('reduced motion turns transitions off', 'media-feature emulation needs Chrome or Edge');
  } else {
    await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
    const motion = await page.evaluate(() => getComputedStyle(document.querySelector('nav button')).transitionDuration);
    check('reduced motion turns transitions off', motion === '0s', motion);
    await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);
  }

  // --- deletion: one scan, a project's history, a project, all data ------------------------
  await goTo(page, 'History');
  await page.select('#history-project', (await page.$$eval('#history-project option', (o) => o.find((x) => x.textContent === 'Demo app').value)));
  await page.waitForFunction(() => document.querySelectorAll('section[aria-labelledby=history-table] tbody tr').length === 2);
  await page.click('xpath/.//tbody/tr[1]//button[normalize-space(.)="Delete"]');
  await page.waitForSelector(button('Delete scan #2'));
  check('deleting a scan asks for confirmation and focuses it', await page.evaluate(() => document.activeElement?.textContent === 'Delete scan #2'));
  await page.keyboard.press('Escape');
  check('Escape cancels the confirmation', !(await page.$(button('Delete scan #2'))));
  await page.click('xpath/.//tbody/tr[1]//button[normalize-space(.)="Delete"]');
  await page.click(button('Delete scan #2'));
  await page.waitForFunction(() => document.querySelectorAll('section[aria-labelledby=history-table] tbody tr').length === 1);
  check('one saved scan can be deleted', true);
  await goTo(page, 'Projects');
  const demoCard = 'xpath/.//li[contains(@class,"project-card")][.//h3[normalize-space(.)="Demo app"]]';
  await page.click(`${demoCard}//summary`);
  await page.click(`${demoCard}//button[normalize-space(.)="Clear history"]`);
  await page.click(`${demoCard}//button[normalize-space(.)="Delete its saved scans"]`);
  await page.waitForFunction(() => document.body.innerText.includes('Its saved scans were deleted.'));
  const cleared = await page
    .waitForFunction(() => document.body.innerText.includes('Not scanned yet.'), { timeout: 10000 })
    .then(() => true, () => false);
  check("a project's history can be cleared", cleared && (await page.$eval(demoCard, (el) => el.innerText)).includes('Not scanned yet.'));
  await page.click(`${demoCard}//button[normalize-space(.)="Remove project"]`);
  await page.click(`${demoCard}//button[normalize-space(.)="Remove project and its history"]`);
  await page.waitForFunction(() => document.querySelectorAll('.project-card').length === 1);
  check('a project can be removed (its folder is untouched)', existsSync(join(projectDir, 'tools', 'release.py')));
  await goTo(page, 'Settings');
  await page.waitForSelector(button('Delete all local data'));
  await page.click(button('Delete all local data'));
  await page.type('xpath/.//main//label[contains(.,"Type")]//input', 'delete');
  check('delete all needs the exact word DELETE', await page.$eval(button('Delete everything'), (el) => el.disabled));
  await fill(page, 'xpath/.//main//label[contains(.,"Type")]//input', 'DELETE');
  await axeCheck(page, 'settings delete-all confirmation');
  await page.click(button('Delete everything'));
  await page.waitForFunction(() => document.body.innerText.includes('All local RepoSentinel data was deleted.'));
  check('delete all removes the local data folder', !existsSync(dataDir));
  check('delete all leaves the scanned folders untouched', existsSync(join(hostile, '.github', 'workflows', 'ci.yml')));

  // --- browser security boundary ------------------------------------------------------------
  // The CSP, tested in the browser: injected markup cannot run or load anything.
  const csp = await page.evaluate(async () => {
    const violations = [];
    document.addEventListener('securitypolicyviolation', (e) => violations.push(e.violatedDirective));
    window.__ran = false;
    document.body.insertAdjacentHTML('beforeend', '<img src="http://probe.invalid/x.png" onerror="window.__ran=true"><script>window.__ran=true</script>');
    let fetched = 'blocked';
    try {
      await fetch('http://example.invalid/');
      fetched = 'allowed';
    } catch {
      /* blocked */
    }
    await new Promise((r) => setTimeout(r, 300));
    return { ran: window.__ran, fetched, violations };
  });
  check('CSP: injected handler and script did not run', csp.ran === false);
  check('CSP: request to another site was blocked', csp.fetched === 'blocked', csp.violations.join(', '));

  // Another website cannot use the API (no CORS; custom header forces a refused preflight).
  const evil = await newPage();
  await evil.goto('data:text/html,<title>other site</title>');
  const crossSite = await evil.evaluate(async (base) => {
    const results = [];
    for (const api of ['api/session', 'api/projects', 'api/data/delete-all']) {
      try {
        const r = await fetch(`${base}${api}`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', 'X-RepoSentinel-Request': '1' },
          body: '{"confirm":"DELETE"}',
        });
        results.push(`status ${r.status}`);
      } catch (e) {
        results.push('blocked');
      }
    }
    return results.join(', ');
  }, origin + basePath);
  check('another website cannot call the API (including history and delete-all)', crossSite === 'blocked, blocked, blocked', crossSite);
  await evil.close();

  // Cross-port isolation in the real browser: another service on 127.0.0.1.
  const other = await newPage();
  for (const path of ['/', '/s/', '/s/guess/api/session', '/api/session']) {
    await other.goto(spyOrigin + path);
  }
  check('another local service never receives a credential', spyGotCredential().length === 0, `${spyCookies.length} requests to ${spyOrigin}`);
  const fromSpy = await other.evaluate(async (api) => {
    try {
      const r = await fetch(api, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-RepoSentinel-Request': '1' }, body: '{}' });
      return `status ${r.status}`;
    } catch {
      return 'blocked';
    }
  }, origin + basePath + 'api/projects');
  check('a page on another local port cannot call the API', fromSpy === 'blocked', fromSpy);
  // A form posted from that page (the classic CSRF shape) is refused by the server.
  await Promise.all([
    other.waitForNavigation(),
    other.evaluate((action) => {
      const form = document.createElement('form');
      form.method = 'POST';
      form.enctype = 'text/plain';
      form.action = action;
      const field = document.createElement('input');
      field.name = '{"name":"x","path":"C:/","y":"';
      field.value = '"}';
      form.append(field);
      document.body.append(form);
      form.submit();
    }, origin + basePath + 'api/projects/add'),
  ]);
  const formResult = await other.evaluate(() => document.body.innerText);
  check('a form post from another local service is refused (same site, other port)', formResult.includes('cross-origin requests are not allowed'), formResult.slice(0, 80));
  check('the refused form post wrote no local data', !existsSync(dataDir));
  const navigation = await other.goto(origin + basePath + 'api/scan');
  check('navigating to the API is refused', navigation.status() === 405, `HTTP ${navigation.status()}`);
  await other.goto(spyOrigin + basePath + 'probe');
  await other.goto(spyOrigin + basePath + 'api/session');
  check('even at the secret base path, another local service receives no credential', spyGotCredential().length === 0);
  await other.close();

  // The one-time link cannot be reused, for example from browser history.
  const reuse = await newPage();
  await reuse.goto(launchUrl);
  await reuse.waitForFunction(() => document.body.innerText.includes('already been used'));
  check('the launch link works only once', true);
  await reuse.close();

  // --- a returning user: history survives a restart of the session -------------------------
  // (Register again, then reload: the session ends, but the saved history stays on disk.)
  await goTo(page, 'Projects');
  await fill(page, '#project-name', 'Demo app');
  await fill(page, '#project-path', projectDir);
  await page.click(button('Register project'));
  await page.waitForSelector('.project-card');
  await clickButton(page, 'Run first scan');
  await page.waitForFunction(() => document.body.innerText.includes('Saved scan #'), { timeout: 60000 });

  // The token lives only in the page's memory: reloading ends the session.
  await page.reload();
  await page.waitForFunction(() => document.body.innerText.includes('This page is not connected'));
  check('reloading the page ends the session (the token is not stored)', !(await page.evaluate(() => Boolean(document.querySelector('nav')))));

  // A returning user: RepoSentinel is stopped and started again on the same data folder.
  server.kill();
  await exited(server);
  server2 = spawn(python, ['-m', 'reposentinel', 'ui', '--no-browser'], { cwd: work, env: serverEnv });
  const secondUrl = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('second server did not start')), 20000);
    server2.stderr.on('data', (chunk) => {
      log2 += chunk.toString();
      const match = log2.match(/(http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]+\/#launch=\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
  });
  origin2 = new URL(secondUrl).origin;
  await page.goto(secondUrl, { waitUntil: 'networkidle0' });
  await page.waitForSelector('nav[aria-label=Main]');
  await page.waitForFunction(() => document.body.innerText.includes('Open latest'));
  text = await visibleText(page);
  check('a returning user sees their saved projects after a restart', text.includes('Demo app') && text.includes('Open latest'));
  await page.click('xpath/.//main//button[starts-with(normalize-space(.),"Open latest")]');
  await page.waitForFunction(() => document.body.innerText.toLowerCase().includes('what needs attention'));
  const reopened = await page.waitForFunction(() => document.body.innerText.includes('Saved scan #'), { timeout: 10000 }).then(() => true, () => false);
  check('a returning user can open their saved scan', reopened);
  await page.screenshot({ path: join(out, 'returning-user.png'), fullPage: true });

  const storedNow = Buffer.concat(dbBytes());
  const launchCodes = [launchUrl, secondUrl].map((u) => u.split('#launch=')[1]);
  check('no session token or launch code was ever written to the local database', tokens.length >= 2 && storedNow.length > 0 && [...tokens, ...launchCodes].every((t) => !storedNow.includes(t)), `${tokens.length} tokens checked`);

  // Every request stayed on this computer.
  const local = (url) => url.startsWith(origin) || url.startsWith(origin2) || url.startsWith(spyOrigin) || url.startsWith('data:') || url.startsWith('blob:');
  const outside = responses.filter((url) => !local(url));
  check('nothing outside this computer answered a request', outside.length === 0, outside.join(', ') || `${responses.length} local responses`);
  const blocked = failures.filter((f) => !local(f));
  check('outside requests attempted by the test probes failed without a response', blocked.every((f) => !responses.some((url) => f.startsWith(url))), blocked.join('; ') || 'none attempted');
  const leakyConsole = consoleMessages.filter((m) => m.includes(TOKEN) || m.includes(UNKNOWN));
  check('no secret in the browser console', leakyConsole.length === 0);
  const pageErrors = consoleMessages.filter((m) => m.startsWith('pageerror'));
  check('no uncaught errors in the page', pageErrors.length === 0, pageErrors.slice(0, 3).join(' | '));
  check('server printed no request log', ![serverLog, log2].some((log) => log.includes('/api/') || log.includes('GET ')));
} catch (error) {
  check('end-to-end run', false, error.stack);
} finally {
  await browser.close();
  spy.close();
  for (const child of [server, server2].filter(Boolean)) {
    child.kill();
    await exited(child);
  }
}

writeFileSync(join(out, 'results.json'), JSON.stringify({ browser: browserPath, results }, null, 2));
const failed = results.filter((r) => !r.ok).length;
const skipped = results.filter((r) => r.skipped).length;
console.log(
  `\n${results.length - failed - skipped} passed, ${failed} failed, ${skipped} skipped. Screenshots and results: ${out}`,
);
try {
  rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
} catch (error) {
  // A browser that failed to start can keep its profile folder open for a while.
  console.log(`Note: could not remove ${work} (${error.code}); delete it later.`);
}
process.exit(failed ? 1 : 0);
