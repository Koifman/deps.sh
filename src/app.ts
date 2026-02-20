import { Hono } from 'hono';
import type { Ecosystem } from './types.js';
import { cacheGet, cacheSet, cacheKey } from './cache.js';
import { fetchNpmPackage } from './ecosystems/npm.js';
import { fetchPypiPackage } from './ecosystems/pypi.js';
import { fetchCratesPackage } from './ecosystems/crates.js';
import { fetchVulnerabilities } from './sources/osv.js';
import { fetchGitHubInfo } from './sources/github.js';
import { computeRiskReport } from './scoring/risk.js';
import { formatTerminal, formatRecentTerminal, formatFeedTerminal, formatIncidentsTerminal, formatTransfersTerminal, formatLockfileScanTerminal } from './formatters/terminal.js';
import { formatJson } from './formatters/json.js';
import { parseLockfile } from './parsers/lockfile.js';
import type { RiskReport, RiskLevel, RecentScanResult, SecurityFeedResult, TransferScanResult, IncidentFeedResult, LockfileScanResult, LockfileScanEntry } from './types.js';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = new Hono();

// Security headers for all responses
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // CSP only for HTML responses
  if (c.res.headers.get('content-type')?.includes('text/html')) {
    c.header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src https:; connect-src 'self'");
  }
});

const MAX_PACKAGE_NAME = 214; // npm max package name length

const ECOSYSTEM_MAP: Record<string, Ecosystem> = {
  npm: 'npm',
  pip: 'pypi',
  pypi: 'pypi',
  cargo: 'cargo',
  crates: 'cargo',
};

const FETCHERS: Record<Ecosystem, (name: string, signal?: AbortSignal) => Promise<import('./types.js').PackageInfo>> = {
  npm: fetchNpmPackage,
  pypi: fetchPypiPackage,
  cargo: fetchCratesPackage,
};

function isCurl(ua: string | undefined): boolean {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  return lower.includes('curl') || lower.includes('wget') || lower.includes('httpie');
}

function wantsJson(url: URL, accept: string | undefined): boolean {
  if (url.searchParams.has('json')) return true;
  if (accept?.includes('application/json')) return true;
  return false;
}

// Track unique IPs hitting scan endpoints in the last 60 seconds
const recentScans: Map<string, number> = new Map();

function trackScan(ip: string): void {
  if (recentScans.size >= MAX_RATE_ENTRIES && !recentScans.has(ip)) {
    const firstKey = recentScans.keys().next().value;
    if (firstKey !== undefined) recentScans.delete(firstKey);
  }
  recentScans.set(ip, Date.now());
}

function getActiveScanners(): number {
  const cutoff = Date.now() - 60_000;
  let count = 0;
  for (const [ip, ts] of recentScans) {
    if (ts >= cutoff) {
      count++;
    } else {
      recentScans.delete(ip);
    }
  }
  return count;
}

// Rate limiting for POST /scan: max 10 requests per IP per 60 seconds
const scanRateLimit: Map<string, number[]> = new Map();
const SCAN_RATE_WINDOW = 60_000;
const SCAN_RATE_MAX = 10;
const MAX_RATE_ENTRIES = 10_000;

function checkScanRateLimit(ip: string): boolean {
  const now = Date.now();
  const cutoff = now - SCAN_RATE_WINDOW;
  const timestamps = (scanRateLimit.get(ip) ?? []).filter(t => t > cutoff);
  // Evict oldest entry if map is at capacity
  if (scanRateLimit.size >= MAX_RATE_ENTRIES && !scanRateLimit.has(ip)) {
    const firstKey = scanRateLimit.keys().next().value;
    if (firstKey !== undefined) scanRateLimit.delete(firstKey);
  }
  if (timestamps.length >= SCAN_RATE_MAX) {
    scanRateLimit.set(ip, timestamps);
    return false; // over limit
  }
  timestamps.push(now);
  scanRateLimit.set(ip, timestamps);
  return true; // allowed
}

function clientIp(c: { req: { header: (name: string) => string | undefined } }): string {
  // Prefer x-real-ip (set by trusted proxies like Vercel/nginx, not spoofable by client)
  return c.req.header('x-real-ip')
    ?? c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    ?? 'unknown';
}

function readDataFile<T>(filename: string, fallback: T): T {
  try {
    const __dir = dirname(fileURLToPath(import.meta.url));
    const filePath = resolve(__dir, '..', 'data', filename);
    return JSON.parse(readFileSync(filePath, 'utf-8')) as T;
  } catch {
    return fallback;
  }
}

async function generateReport(ecosystem: Ecosystem, packageName: string, signal?: AbortSignal): Promise<RiskReport> {
  const key = cacheKey(ecosystem, packageName);
  const cached = cacheGet<RiskReport>(key);
  if (cached) return cached;

  const fetcher = FETCHERS[ecosystem];
  const [pkg, vulns] = await Promise.all([
    fetcher(packageName, signal),
    fetchVulnerabilities(packageName, ecosystem, signal),
  ]);

  const github = pkg.repoUrl ? await fetchGitHubInfo(pkg.repoUrl, signal) : null;
  const report = computeRiskReport(pkg, vulns, github);

  cacheSet(key, report);
  return report;
}

// Homepage
app.get('/', (c) => {
  const ua = c.req.header('user-agent');
  if (isCurl(ua)) {
    return c.text(`
  deps.sh — supply chain risk scoring

  Usage:
    curl deps.sh/npm/<package>       npm package
    curl deps.sh/pip/<package>       PyPI package
    curl deps.sh/cargo/<package>     crates.io package
    curl deps.sh/<package>           defaults to npm
    curl deps.sh/recent              high-risk packages (last scan)
    curl deps.sh/feed                security advisories
    curl deps.sh/incidents           supply chain incidents
    curl deps.sh/transfers           ownership transfers

  Lockfile scanning:
    curl -X POST deps.sh/scan -d @package-lock.json
    curl -X POST deps.sh/scan -d @requirements.txt
    curl -X POST deps.sh/scan -d @Cargo.lock

  Options:
    ?json                            JSON output

  Examples:
    curl deps.sh/npm/lodash
    curl deps.sh/pip/requests
    curl deps.sh/cargo/serde
    curl deps.sh/npm/lodash?json
    curl deps.sh/recent

  Source: github.com/koifman/deps.sh
`);
  }

  const feed = readDataFile<SecurityFeedResult>('security-feed.json', { fetchedAt: null, entries: [] });
  const incidents = readDataFile<IncidentFeedResult>('incidents-feed.json', { fetchedAt: null, entries: [] });
  const scanners = getActiveScanners();

  const SEV_COLORS: Record<string, string> = { CRITICAL: '#f85149', HIGH: '#f0883e', MODERATE: '#e3b341', LOW: '#3fb950' };

  const feedHtml = feed.entries.length > 0
    ? feed.entries.map(e => {
        const ago = e.date ? timeAgoHtml(e.date) : '';
        const sevColor = e.severity ? SEV_COLORS[e.severity] ?? '#8b949e' : '';
        const sevBadge = e.severity ? `<span class="feed-sev" style="color:${sevColor}">${escHtml(e.severity)}</span> ` : '';
        return `<li>${sevBadge}<span class="feed-eco">${escHtml(e.ecosystem)}</span> <a href="${safeHref(e.url)}">${escHtml(e.title)}</a> <span class="feed-date">${ago}</span></li>`;
      }).join('\n    ')
    : '<li class="feed-empty">No recent advisories.</li>';

  const incidentsHtml = incidents.entries.length > 0
    ? incidents.entries.map(e => {
        const ago = e.date ? timeAgoHtml(e.date) : '';
        return `<li><span class="feed-eco">${escHtml(e.source)}</span> <a href="${safeHref(e.url)}">${escHtml(e.title)}</a> <span class="feed-date">${ago}</span></li>`;
      }).join('\n    ')
    : '<li class="feed-empty">No recent incidents.</li>';

  const feedAge = feed.fetchedAt ? ` <span class="feed-date">(${timeAgoHtml(feed.fetchedAt)})</span>` : '';
  const incidentAge = incidents.fetchedAt ? ` <span class="feed-date">(${timeAgoHtml(incidents.fetchedAt)})</span>` : '';

  return c.html(`<!DOCTYPE html>
<html><head><title>deps.sh — supply chain risk scoring</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: monospace; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
  .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 32px; }
  .columns h2 { margin-top: 0; }
  @media (max-width: 700px) { .columns { grid-template-columns: 1fr; } }
  h1 { color: #58a6ff; } code { background: #161b22; padding: 2px 6px; border-radius: 4px; }
  pre { background: #161b22; padding: 16px; border-radius: 8px; overflow-x: auto; }
  a { color: #58a6ff; }
  .scanners { text-align: center; color: #8b949e; font-size: 13px; margin: 8px 0 24px 0; }
  .scanners strong { color: #58a6ff; }
  h2 { color: #c9d1d9; font-size: 16px; margin-top: 32px; }
  .feed { list-style: none; padding: 0; }
  .feed li { padding: 4px 0; border-bottom: 1px solid #21262d; }
  .feed-eco { background: #161b22; color: #58a6ff; padding: 1px 6px; border-radius: 3px; font-size: 11px; }
  .feed-sev { font-size: 10px; font-weight: bold; padding: 1px 4px; border-radius: 3px; background: #161b22; }
  .feed-date { color: #484f58; font-size: 12px; }
  .feed-empty { color: #484f58; }
</style></head>
<body>
<div class="scanners">${scanners > 0 ? `<strong>${scanners}</strong> scanning now` : ''}</div>
<h1>deps.sh</h1>
<p>Supply chain risk scoring as a service.</p>
<pre>
curl deps.sh/npm/lodash          # npm package
curl deps.sh/pip/requests        # PyPI package
curl deps.sh/cargo/serde         # crates.io package
curl deps.sh/lodash              # defaults to npm
curl deps.sh/recent              # high-risk packages (last scan)
curl deps.sh/feed                # security advisories
curl deps.sh/incidents           # supply chain incidents
curl deps.sh/transfers           # ownership transfers
curl -X POST deps.sh/scan -d @package-lock.json  # lockfile scan
curl deps.sh/npm/lodash?json     # JSON output
</pre>
<div class="columns">
<div>
<h2>Recent Advisories${feedAge}</h2>
<ul class="feed">
    ${feedHtml}
</ul>
</div>
<div>
<h2>Supply Chain Incidents${incidentAge}</h2>
<ul class="feed">
    ${incidentsHtml}
</ul>
</div>
</div>
<p>Source: <a href="https://github.com/koifman/deps.sh">github.com/koifman/deps.sh</a></p>
</body></html>`);
});

function timeAgoHtml(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Read request body with streaming size limit. Returns null if body exceeds maxSize. */
async function readBodyWithLimit(req: Request, maxSize: number): Promise<string | null> {
  const cl = parseInt(req.headers.get('content-length') ?? '', 10);
  if (cl > maxSize) return null;

  const reader = req.body?.getReader();
  if (!reader) return '';

  const chunks: Uint8Array[] = [];
  let totalSize = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.byteLength;
      if (totalSize > maxSize) {
        reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(combined);
}

/** Only allow http/https URLs in HTML href attributes. Blocks javascript: and data: schemes. */
function safeHref(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return escHtml(url);
    }
  } catch { /* malformed URL */ }
  return '#';
}

// Recent high-risk packages (pre-computed by scanner)
app.get('/recent', (c) => {
  const data = readDataFile<RecentScanResult>('recent-high-risk.json', { scannedAt: null, count: 0, packages: [] });

  const url = new URL(c.req.url);
  if (wantsJson(url, c.req.header('accept'))) {
    return c.json(data);
  }

  const useColor = isCurl(c.req.header('user-agent'));
  return c.text(formatRecentTerminal(data, useColor));
});

// Security advisory feed
app.get('/feed', (c) => {
  const data = readDataFile<SecurityFeedResult>('security-feed.json', { fetchedAt: null, entries: [] });

  const url = new URL(c.req.url);
  if (wantsJson(url, c.req.header('accept'))) {
    return c.json(data);
  }

  const useColor = isCurl(c.req.header('user-agent'));
  return c.text(formatFeedTerminal(data, useColor));
});

// Supply chain incidents
app.get('/incidents', (c) => {
  const data = readDataFile<IncidentFeedResult>('incidents-feed.json', { fetchedAt: null, entries: [] });

  const url = new URL(c.req.url);
  if (wantsJson(url, c.req.header('accept'))) {
    return c.json(data);
  }

  const useColor = isCurl(c.req.header('user-agent'));
  return c.text(formatIncidentsTerminal(data, useColor));
});

// Ownership transfers
app.get('/transfers', (c) => {
  const data = readDataFile<TransferScanResult>('recent-transfers.json', { scannedAt: null, count: 0, packages: [] });

  const url = new URL(c.req.url);
  if (wantsJson(url, c.req.header('accept'))) {
    return c.json(data);
  }

  const useColor = isCurl(c.req.header('user-agent'));
  return c.text(formatTransfersTerminal(data, useColor));
});

// Concurrency-limited map
async function mapConcurrent<T, R>(items: T[], fn: (item: T) => Promise<R>, limit: number): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;
  const worker = async () => {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

const MAX_SCAN_PACKAGES = 100;
const SCAN_CONCURRENCY = 5;
const MAX_BODY_SIZE = 5 * 1024 * 1024; // 5MB
const SCAN_TIMEOUT = 60_000; // 60 seconds

// Lockfile scanning
app.post('/scan', async (c) => {
  const ip = clientIp(c);
  if (!checkScanRateLimit(ip)) {
    return c.text('Rate limit exceeded. Max 10 scans per minute.\n', 429);
  }

  const body = await readBodyWithLimit(c.req.raw, MAX_BODY_SIZE);
  if (body === null) {
    return c.text('Request body too large (max 5MB).\n', 413);
  }
  if (!body.trim()) {
    return c.text('Empty request body. Pipe a lockfile:\n  curl -X POST deps.sh/scan -d @package-lock.json\n', 400);
  }

  const { format, ecosystem, deps } = parseLockfile(body);
  if (format === 'unknown' || deps.length === 0) {
    return c.text('Could not detect lockfile format. Supported: package-lock.json, package.json, requirements.txt, Cargo.lock\n', 400);
  }

  const totalPackages = deps.length;
  const toScore = deps.slice(0, MAX_SCAN_PACKAGES);

  // Abort signal cancels in-flight scoring via Promise.race
  const timeout = AbortSignal.timeout(SCAN_TIMEOUT);

  const scored = await mapConcurrent(toScore, async (dep) => {
    if (timeout.aborted) {
      return {
        name: dep.name, version: dep.version, ecosystem: dep.ecosystem,
        score: 0, level: 'LOW' as RiskLevel, topRisks: ['scan timed out'],
      } satisfies LockfileScanEntry;
    }
    try {
      const report = await Promise.race([
        generateReport(dep.ecosystem, dep.name, timeout),
        new Promise<never>((_, reject) => {
          if (timeout.aborted) { reject(new Error('timeout')); return; }
          timeout.addEventListener('abort', () => reject(new Error('timeout')), { once: true });
        }),
      ]);
      const topRisks = report.signals
        .filter(s => s.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 3)
        .map(s => s.detail);
      return {
        name: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        score: report.totalScore,
        level: report.level,
        topRisks,
      } satisfies LockfileScanEntry;
    } catch {
      return {
        name: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        score: 0,
        level: 'LOW' as RiskLevel,
        topRisks: [timeout.aborted ? 'scan timed out' : 'score unavailable'],
      } satisfies LockfileScanEntry;
    }
  }, SCAN_CONCURRENCY);

  // Sort by score descending
  scored.sort((a, b) => b.score - a.score);

  const summary = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const pkg of scored) {
    const key = pkg.level.toLowerCase() as keyof typeof summary;
    summary[key]++;
  }

  const result: LockfileScanResult = {
    format,
    ecosystem,
    totalPackages,
    scannedPackages: scored.length,
    summary,
    packages: scored,
  };

  const url = new URL(c.req.url);
  if (wantsJson(url, c.req.header('accept'))) {
    return c.json(result);
  }

  const useColor = isCurl(c.req.header('user-agent'));
  return c.text(formatLockfileScanTerminal(result, useColor));
});

/** Sanitize user input for safe inclusion in text responses. Strips control chars and caps length. */
function sanitizeName(s: string): string {
  return s.replace(/[\x00-\x1F\x7F]/g, '').slice(0, MAX_PACKAGE_NAME);
}

// Package lookup with ecosystem prefix
app.get('/:ecosystem/:package', async (c) => {
  const ecosystemParam = c.req.param('ecosystem').toLowerCase();
  const packageName = c.req.param('package');
  trackScan(clientIp(c));

  if (packageName.length > MAX_PACKAGE_NAME) {
    return c.text('Package name too long.\n', 400);
  }

  const ecosystem = ECOSYSTEM_MAP[ecosystemParam];
  if (!ecosystem) {
    return c.text(`Unknown ecosystem: ${sanitizeName(ecosystemParam)}\n\nSupported: npm, pip, cargo\n`, 400);
  }

  try {
    const report = await generateReport(ecosystem, packageName);
    const url = new URL(c.req.url);

    if (wantsJson(url, c.req.header('accept'))) {
      return c.json(JSON.parse(formatJson(report)));
    }

    const useColor = isCurl(c.req.header('user-agent'));
    return c.text(formatTerminal(report, useColor));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '';
    const safeName = sanitizeName(packageName);
    const safeEco = sanitizeName(ecosystemParam);
    if (msg.includes('not found') || msg.includes('404')) {
      return c.text(`Package not found: ${safeEco}/${safeName}\n`, 404);
    }
    return c.text(`Error scoring ${safeEco}/${safeName}. Try again later.\n`, 500);
  }
});

// Default to npm when no ecosystem prefix
app.get('/:package', async (c) => {
  const packageName = c.req.param('package');
  trackScan(clientIp(c));

  // Skip favicon and other browser requests
  if (packageName === 'favicon.ico' || packageName === 'robots.txt') {
    return c.text('', 404);
  }

  if (packageName.length > MAX_PACKAGE_NAME) {
    return c.text('Package name too long.\n', 400);
  }

  try {
    const report = await generateReport('npm', packageName);
    const url = new URL(c.req.url);

    if (wantsJson(url, c.req.header('accept'))) {
      return c.json(JSON.parse(formatJson(report)));
    }

    const useColor = isCurl(c.req.header('user-agent'));
    return c.text(formatTerminal(report, useColor));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : '';
    const safeName = sanitizeName(packageName);
    if (msg.includes('not found') || msg.includes('404')) {
      return c.text(`Package not found: npm/${safeName}\n`, 404);
    }
    return c.text(`Error scoring npm/${safeName}. Try again later.\n`, 500);
  }
});

export default app;
