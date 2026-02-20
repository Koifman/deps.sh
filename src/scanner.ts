#!/usr/bin/env bun
/**
 * CLI scanner — run by GitHub Actions every 6 hours.
 * Fetches recent packages from npm, PyPI, crates.io,
 * scores them, and writes high-risk results to data/recent-high-risk.json.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchNpmPackage } from './ecosystems/npm.js';
import { fetchPypiPackage } from './ecosystems/pypi.js';
import { fetchCratesPackage } from './ecosystems/crates.js';
import { fetchVulnerabilities } from './sources/osv.js';
import { fetchGitHubInfo } from './sources/github.js';
import { computeRiskReport } from './scoring/risk.js';
import type { Ecosystem, RecentScanEntry, RecentScanResult, RiskReport, SecurityFeedEntry, SecurityFeedResult, TransferEntry, TransferScanResult, IncidentEntry, IncidentFeedResult } from './types.js';
import { resilientFetch } from './fetch.js';

const SCORE_THRESHOLD = 80;
const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT_PATH = resolve(__dirname, '..', 'data', 'recent-high-risk.json');
const FEED_PATH = resolve(__dirname, '..', 'data', 'security-feed.json');
const TRANSFERS_PATH = resolve(__dirname, '..', 'data', 'recent-transfers.json');
const INCIDENTS_PATH = resolve(__dirname, '..', 'data', 'incidents-feed.json');

const RATE_LIMITS: Record<string, number> = {
  npm: 200,
  pypi: 500,
  cargo: 1000,
};

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function topRisks(report: RiskReport): string[] {
  return report.signals
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((s) => s.detail);
}

function toEntry(report: RiskReport): RecentScanEntry {
  return {
    name: report.package.name,
    version: report.package.version,
    ecosystem: report.package.ecosystem,
    score: report.totalScore,
    level: report.level,
    signals: report.signals,
    topRisks: topRisks(report),
  };
}

// ── npm: search API, filter by recently modified ──

async function fetchRecentNpm(): Promise<string[]> {
  try {
    const url = 'https://registry.npmjs.org/-/v1/search?text=keywords:javascript&size=250';
    const res = await fetch(url);
    if (!res.ok) {
      console.error(`npm search failed: HTTP ${res.status}`);
      return [];
    }
    const data = (await res.json()) as {
      objects: Array<{ package: { name: string; date: string } }>;
    };
    return data.objects.map((o) => o.package.name);
  } catch (err) {
    console.error(`npm search error: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

// ── PyPI: RSS updates feed ──

async function fetchRecentPypi(): Promise<string[]> {
  try {
    const res = await fetch('https://pypi.org/rss/updates.xml');
    if (!res.ok) {
      console.error(`PyPI RSS failed: HTTP ${res.status}`);
      return [];
    }
    const xml = await res.text();
    const names: string[] = [];
    const seen = new Set<string>();
    // <title>package-name X.Y.Z</title> — extract package name (first word)
    for (const match of xml.matchAll(/<title>([^<]+)<\/title>/g)) {
      const parts = match[1].trim().split(/\s+/);
      if (parts.length >= 2) {
        const name = parts[0];
        if (!seen.has(name)) {
          seen.add(name);
          names.push(name);
        }
      }
    }
    return names;
  } catch (err) {
    console.error(`PyPI RSS error: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

// ── crates.io: newest crates ──

async function fetchRecentCrates(): Promise<string[]> {
  try {
    const res = await resilientFetch('https://crates.io/api/v1/crates?page=1&per_page=50&sort=new', {
      headers: { 'User-Agent': 'deps.sh/1.0 (supply chain risk scoring)' },
    });
    if (!res.ok) {
      console.error(`crates.io failed: HTTP ${res.status}`);
      return [];
    }
    const data = (await res.json()) as { crates: Array<{ name: string }> };
    return data.crates.map((c) => c.name);
  } catch (err) {
    console.error(`crates.io error: ${err instanceof Error ? err.message : err}`);
    return [];
  }
}

// ── Scan a single package ──

async function scanPackage(
  name: string,
  ecosystem: Ecosystem,
  fetcher: (name: string) => Promise<import('./types.js').PackageInfo>,
): Promise<RiskReport | null> {
  try {
    const [pkg, vulns] = await Promise.all([
      fetcher(name),
      fetchVulnerabilities(name, ecosystem),
    ]);
    const github = pkg.repoUrl ? await fetchGitHubInfo(pkg.repoUrl) : null;
    return computeRiskReport(pkg, vulns, github);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  ✗ ${ecosystem}/${name}: ${msg}`);
    return null;
  }
}

// ── Scan an ecosystem sequentially with rate limiting ──

interface ScanResult {
  entries: RecentScanEntry[];
  transfers: TransferEntry[];
}

async function scanEcosystem(
  names: string[],
  ecosystem: Ecosystem,
  fetcher: (name: string) => Promise<import('./types.js').PackageInfo>,
): Promise<ScanResult> {
  const delay = RATE_LIMITS[ecosystem] ?? 200;
  const entries: RecentScanEntry[] = [];
  const transfers: TransferEntry[] = [];

  console.log(`Scanning ${names.length} ${ecosystem} packages (${delay}ms delay)...`);

  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    process.stdout.write(`  [${i + 1}/${names.length}] ${ecosystem}/${name}...`);
    const report = await scanPackage(name, ecosystem, fetcher);
    if (report) {
      if (report.totalScore > SCORE_THRESHOLD) {
        entries.push(toEntry(report));
        process.stdout.write(` ⚠ score=${report.totalScore} ${report.level}\n`);
      } else {
        process.stdout.write(` score=${report.totalScore} ok\n`);
      }
      // Collect ownership transfers regardless of score
      if (report.package.ownershipTransfer && report.package.previousOwner && report.package.currentOwner) {
        transfers.push({
          name: report.package.name,
          version: report.package.version,
          ecosystem: report.package.ecosystem,
          score: report.totalScore,
          level: report.level,
          previousOwner: report.package.previousOwner,
          currentOwner: report.package.currentOwner,
        });
      }
    } else {
      process.stdout.write(` failed\n`);
    }
    await sleep(delay);
  }

  return { entries, transfers };
}

// ── Security Feed: fetch Atom feeds from GitHub Advisory + RustSec ──

const FEED_URLS: Array<{ url: string; ecosystem: string }> = [
  { url: 'https://azu.github.io/github-advisory-database-rss/npm.rss', ecosystem: 'npm' },
  { url: 'https://azu.github.io/github-advisory-database-rss/pip.rss', ecosystem: 'pypi' },
  { url: 'https://rustsec.org/feed.xml', ecosystem: 'cargo' },
];

function parseAtomEntries(xml: string, ecosystem: string): SecurityFeedEntry[] {
  const entries: SecurityFeedEntry[] = [];
  const entryRegex = /<entry>([\s\S]*?)<\/entry>/g;
  let match;
  while ((match = entryRegex.exec(xml)) !== null) {
    const block = match[1];
    const title = (
      block.match(/<title[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/title>/)?.[1]?.trim()
      ?? block.match(/<title[^>]*>([^<]*)<\/title>/)?.[1]?.trim()
      ?? ''
    );
    const url = block.match(/<id>([^<]*)<\/id>/)?.[1]?.trim()
      ?? block.match(/<link[^>]*href="([^"]*)"[^>]*\/>/)?.[1]?.trim()
      ?? '';
    const date = block.match(/<updated>([^<]*)<\/updated>/)?.[1]?.trim()
      ?? block.match(/<published>([^<]*)<\/published>/)?.[1]?.trim()
      ?? '';
    if (title) {
      const severity = block.match(/<category[^>]*term="(CRITICAL|HIGH|MODERATE|LOW)"[^>]*\/?>/i)?.[1]?.toUpperCase();
      entries.push({ title, url, date, ecosystem, severity });
    }
  }
  return entries;
}

async function fetchSecurityFeeds(): Promise<SecurityFeedResult> {
  console.log('Fetching security advisory feeds...');
  const allEntries: SecurityFeedEntry[] = [];

  await Promise.all(FEED_URLS.map(async ({ url, ecosystem }) => {
    try {
      const res = await fetch(url);
      if (!res.ok) {
        console.error(`  Feed ${ecosystem} failed: HTTP ${res.status}`);
        return;
      }
      const xml = await res.text();
      const entries = parseAtomEntries(xml, ecosystem);
      allEntries.push(...entries);
      console.log(`  ${ecosystem}: ${entries.length} entries`);
    } catch (err) {
      console.error(`  Feed ${ecosystem} error: ${err instanceof Error ? err.message : err}`);
    }
  }));

  // Sort newest first, cap at 20
  allEntries.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  const capped = allEntries.slice(0, 20);

  return { fetchedAt: new Date().toISOString(), entries: capped };
}

// ── Incident Feed: supply chain security blogs ──

const INCIDENT_FEEDS: Array<{ url: string; source: string; format: 'rss' | 'atom' }> = [
  { url: 'https://snyk.io/blog/feed/', source: 'Snyk', format: 'rss' },
  { url: 'https://www.sonatype.com/blog/rss.xml', source: 'Sonatype', format: 'rss' },
  { url: 'https://hnrss.org/newest?q=%22supply+chain+attack%22+OR+%22malicious+package%22+OR+%22typosquatting%22+OR+%22dependency+confusion%22&points=5&count=20', source: 'Hacker News', format: 'rss' },
  { url: 'https://www.reversinglabs.com/blog/rss.xml', source: 'ReversingLabs', format: 'rss' },
  { url: 'https://jfrog.com/blog/feed/', source: 'JFrog', format: 'rss' },
];

// Match actual incidents, not thought leadership or partnership announcements
const INCIDENT_KEYWORDS = /malicious.package|typosquat|dependency.confusion|backdoor|compromis|hijack|malware|trojan|protestware|supply.chain.attack|installs?.*(malicious|backdoor)|discover.*(malicious|backdoor)|found.*(malicious|backdoor)|detect.*(malicious|backdoor)|infect|CVE-\d|vulnerabilit.*(exploit|critical|remote.code)|package.*(takeover|inject|poison)|account.*(takeover|compromis)|registry.*(attack|compromis)/i;
const INCIDENT_EXCLUDE = /partnership|securing the future|how .* are locking|what .* need to do|predictions|imperative|at scale|best practices|state of the/i;

function isSupplyChainRelevant(title: string): boolean {
  return INCIDENT_KEYWORDS.test(title) && !INCIDENT_EXCLUDE.test(title);
}

function parseRssEntries(xml: string, source: string): IncidentEntry[] {
  const entries: IncidentEntry[] = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const title = (
      block.match(/<title><!\[CDATA\[([\s\S]*?)\]\]><\/title>/)?.[1]?.trim()
      ?? block.match(/<title>([^<]*)<\/title>/)?.[1]?.trim()
      ?? ''
    );
    const url = block.match(/<link>([^<]*)<\/link>/)?.[1]?.trim() ?? '';
    const date = block.match(/<pubDate>([^<]*)<\/pubDate>/)?.[1]?.trim() ?? '';
    if (title && url) {
      entries.push({ title, url, date: date ? new Date(date).toISOString() : '', source });
    }
  }
  return entries;
}

async function fetchIncidentFeeds(): Promise<IncidentFeedResult> {
  console.log('Fetching incident feeds...');
  const allEntries: IncidentEntry[] = [];
  const seenUrls = new Set<string>();

  await Promise.all(INCIDENT_FEEDS.map(async ({ url, source, format }) => {
    try {
      const res = await resilientFetch(url);
      if (!res.ok) {
        console.error(`  Incidents ${source} failed: HTTP ${res.status}`);
        return;
      }
      const xml = await res.text();
      const entries = format === 'rss'
        ? parseRssEntries(xml, source)
        : parseAtomEntries(xml, source).map(e => ({ title: e.title, url: e.url, date: e.date, source }));

      // Filter by relevance, deduplicate by URL
      let kept = 0;
      for (const entry of entries) {
        if (!seenUrls.has(entry.url) && isSupplyChainRelevant(entry.title)) {
          seenUrls.add(entry.url);
          allEntries.push(entry);
          kept++;
        }
      }
      console.log(`  ${source}: ${kept}/${entries.length} relevant`);
    } catch (err) {
      console.error(`  Incidents ${source} error: ${err instanceof Error ? err.message : err}`);
    }
  }));

  allEntries.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  const capped = allEntries.slice(0, 20);

  return { fetchedAt: new Date().toISOString(), entries: capped };
}

// ── Main ──

async function main() {
  console.log('deps.sh scanner\n');

  // 1. Security advisory + incident feeds first (fast, no rate limiting)
  const [feedResult, incidentResult] = await Promise.all([
    fetchSecurityFeeds(),
    fetchIncidentFeeds(),
  ]);
  const outDir = dirname(OUTPUT_PATH);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(FEED_PATH, JSON.stringify(feedResult, null, 2) + '\n');
  writeFileSync(INCIDENTS_PATH, JSON.stringify(incidentResult, null, 2) + '\n');
  console.log(`${feedResult.entries.length} advisories, ${incidentResult.entries.length} incidents written\n`);

  // 2. Fetch package lists from all 3 ecosystems in parallel
  const [npmNames, pypiNames, crateNames] = await Promise.all([
    fetchRecentNpm(),
    fetchRecentPypi(),
    fetchRecentCrates(),
  ]);

  console.log(`Found: ${npmNames.length} npm, ${pypiNames.length} pypi, ${crateNames.length} cargo\n`);

  // 3. Scan all 3 ecosystems in parallel (sequential within each)
  const [npmResult, pypiResult, crateResult] = await Promise.all([
    scanEcosystem(npmNames, 'npm', fetchNpmPackage),
    scanEcosystem(pypiNames, 'pypi', fetchPypiPackage),
    scanEcosystem(crateNames, 'cargo', fetchCratesPackage),
  ]);

  const allEntries = [...npmResult.entries, ...pypiResult.entries, ...crateResult.entries]
    .sort((a, b) => b.score - a.score);

  const allTransfers = [...npmResult.transfers, ...pypiResult.transfers, ...crateResult.transfers]
    .sort((a, b) => b.score - a.score);

  const result: RecentScanResult = {
    scannedAt: new Date().toISOString(),
    count: allEntries.length,
    packages: allEntries,
  };

  const transferResult: TransferScanResult = {
    scannedAt: new Date().toISOString(),
    count: allTransfers.length,
    packages: allTransfers,
  };

  writeFileSync(OUTPUT_PATH, JSON.stringify(result, null, 2) + '\n');
  writeFileSync(TRANSFERS_PATH, JSON.stringify(transferResult, null, 2) + '\n');

  console.log(`\nDone. ${allEntries.length} high-risk, ${allTransfers.length} transfers, ${feedResult.entries.length} advisories, ${incidentResult.entries.length} incidents`);
}

main().catch((err) => {
  console.error('Scanner failed:', err);
  process.exit(1);
});
