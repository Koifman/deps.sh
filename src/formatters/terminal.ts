import type { RiskReport, RiskLevel, RecentScanResult, SecurityFeedResult, TransferScanResult, IncidentFeedResult, LockfileScanResult } from '../types.js';

// ANSI color codes
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const ORANGE = '\x1b[38;5;208m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';

const LEVEL_COLORS: Record<RiskLevel, string> = {
  LOW: GREEN,
  MODERATE: YELLOW,
  HIGH: ORANGE,
  CRITICAL: RED,
};

/** Strip control characters (including ESC for ANSI injection) from external strings. */
function stripControl(s: string): string {
  return s.replace(/[\x00-\x1F\x7F]/g, '');
}

function riskBar(score: number, color: string): string {
  const filled = Math.round(score / 10);
  const empty = 10 - filled;
  return `${color}${'█'.repeat(filled)}${DIM}${'░'.repeat(empty)}${RESET}`;
}

function pad(str: string, len: number): string {
  return str + ' '.repeat(Math.max(0, len - str.length));
}

function formatDownloads(n: number | null): string {
  if (n === null) return 'unknown';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return n.toString();
}

function timeSince(date: Date | null): string {
  if (!date) return 'unknown';
  const months = Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24 * 30));
  if (months < 1) return 'this month';
  if (months < 12) return `${months} month${months > 1 ? 's' : ''} ago`;
  const years = Math.floor(months / 12);
  return `${years}+ year${years > 1 ? 's' : ''} ago`;
}

export function formatTerminal(report: RiskReport, useColor: boolean): string {
  const c = useColor ? LEVEL_COLORS[report.level] : '';
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const w = useColor ? WHITE : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  // Header: name@version + RISK level
  const nameVer = `${report.package.name}@${report.package.version}`;
  const bar = useColor
    ? riskBar(report.totalScore, c)
    : `[${'#'.repeat(Math.round(report.totalScore / 10))}${'.'.repeat(10 - Math.round(report.totalScore / 10))}]`;
  const riskLabel = `RISK: ${report.level} ${bar} ${report.totalScore}/100`;
  const gap = Math.max(2, 50 - nameVer.length - riskLabel.replace(/\x1b\[[0-9;]*m/g, '').length);
  lines.push(`  ${b}${nameVer}${r}${' '.repeat(gap)}${c}${riskLabel}${r}`);
  lines.push('');

  // Warnings for critical signals
  const warnings: string[] = [];
  if (report.package.ownershipTransfer) {
    warnings.push(`${c}  \u26A0 OWNERSHIP TRANSFER detected${r}`);
  }
  if (report.package.installScripts.length > 0) {
    warnings.push(`${c}  \u26A0 Install scripts: ${report.package.installScripts.join(', ')}${r}`);
  }
  const criticalVulns = report.vulnerabilities.filter(v => v.severity === 'CRITICAL');
  if (criticalVulns.length > 0) {
    warnings.push(`${c}  \u26A0 ${criticalVulns.length} CRITICAL vulnerabilit${criticalVulns.length > 1 ? 'ies' : 'y'}${r}`);
    for (const vuln of criticalVulns) {
      const cve = vuln.aliases.find(a => a.startsWith('CVE-')) ?? vuln.id;
      const url = `https://osv.dev/vulnerability/${vuln.id}`;
      warnings.push(`${d}      ${cve}  ${cy}${url}${r}`);
    }
  }

  if (warnings.length > 0) {
    lines.push(...warnings);
    lines.push('');
  }

  // Detail rows
  const label = (s: string) => `${d}${pad(s, 18)}${r}`;

  lines.push(`  ${label('Maintainers')}${report.signals.find(s => s.name === 'Maintainer risk')?.detail ?? 'unknown'}`);
  lines.push(`  ${label('Last publish')}${report.package.lastPublish ? `${report.package.lastPublish.toISOString().split('T')[0]} (${timeSince(report.package.lastPublish)})` : 'unknown'}`);
  lines.push(`  ${label('Vulnerabilities')}${report.signals.find(s => s.name === 'Vulnerabilities')?.detail ?? 'unknown'}`);
  lines.push(`  ${label('Install scripts')}${report.signals.find(s => s.name === 'Install scripts')?.detail ?? 'none'}`);
  lines.push(`  ${label('Dependencies')}${report.signals.find(s => s.name === 'Dependencies')?.detail ?? 'unknown'}`);

  if (report.package.weeklyDownloads !== null) {
    lines.push(`  ${label('Weekly downloads')}${formatDownloads(report.package.weeklyDownloads)}`);
  }

  if (report.typosquatMatches.length > 0) {
    lines.push(`  ${label('Typosquats')}${report.typosquatMatches.length} detected (${report.typosquatMatches.slice(0, 3).join(', ')})`);
  }

  if (report.github) {
    lines.push(`  ${label('GitHub stars')}${formatDownloads(report.github.stars)}`);
    if (report.github.archived) {
      lines.push(`  ${c}${label('Status')}ARCHIVED${r}`);
    }
  }

  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatRecentTerminal(data: RecentScanResult, useColor: boolean): string {
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  if (data.packages.length === 0) {
    const scannedInfo = data.scannedAt ? ` (scanned ${timeAgo(data.scannedAt)})` : '';
    lines.push(`  ${d}No high-risk packages found${scannedInfo}${r}`);
    lines.push('');
    lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
    lines.push('');
    return lines.join('\n');
  }

  const scannedInfo = data.scannedAt ? ` (scanned ${timeAgo(data.scannedAt)})` : '';
  lines.push(`  ${b}Recent high-risk packages${r}${d}${scannedInfo}${r}`);
  lines.push('');

  for (const pkg of data.packages) {
    const c = useColor ? LEVEL_COLORS[pkg.level] : '';
    const ecoName = `${pkg.ecosystem}/${pkg.name}@${pkg.version}`;
    const risks = pkg.topRisks.join(', ');
    lines.push(`  ${c}${b}${String(pkg.score).padStart(3)}${r}  ${c}${pad(pkg.level, 9)}${r} ${pad(ecoName, 36)} ${d}${risks}${r}`);
  }

  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}

export function formatFeedTerminal(data: SecurityFeedResult, useColor: boolean): string {
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  if (data.entries.length === 0) {
    const fetchedInfo = data.fetchedAt ? ` (fetched ${timeAgo(data.fetchedAt)})` : '';
    lines.push(`  ${d}No recent advisories${fetchedInfo}${r}`);
    lines.push('');
    lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
    lines.push('');
    return lines.join('\n');
  }

  const fetchedInfo = data.fetchedAt ? ` (fetched ${timeAgo(data.fetchedAt)})` : '';
  lines.push(`  ${b}Recent security advisories${r}${d}${fetchedInfo}${r}`);
  lines.push('');

  const SEV_COLORS: Record<string, string> = { CRITICAL: RED, HIGH: ORANGE, MODERATE: YELLOW, LOW: GREEN };

  for (const entry of data.entries) {
    const eco = pad(entry.ecosystem, 6);
    const date = entry.date ? timeAgo(entry.date) : '';
    const sev = entry.severity ?? '';
    const sc = useColor && sev ? (SEV_COLORS[sev] ?? '') : '';
    const sevLabel = sev ? `${sc}${pad(sev, 9)}${r} ` : '';
    lines.push(`  ${sevLabel}${cy}${eco}${r} ${stripControl(entry.title)}  ${d}${date}${r}`);
    if (entry.url) {
      lines.push(`  ${d}${sev ? '                ' : '       '}${stripControl(entry.url)}${r}`);
    }
  }

  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}

export function formatIncidentsTerminal(data: IncidentFeedResult, useColor: boolean): string {
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  if (data.entries.length === 0) {
    const fetchedInfo = data.fetchedAt ? ` (fetched ${timeAgo(data.fetchedAt)})` : '';
    lines.push(`  ${d}No recent incidents${fetchedInfo}${r}`);
    lines.push('');
    lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
    lines.push('');
    return lines.join('\n');
  }

  const fetchedInfo = data.fetchedAt ? ` (fetched ${timeAgo(data.fetchedAt)})` : '';
  lines.push(`  ${b}Recent supply chain incidents${r}${d}${fetchedInfo}${r}`);
  lines.push('');

  for (const entry of data.entries) {
    const src = pad(entry.source, 13);
    const date = entry.date ? timeAgo(entry.date) : '';
    lines.push(`  ${cy}${src}${r} ${stripControl(entry.title)}  ${d}${date}${r}`);
    if (entry.url) {
      lines.push(`  ${d}              ${stripControl(entry.url)}${r}`);
    }
  }

  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}

export function formatLockfileScanTerminal(data: LockfileScanResult, useColor: boolean): string {
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  const capNote = data.totalPackages > data.scannedPackages
    ? ` (capped from ${data.totalPackages})`
    : '';
  lines.push(`  ${b}deps.sh lockfile scan${r}${d} — ${data.totalPackages} packages found, ${data.scannedPackages} scored${capNote}${r}`);
  lines.push('');

  // Only show MODERATE+ in terminal
  const notable = data.packages.filter(p => p.level !== 'LOW');

  if (notable.length === 0) {
    lines.push(`  ${d}No packages scored MODERATE or above.${r}`);
  } else {
    for (const pkg of notable) {
      const c = useColor ? LEVEL_COLORS[pkg.level] : '';
      const ecoName = `${pkg.ecosystem}/${pkg.name}@${pkg.version}`;
      const risks = pkg.topRisks.join(', ');
      lines.push(`  ${c}${b}${String(pkg.score).padStart(4)}${r}  ${c}${pad(pkg.level, 9)}${r} ${pad(ecoName, 36)} ${d}${risks}${r}`);
    }
  }

  lines.push('');
  lines.push(`  ${d}Summary: ${data.summary.critical} critical, ${data.summary.high} high, ${data.summary.moderate} moderate, ${data.summary.low} low${r}`);
  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}

export function formatTransfersTerminal(data: TransferScanResult, useColor: boolean): string {
  const b = useColor ? BOLD : '';
  const d = useColor ? DIM : '';
  const r = useColor ? RESET : '';
  const cy = useColor ? CYAN : '';

  const lines: string[] = [''];

  if (data.packages.length === 0) {
    const scannedInfo = data.scannedAt ? ` (scanned ${timeAgo(data.scannedAt)})` : '';
    lines.push(`  ${d}No ownership transfers detected${scannedInfo}${r}`);
    lines.push('');
    lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
    lines.push('');
    return lines.join('\n');
  }

  const scannedInfo = data.scannedAt ? ` (scanned ${timeAgo(data.scannedAt)})` : '';
  lines.push(`  ${b}Recent ownership transfers${r}${d}${scannedInfo}${r}`);
  lines.push('');

  for (const pkg of data.packages) {
    const c = useColor ? LEVEL_COLORS[pkg.level] : '';
    const ecoName = `${pkg.ecosystem}/${pkg.name}@${pkg.version}`;
    lines.push(`  ${c}${b}${String(pkg.score).padStart(3)}${r}  ${c}${pad(pkg.level, 9)}${r} ${pad(ecoName, 36)} ${d}${stripControl(pkg.previousOwner)} → ${stripControl(pkg.currentOwner)}${r}`);
  }

  lines.push('');
  lines.push(`  ${d}${'─'.repeat(50)}${r}`);
  lines.push(`  ${cy}deps.sh${r}${d} — supply chain risk scoring${r}`);
  lines.push('');

  return lines.join('\n');
}
