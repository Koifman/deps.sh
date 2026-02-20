import type { PackageInfo, VulnInfo, GitHubInfo, RiskSignal, RiskLevel, RiskReport } from '../types.js';
import { detectTyposquats } from './typosquat.js';

// Exact weights from spec — DO NOT MODIFY
const WEIGHTS = {
  vulnerabilities: 30,
  maintainer: 20,
  freshness: 15,
  installScripts: 15,
  dependencies: 10,
  typosquat: 10,
} as const;

// Exact thresholds from spec — DO NOT MODIFY
const THRESHOLDS: { level: RiskLevel; min: number; max: number }[] = [
  { level: 'LOW', min: 0, max: 20 },
  { level: 'MODERATE', min: 21, max: 45 },
  { level: 'HIGH', min: 46, max: 70 },
  { level: 'CRITICAL', min: 71, max: 100 },
];

function scoreVulnerabilities(vulns: VulnInfo[]): RiskSignal {
  let score = 0;
  for (const v of vulns) {
    switch (v.severity) {
      case 'CRITICAL': score += 30; break;
      case 'HIGH': score += 20; break;
      case 'MEDIUM': score += 10; break;
      case 'LOW': score += 5; break;
      case 'UNKNOWN': score += 5; break;
    }
  }
  score = Math.min(score, WEIGHTS.vulnerabilities);

  const detail = vulns.length === 0
    ? '0 known (OSV)'
    : `${vulns.length} known (${vulns.filter(v => v.severity === 'CRITICAL').length} critical)`;

  return { name: 'Vulnerabilities', score, maxScore: WEIGHTS.vulnerabilities, detail };
}

function scoreMaintainer(pkg: PackageInfo): RiskSignal {
  let score = 0;
  const details: string[] = [];

  if (pkg.ownershipTransfer) {
    score = 20;
    details.push('ownership transfer detected');
  } else if (pkg.maintainers.length === 1) {
    score = 10;
    details.push('single maintainer');
  } else if (pkg.maintainers.length === 0) {
    score = 15;
    details.push('no maintainer info');
  }

  score = Math.min(score, WEIGHTS.maintainer);
  const detail = details.length > 0 ? details.join(', ') : `${pkg.maintainers.length} active`;

  return { name: 'Maintainer risk', score, maxScore: WEIGHTS.maintainer, detail };
}

function scoreFreshness(pkg: PackageInfo): RiskSignal {
  if (!pkg.lastPublish) {
    return { name: 'Freshness', score: 15, maxScore: WEIGHTS.freshness, detail: 'unknown publish date' };
  }

  const monthsAgo = (Date.now() - pkg.lastPublish.getTime()) / (1000 * 60 * 60 * 24 * 30);
  let score: number;
  let detail: string;

  if (monthsAgo < 6) {
    score = 0;
    detail = formatDate(pkg.lastPublish);
  } else if (monthsAgo < 12) {
    score = 5;
    detail = formatDate(pkg.lastPublish);
  } else if (monthsAgo < 24) {
    score = 10;
    detail = formatDate(pkg.lastPublish);
  } else {
    score = 15;
    detail = `${formatDate(pkg.lastPublish)} (${Math.floor(monthsAgo / 12)}+ years ago)`;
  }

  return { name: 'Freshness', score, maxScore: WEIGHTS.freshness, detail };
}

function scoreInstallScripts(pkg: PackageInfo): RiskSignal {
  if (pkg.ecosystem !== 'npm') {
    return { name: 'Install scripts', score: 0, maxScore: WEIGHTS.installScripts, detail: 'N/A (not npm)' };
  }

  const score = pkg.installScripts.length > 0 ? 15 : 0;
  const detail = pkg.installScripts.length > 0
    ? pkg.installScripts.join(', ')
    : 'none';

  return { name: 'Install scripts', score, maxScore: WEIGHTS.installScripts, detail };
}

function scoreDependencies(pkg: PackageInfo): RiskSignal {
  const count = pkg.dependencies;
  let score: number;

  if (count === 0) score = 0;
  else if (count <= 5) score = 2;
  else if (count <= 20) score = 5;
  else if (count <= 50) score = 8;
  else score = 10;

  return { name: 'Dependencies', score, maxScore: WEIGHTS.dependencies, detail: `${count} direct` };
}

function scoreTyposquat(name: string, ecosystem: string): { signal: RiskSignal; matches: string[] } {
  const matches = detectTyposquats(name, ecosystem);
  const score = matches.length > 0 ? 10 : 0;
  const detail = matches.length > 0
    ? `${matches.length} detected (${matches.slice(0, 3).join(', ')})`
    : 'none detected';

  return {
    signal: { name: 'Typosquat risk', score, maxScore: WEIGHTS.typosquat, detail },
    matches,
  };
}

function classifyRisk(score: number): RiskLevel {
  for (const t of THRESHOLDS) {
    if (score >= t.min && score <= t.max) return t.level;
  }
  return 'CRITICAL';
}

function formatDate(d: Date): string {
  return d.toISOString().split('T')[0];
}

export function computeRiskReport(
  pkg: PackageInfo,
  vulns: VulnInfo[],
  github: GitHubInfo | null,
): RiskReport {
  const vulnSignal = scoreVulnerabilities(vulns);
  const maintainerSignal = scoreMaintainer(pkg);
  const freshnessSignal = scoreFreshness(pkg);
  const scriptsSignal = scoreInstallScripts(pkg);
  const depsSignal = scoreDependencies(pkg);
  const { signal: typosquatSignal, matches } = scoreTyposquat(pkg.name, pkg.ecosystem);

  const signals = [vulnSignal, maintainerSignal, freshnessSignal, scriptsSignal, depsSignal, typosquatSignal];
  const totalScore = Math.min(100, signals.reduce((sum, s) => sum + s.score, 0));

  return {
    package: pkg,
    vulnerabilities: vulns,
    github,
    signals,
    totalScore,
    level: classifyRisk(totalScore),
    typosquatMatches: matches,
  };
}
