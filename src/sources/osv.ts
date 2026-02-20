import type { Ecosystem, VulnInfo } from '../types.js';
import { resilientFetch } from '../fetch.js';

const ECOSYSTEM_MAP: Record<Ecosystem, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
};

interface OsvSeverityEntry {
  type: string;
  score: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  affected?: Array<{
    ranges?: Array<{
      events?: Array<Record<string, string>>;
    }>;
    versions?: string[];
  }>;
  severity?: OsvSeverityEntry[];
  database_specific?: {
    severity?: string;
  };
}

function cvssToSeverity(score: number): VulnInfo['severity'] {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function extractCvssScore(scoreStr: string): number | null {
  // CVSS vector strings end with metrics; try parsing as plain number first
  const asNum = parseFloat(scoreStr);
  if (!isNaN(asNum)) return asNum;

  // Try extracting base score from CVSS vector (e.g. CVSS:3.1/AV:N/AC:L/...)
  // The score itself isn't in the vector string — return null
  return null;
}

function parseSeverity(vuln: OsvVuln): VulnInfo['severity'] {
  // 1. Check database_specific.severity (plain label)
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(dbSev)) {
    return dbSev as VulnInfo['severity'];
  }

  // 2. Check severity[] array for CVSS scores
  if (vuln.severity?.length) {
    for (const entry of vuln.severity) {
      const score = extractCvssScore(entry.score);
      if (score !== null) return cvssToSeverity(score);
    }
  }

  return 'UNKNOWN';
}

function extractAffectedVersions(vuln: OsvVuln): string[] {
  const versions: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.versions) {
      versions.push(...affected.versions);
    }
  }
  return versions;
}

function parseVuln(vuln: OsvVuln): VulnInfo {
  return {
    id: vuln.id,
    summary: vuln.summary ?? '',
    severity: parseSeverity(vuln),
    aliases: vuln.aliases ?? [],
    affectedVersions: extractAffectedVersions(vuln),
  };
}

export async function fetchVulnerabilities(
  name: string,
  ecosystem: Ecosystem,
  signal?: AbortSignal,
): Promise<VulnInfo[]> {
  try {
    const res = await resilientFetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: {
          name,
          ecosystem: ECOSYSTEM_MAP[ecosystem],
        },
      }),
      signal,
    });

    if (!res.ok) return [];

    const data = (await res.json()) as { vulns?: OsvVuln[] };
    if (!data.vulns?.length) return [];

    return data.vulns.map(parseVuln);
  } catch {
    return [];
  }
}
