import type { PackageInfo, MaintainerInfo, EcosystemAdapter } from '../types';
import { resilientFetch } from '../fetch.js';

const REGISTRY_URL = 'https://registry.npmjs.org';
const DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week';

interface NpmRegistryResponse {
  name: string;
  description?: string;
  'dist-tags': { latest: string };
  versions: Record<string, NpmVersionData>;
  time: Record<string, string>;
  maintainers: Array<{ name: string; email?: string }>;
  repository?: { type?: string; url?: string } | string;
}

interface NpmVersionData {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  _npmUser?: { name: string; email?: string };
}

interface NpmDownloadsResponse {
  downloads: number;
}

interface FetchOptions {
  includeDownloads?: boolean;
}

function parseRepoUrl(repository: NpmRegistryResponse['repository']): string | null {
  if (!repository) return null;
  const raw = typeof repository === 'string' ? repository : repository.url;
  if (!raw) return null;
  return raw
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/\.git$/, '')
    .replace(/^ssh:\/\/git@github\.com/, 'https://github.com');
}

function extractInstallScripts(scripts: Record<string, string> | undefined): string[] {
  if (!scripts) return [];
  const dangerous = ['preinstall', 'install', 'postinstall'];
  return dangerous.filter((s) => s in scripts);
}

interface OwnershipTransferResult {
  transferred: boolean;
  previousOwner?: string;
  currentOwner?: string;
}

function detectOwnershipTransfer(versions: Record<string, NpmVersionData>, time: Record<string, string>): OwnershipTransferResult {
  const versionsByTime = Object.keys(versions)
    .filter((v) => v in time && v !== 'created' && v !== 'modified')
    .sort((a, b) => new Date(time[a]).getTime() - new Date(time[b]).getTime());

  if (versionsByTime.length < 2) return { transferred: false };

  const firstRaw = versions[versionsByTime[0]]?._npmUser?.name;
  const lastRaw = versions[versionsByTime[versionsByTime.length - 1]]?._npmUser?.name;

  if (!firstRaw || !lastRaw) return { transferred: false };
  if (firstRaw.toLowerCase() === lastRaw.toLowerCase()) return { transferred: false };

  return { transferred: true, previousOwner: firstRaw, currentOwner: lastRaw };
}

async function fetchDownloads(name: string, signal?: AbortSignal): Promise<number | null> {
  try {
    const res = await resilientFetch(`${DOWNLOADS_URL}/${encodeURIComponent(name)}`, { signal });
    if (!res.ok) return null;
    const data = (await res.json()) as NpmDownloadsResponse;
    return data.downloads ?? null;
  } catch {
    return null;
  }
}

export async function fetchNpmPackage(name: string, signal?: AbortSignal, options?: FetchOptions): Promise<PackageInfo> {
  const res = await resilientFetch(`${REGISTRY_URL}/${encodeURIComponent(name)}`, { signal });

  if (res.status === 404) {
    throw new Error(`npm package not found: ${name}`);
  }
  if (!res.ok) {
    throw new Error(`npm registry error for ${name}: HTTP ${res.status}`);
  }

  const data = (await res.json()) as NpmRegistryResponse;
  const latestVersion = data['dist-tags'].latest;
  const latestData = data.versions[latestVersion];

  if (!latestData) {
    throw new Error(`npm package ${name}: latest version ${latestVersion} has no version data`);
  }

  const maintainers: MaintainerInfo[] = (data.maintainers ?? []).map((m) => ({
    name: m.name,
    ...(m.email ? { email: m.email } : {}),
  }));

  const lastPublishStr = data.time?.[latestVersion];
  const lastPublish = lastPublishStr ? new Date(lastPublishStr) : null;

  const deps = latestData.dependencies ?? {};
  const includeDownloads = options?.includeDownloads ?? true;
  const weeklyDownloads = includeDownloads ? await fetchDownloads(name, signal) : null;
  const transfer = detectOwnershipTransfer(data.versions, data.time);

  return {
    name: data.name,
    version: latestVersion,
    ecosystem: 'npm',
    maintainers,
    lastPublish,
    dependencies: Object.keys(deps).length,
    weeklyDownloads,
    installScripts: extractInstallScripts(latestData.scripts),
    repoUrl: parseRepoUrl(data.repository),
    description: data.description ?? null,
    ownershipTransfer: transfer.transferred,
    ...(transfer.previousOwner ? { previousOwner: transfer.previousOwner } : {}),
    ...(transfer.currentOwner ? { currentOwner: transfer.currentOwner } : {}),
  };
}

export const npmAdapter: EcosystemAdapter = {
  ecosystem: 'npm',
  fetch: fetchNpmPackage,
};
