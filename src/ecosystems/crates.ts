import type { PackageInfo, MaintainerInfo, EcosystemAdapter } from '../types';
import { resilientFetch } from '../fetch.js';

const API_BASE = 'https://crates.io/api/v1/crates';
const USER_AGENT = 'deps.sh/1.0 (supply chain risk scoring)';

interface CrateResponse {
  crate: {
    name: string;
    newest_version: string;
    description: string | null;
    repository: string | null;
    updated_at: string;
    recent_downloads: number | null;
  };
  versions: Array<{
    num: string;
    updated_at: string;
  }>;
}

interface CrateOwner {
  login: string;
  name: string | null;
}

interface OwnersResponse {
  users: CrateOwner[];
}

interface DepsResponse {
  dependencies: Array<{
    kind: string; // 'normal' | 'dev' | 'build'
  }>;
}

function headers(): HeadersInit {
  return { 'User-Agent': USER_AGENT };
}

async function fetchOwners(name: string, signal?: AbortSignal): Promise<MaintainerInfo[]> {
  try {
    const res = await resilientFetch(`${API_BASE}/${encodeURIComponent(name)}/owners`, { headers: headers(), signal });
    if (!res.ok) return [];
    const data = (await res.json()) as OwnersResponse;
    return (data.users ?? []).map((o) => ({
      name: o.name || o.login,
    }));
  } catch {
    return [];
  }
}

async function fetchDepCount(name: string, version: string, signal?: AbortSignal): Promise<number> {
  try {
    const res = await resilientFetch(
      `${API_BASE}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/dependencies`,
      { headers: headers(), signal },
    );
    if (!res.ok) return 0;
    const data = (await res.json()) as DepsResponse;
    return (data.dependencies ?? []).filter((d) => d.kind === 'normal').length;
  } catch {
    return 0;
  }
}

export async function fetchCratesPackage(name: string, signal?: AbortSignal): Promise<PackageInfo> {
  const res = await resilientFetch(`${API_BASE}/${encodeURIComponent(name)}`, { headers: headers(), signal });

  if (res.status === 404) {
    throw new Error(`crates.io package not found: ${name}`);
  }
  if (!res.ok) {
    throw new Error(`crates.io registry error for ${name}: HTTP ${res.status}`);
  }

  const data = (await res.json()) as CrateResponse;
  const latestVersion = data.versions?.[0]?.num ?? data.crate.newest_version;

  const [maintainers, dependencies] = await Promise.all([
    fetchOwners(name, signal),
    fetchDepCount(name, latestVersion, signal),
  ]);

  const lastPublishStr = data.crate.updated_at;
  const lastPublish = lastPublishStr ? new Date(lastPublishStr) : null;

  return {
    name: data.crate.name,
    version: latestVersion,
    ecosystem: 'cargo',
    maintainers,
    lastPublish,
    dependencies,
    weeklyDownloads: data.crate.recent_downloads ?? null,
    installScripts: [],
    repoUrl: data.crate.repository ?? null,
    description: data.crate.description ?? null,
    ownershipTransfer: false,
  };
}

export const cratesAdapter: EcosystemAdapter = {
  ecosystem: 'cargo',
  fetch: fetchCratesPackage,
};
