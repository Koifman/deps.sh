import type { PackageInfo, MaintainerInfo, EcosystemAdapter } from '../types';
import { resilientFetch } from '../fetch.js';

const PYPI_URL = 'https://pypi.org/pypi';
const PYPISTATS_URL = 'https://pypistats.org/api/packages';

interface PypiResponse {
  info: {
    name: string;
    version: string;
    summary?: string;
    description?: string;
    author?: string;
    author_email?: string;
    maintainer?: string;
    maintainer_email?: string;
    requires_dist?: string[] | null;
    project_urls?: Record<string, string> | null;
  };
  releases: Record<string, PypiReleaseFile[]>;
}

interface PypiReleaseFile {
  upload_time_iso_8601: string;
}

interface PypiStatsResponse {
  data: {
    last_week: number;
  };
}

function parseMaintainers(info: PypiResponse['info']): MaintainerInfo[] {
  const maintainers: MaintainerInfo[] = [];
  const seen = new Set<string>();

  // Parse author
  if (info.author) {
    const key = info.author.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      maintainers.push({
        name: info.author,
        ...(info.author_email ? { email: info.author_email } : {}),
      });
    }
  }

  // Parse maintainer (separate field from author)
  if (info.maintainer) {
    const key = info.maintainer.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      maintainers.push({
        name: info.maintainer,
        ...(info.maintainer_email ? { email: info.maintainer_email } : {}),
      });
    }
  }

  // If no author but maintainer_email exists, try to extract from email
  if (maintainers.length === 0 && info.maintainer_email) {
    const emailName = info.maintainer_email.split('@')[0] ?? info.maintainer_email;
    maintainers.push({
      name: emailName,
      email: info.maintainer_email,
    });
  }

  if (maintainers.length === 0 && info.author_email) {
    const emailName = info.author_email.split('@')[0] ?? info.author_email;
    maintainers.push({
      name: emailName,
      email: info.author_email,
    });
  }

  return maintainers;
}

function extractRepoUrl(projectUrls: Record<string, string> | null | undefined): string | null {
  if (!projectUrls) return null;

  // Priority order for finding the repo URL
  const keys = ['Source', 'Source Code', 'Repository', 'GitHub', 'Homepage', 'Code'];
  const lowerMap = new Map<string, string>();
  for (const [k, v] of Object.entries(projectUrls)) {
    lowerMap.set(k.toLowerCase(), v);
  }

  for (const key of keys) {
    const url = lowerMap.get(key.toLowerCase());
    if (url && (url.includes('github.com') || url.includes('gitlab.com') || url.includes('bitbucket.org'))) {
      return url;
    }
  }

  // Fallback: any URL containing a known code host
  for (const url of Object.values(projectUrls)) {
    if (url.includes('github.com') || url.includes('gitlab.com') || url.includes('bitbucket.org')) {
      return url;
    }
  }

  return null;
}

function getLatestReleaseDate(releases: Record<string, PypiReleaseFile[]>, version: string): Date | null {
  const files = releases[version];
  if (!files || files.length === 0) return null;

  // Get the earliest upload time for the latest version's files
  const times = files
    .map((f) => f.upload_time_iso_8601)
    .filter(Boolean)
    .map((t) => new Date(t).getTime())
    .filter((t) => !isNaN(t));

  if (times.length === 0) return null;
  return new Date(Math.min(...times));
}

async function fetchDownloads(name: string, signal?: AbortSignal): Promise<number | null> {
  try {
    const res = await resilientFetch(`${PYPISTATS_URL}/${encodeURIComponent(name)}/recent?period=week`, { signal });
    if (!res.ok) return null;
    const data = (await res.json()) as PypiStatsResponse;
    return data.data?.last_week ?? null;
  } catch {
    return null;
  }
}

export async function fetchPypiPackage(name: string, signal?: AbortSignal): Promise<PackageInfo> {
  const res = await resilientFetch(`${PYPI_URL}/${encodeURIComponent(name)}/json`, { signal });

  if (res.status === 404) {
    throw new Error(`PyPI package not found: ${name}`);
  }
  if (!res.ok) {
    throw new Error(`PyPI registry error for ${name}: HTTP ${res.status}`);
  }

  const data = (await res.json()) as PypiResponse;
  const { info, releases } = data;

  const maintainers = parseMaintainers(info);
  const lastPublish = getLatestReleaseDate(releases, info.version);
  const dependencies = info.requires_dist?.length ?? 0;
  const weeklyDownloads = await fetchDownloads(name, signal);

  return {
    name: info.name,
    version: info.version,
    ecosystem: 'pypi',
    maintainers,
    lastPublish,
    dependencies,
    weeklyDownloads,
    installScripts: [],
    repoUrl: extractRepoUrl(info.project_urls),
    description: info.summary || info.description?.slice(0, 200) || null,
    ownershipTransfer: false,
  };
}

export const pypiAdapter: EcosystemAdapter = {
  ecosystem: 'pypi',
  fetch: fetchPypiPackage,
};
