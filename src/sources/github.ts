import type { GitHubInfo } from '../types.js';

const GITHUB_API = 'https://api.github.com';

/**
 * Extract owner/repo from various GitHub URL formats:
 *   https://github.com/owner/repo
 *   github.com/owner/repo
 *   github:owner/repo
 * Returns null if the URL doesn't match any known format.
 */
export function parseGitHubRepo(repoUrl: string): { owner: string; repo: string } | null {
  // github:owner/repo shorthand
  const shorthand = repoUrl.match(/^github:([^/]+)\/([^/#?]+)/);
  if (shorthand) {
    return { owner: shorthand[1], repo: shorthand[2].replace(/\.git$/, '') };
  }

  // https://github.com/owner/repo or github.com/owner/repo
  const urlPattern = repoUrl.match(/(?:https?:\/\/)?github\.com\/([^/]+)\/([^/#?]+)/);
  if (urlPattern) {
    return { owner: urlPattern[1], repo: urlPattern[2].replace(/\.git$/, '') };
  }

  return null;
}

function buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'deps-sh-risk-scanner',
  };

  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  return headers;
}

/**
 * Parse the last page number from a GitHub Link header.
 * Format: <url>; rel="next", <url?page=N>; rel="last"
 */
function parseLastPageFromLink(linkHeader: string | null): number | null {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="last"/);
  return match ? parseInt(match[1], 10) : null;
}

const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;

export async function fetchGitHubInfo(repoUrl: string, signal?: AbortSignal): Promise<GitHubInfo | null> {
  const parsed = parseGitHubRepo(repoUrl);
  if (!parsed) return null;

  const { owner, repo } = parsed;
  if (!SAFE_NAME.test(owner) || !SAFE_NAME.test(repo)) return null;

  const headers = buildHeaders();

  try {
    // Fetch repo metadata and contributor count in parallel
    const [repoRes, contribRes] = await Promise.all([
      fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers, signal }),
      fetch(`${GITHUB_API}/repos/${owner}/${repo}/contributors?per_page=1&anon=true`, { headers, signal }),
    ]);

    // Any non-OK response (403 rate limit, 404 not found, etc.) -> graceful null
    if (!repoRes.ok) return null;

    const data = await repoRes.json();

    // Contributor count: use Link header pagination total, fall back to array length
    let contributors = 0;
    if (contribRes.ok) {
      const linkTotal = parseLastPageFromLink(contribRes.headers.get('Link'));
      if (linkTotal !== null) {
        contributors = linkTotal;
      } else {
        // No Link header means all contributors fit on one page
        const contribData = await contribRes.json();
        contributors = Array.isArray(contribData) ? contribData.length : 0;
      }
    }

    return {
      stars: data.stargazers_count ?? 0,
      openIssues: data.open_issues_count ?? 0,
      lastCommit: data.pushed_at ? new Date(data.pushed_at) : null,
      contributors,
      archived: data.archived ?? false,
    };
  } catch {
    // Network errors, JSON parse failures, anything unexpected -> null
    return null;
  }
}
