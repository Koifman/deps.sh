/**
 * Resilient fetch wrapper.
 * Bun's native fetch on Windows fails for certain TLS hosts (e.g. crates.io).
 * On "Unable to connect" errors, falls back to shelling out to curl.
 */

import { spawnSync } from 'node:child_process';

export async function resilientFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  try {
    const res = await fetch(url, init);
    return res;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes('Unable to connect')) throw err;

    // Fallback: curl subprocess
    const args = ['-s', '-S', '--fail-with-body', '-L', '--max-time', '15'];

    // Forward headers
    const headers = init?.headers;
    if (headers) {
      if (headers instanceof Headers) {
        headers.forEach((v, k) => args.push('-H', `${k}: ${v}`));
      } else if (Array.isArray(headers)) {
        for (const [k, v] of headers) args.push('-H', `${k}: ${v}`);
      } else {
        for (const [k, v] of Object.entries(headers)) args.push('-H', `${k}: ${v}`);
      }
    }

    args.push(url);
    const result = spawnSync('curl', args, { encoding: 'utf-8', timeout: 20_000 });

    if (result.error) {
      throw new Error(`curl fallback failed: ${result.error.message}`);
    }
    if (result.status !== null && result.status !== 0) {
      // curl exit code 22 = HTTP error (--fail-with-body)
      const body = result.stdout || result.stderr || '';
      const statusMatch = result.stderr?.match(/The requested URL returned error: (\d+)/);
      const status = statusMatch ? parseInt(statusMatch[1], 10) : 502;
      return new Response(body, { status, statusText: 'curl fallback' });
    }

    return new Response(result.stdout, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
}
