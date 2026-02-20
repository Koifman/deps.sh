/**
 * Resilient fetch wrapper with per-request timeout.
 * Combines a 10-second per-request timeout with any parent AbortSignal.
 * Replaces the previous spawnSync('curl') fallback which doesn't work on Vercel.
 */

const DEFAULT_TIMEOUT = 10_000;

export async function resilientFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const signals: AbortSignal[] = [AbortSignal.timeout(DEFAULT_TIMEOUT)];
  if (init?.signal) signals.push(init.signal);

  const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);

  return fetch(url, { ...init, signal });
}
