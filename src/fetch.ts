/**
 * Resilient fetch wrapper with per-request timeout.
 * Uses AbortController + setTimeout so the timeout covers BOTH the connection
 * AND body reading (res.json()). AbortSignal.timeout only aborts the connection
 * phase — once headers arrive, body streaming can hang indefinitely.
 *
 * The timer is intentionally NOT cleared after fetch() resolves, so it can
 * still abort slow body reads. It's harmless once the body is fully consumed.
 */

const DEFAULT_TIMEOUT = 15_000;

export async function resilientFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT);

  // Forward parent signal abort to our controller
  if (init?.signal) {
    if (init.signal.aborted) {
      clearTimeout(timer);
      controller.abort();
    } else {
      init.signal.addEventListener(
        'abort',
        () => { clearTimeout(timer); controller.abort(); },
        { once: true },
      );
    }
  }

  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}
