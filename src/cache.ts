interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const DEFAULT_TTL = 60 * 60 * 1000; // 1 hour
const MAX_ENTRIES = 10_000;
const SWEEP_INTERVAL = 5 * 60 * 1000; // 5 minutes

const store = new Map<string, CacheEntry<unknown>>();

export function cacheGet<T>(key: string): T | null {
  const entry = store.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    store.delete(key);
    return null;
  }
  return entry.value as T;
}

export function cacheSet<T>(key: string, value: T, ttl = DEFAULT_TTL): void {
  // Evict oldest entries if at capacity
  if (store.size >= MAX_ENTRIES && !store.has(key)) {
    const firstKey = store.keys().next().value;
    if (firstKey !== undefined) store.delete(firstKey);
  }
  store.set(key, { value, expiresAt: Date.now() + ttl });
}

export function cacheKey(ecosystem: string, name: string): string {
  return `${ecosystem}:${name}`;
}

// Periodic sweep of expired entries
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (now > entry.expiresAt) store.delete(key);
  }
}, SWEEP_INTERVAL).unref();
