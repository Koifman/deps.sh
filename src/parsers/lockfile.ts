import type { Ecosystem } from '../types.js';

export interface ParsedDep {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

export interface ParseResult {
  format: string;
  ecosystem: Ecosystem;
  deps: ParsedDep[];
}

export function parseLockfile(body: string): ParseResult {
  const trimmed = body.trim();

  // Cargo.lock — contains [[package]]
  if (trimmed.includes('[[package]]')) {
    return parseCargo(trimmed);
  }

  // Try JSON formats
  if (trimmed.startsWith('{')) {
    try {
      const data = JSON.parse(trimmed);

      // package-lock.json v2/v3: has "packages" key
      if (data.packages && typeof data.packages === 'object') {
        return parsePackageLockV2(data);
      }

      // package-lock.json v1: has "dependencies" + "lockfileVersion"
      if (data.dependencies && data.lockfileVersion) {
        return parsePackageLockV1(data);
      }

      // package.json: has "dependencies" but no lockfileVersion
      if (data.dependencies && !data.lockfileVersion) {
        return parsePackageJson(data);
      }
    } catch {
      // Not valid JSON, fall through
    }
  }

  // requirements.txt — lines with package specs
  if (/^[a-zA-Z0-9_-]/.test(trimmed)) {
    return parseRequirementsTxt(trimmed);
  }

  return { format: 'unknown', ecosystem: 'npm', deps: [] };
}

function parsePackageLockV2(data: Record<string, unknown>): ParseResult {
  const deps: ParsedDep[] = [];
  const packages = data.packages as Record<string, { version?: string }>;

  for (const [key, val] of Object.entries(packages)) {
    if (key === '') continue; // skip root
    const name = key.replace(/^node_modules\//, '');
    if (val.version) {
      deps.push({ name, version: val.version, ecosystem: 'npm' });
    }
  }

  const version = (data as { lockfileVersion?: number }).lockfileVersion;
  return { format: `package-lock.json v${version ?? 2}`, ecosystem: 'npm', deps };
}

function parsePackageLockV1(data: Record<string, unknown>): ParseResult {
  const deps: ParsedDep[] = [];
  const dependencies = data.dependencies as Record<string, { version?: string }>;

  for (const [name, val] of Object.entries(dependencies)) {
    if (val.version) {
      deps.push({ name, version: val.version, ecosystem: 'npm' });
    }
  }

  return { format: 'package-lock.json v1', ecosystem: 'npm', deps };
}

function parsePackageJson(data: Record<string, unknown>): ParseResult {
  const deps: ParsedDep[] = [];
  const allDeps = {
    ...(data.dependencies as Record<string, string> | undefined),
    ...(data.devDependencies as Record<string, string> | undefined),
  };

  for (const name of Object.keys(allDeps)) {
    deps.push({ name, version: 'latest', ecosystem: 'npm' });
  }

  return { format: 'package.json', ecosystem: 'npm', deps };
}

function parseRequirementsTxt(body: string): ParseResult {
  const deps: ParsedDep[] = [];

  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    const name = trimmed.split(/[=<>!~\[;]/)[0].trim();
    if (name) {
      deps.push({ name, version: 'latest', ecosystem: 'pypi' });
    }
  }

  return { format: 'requirements.txt', ecosystem: 'pypi', deps };
}

function parseCargo(body: string): ParseResult {
  const deps: ParsedDep[] = [];
  const blocks = body.split('[[package]]').slice(1);

  for (const block of blocks) {
    const name = block.match(/name\s*=\s*"([^"]+)"/)?.[1];
    const version = block.match(/version\s*=\s*"([^"]+)"/)?.[1];
    if (name) {
      deps.push({ name, version: version ?? 'latest', ecosystem: 'cargo' });
    }
  }

  return { format: 'Cargo.lock', ecosystem: 'cargo', deps };
}
