# deps.sh

Supply chain risk scoring as a service.

```bash
curl -L deps.sh/npm/lodash
```

```
  lodash@4.17.21                        RISK: LOW [##........] 17/100

  Maintainers       3 active
  Last publish       2021-02-20 (4+ years ago)
  Vulnerabilities    4 known (0 critical)
  Install scripts    none
  Dependencies       0 direct
  Weekly downloads   45M
  GitHub stars       59.8K

  ──────────────────────────────────────────────────
  deps.sh — supply chain risk scoring
```

## Usage

```bash
# Score a package
curl -L deps.sh/npm/lodash
curl -L deps.sh/pip/requests
curl -L deps.sh/cargo/serde
curl -L deps.sh/lodash              # defaults to npm

# Lockfile scanning
curl -L -X POST deps.sh/scan -d @package-lock.json
curl -L -X POST deps.sh/scan -d @requirements.txt
curl -L -X POST deps.sh/scan -d @Cargo.lock

# Feeds
curl -L deps.sh/recent              # high-risk packages
curl -L deps.sh/feed                # security advisories
curl -L deps.sh/incidents           # supply chain incidents
curl -L deps.sh/transfers           # ownership transfers

# JSON output
curl -L deps.sh/npm/lodash?json
curl -L -X POST deps.sh/scan?json -d @package-lock.json
```

## How scoring works

Each package is scored 0-100 across six risk signals:

| Signal | Weight | What it measures |
|-|-|-|
| Vulnerabilities | 30 | Known CVEs via [OSV.dev](https://osv.dev) |
| Maintainer risk | 20 | Single maintainer, ownership transfers |
| Freshness | 15 | Time since last publish |
| Install scripts | 15 | Presence of preinstall/postinstall hooks (npm) |
| Dependencies | 10 | Direct dependency count |
| Typosquat risk | 10 | Name similarity to popular packages |

Risk levels:

| Level | Score |
|-|-|
| LOW | 0 - 20 |
| MODERATE | 21 - 45 |
| HIGH | 46 - 70 |
| CRITICAL | 71 - 100 |

## Supported ecosystems

- **npm** — registry.npmjs.org
- **PyPI** — pypi.org
- **crates.io** — crates.io

## Self-hosting

```bash
git clone https://github.com/koifman/deps.sh.git
cd deps.sh
bun install
bun run dev
# → http://localhost:3000
```

Optionally set a GitHub token for higher API rate limits:

```bash
export GITHUB_TOKEN=ghp_...
```

### Deploy to Vercel

The repo includes a Vercel adapter out of the box:

```bash
vercel
```

Or connect the GitHub repo from the [Vercel dashboard](https://vercel.com/new).

## API

All endpoints return terminal-formatted text by default. Append `?json` or send `Accept: application/json` for JSON output.

| Method | Path | Description |
|-|-|-|
| GET | `/:ecosystem/:package` | Score a package |
| GET | `/:package` | Score an npm package |
| GET | `/recent` | Recently scanned high-risk packages |
| GET | `/feed` | Security advisory feed |
| GET | `/incidents` | Supply chain incident feed |
| GET | `/transfers` | Ownership transfer detections |
| POST | `/scan` | Scan a lockfile (body = file contents) |

### POST /scan

Accepts `package-lock.json` (v1/v2/v3), `package.json`, `requirements.txt`, or `Cargo.lock`. Auto-detects format from content.

```bash
cat package-lock.json | curl -sL -X POST deps.sh/scan --data-binary @-
```

Limits: 5MB max body, 100 packages scored per request, 10 requests/min rate limit.

## Project structure

```
src/
  app.ts              Hono routes and middleware
  dev.ts              Local dev server
  cache.ts            In-memory cache (1hr TTL)
  fetch.ts            Resilient fetch with TLS fallback
  types.ts            TypeScript interfaces
  ecosystems/
    npm.ts            npm registry adapter
    pypi.ts           PyPI registry adapter
    crates.ts         crates.io registry adapter
  sources/
    osv.ts            OSV vulnerability database
    github.ts         GitHub repo metadata
  scoring/
    risk.ts           Risk scoring engine
    typosquat.ts      Typosquat detection
  parsers/
    lockfile.ts       Lockfile format detection and parsing
  formatters/
    terminal.ts       Terminal/ANSI output
    json.ts           JSON output
  scanner.ts          Background scanner for feeds and high-risk packages
api/
  [[...route]].ts     Vercel serverless adapter
```

## License

APGL
