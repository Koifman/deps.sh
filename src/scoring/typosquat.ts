// Top packages per ecosystem (curated subset for typosquat detection)
const TOP_NPM = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'moment', 'debug', 'commander',
  'request', 'async', 'bluebird', 'underscore', 'webpack', 'babel', 'typescript',
  'eslint', 'prettier', 'jest', 'mocha', 'gulp', 'grunt', 'jquery', 'vue', 'angular',
  'next', 'nuxt', 'svelte', 'inquirer', 'yargs', 'glob', 'minimist', 'dotenv',
  'uuid', 'semver', 'colors', 'cheerio', 'puppeteer', 'socket.io', 'mongoose',
  'sequelize', 'knex', 'passport', 'jsonwebtoken', 'bcrypt', 'cors', 'helmet',
  'morgan', 'nodemon', 'pm2', 'redis', 'pg', 'mysql', 'mongodb', 'aws-sdk',
  'firebase', 'graphql', 'apollo', 'prisma', 'zod', 'rxjs', 'ramda', 'immutable',
  'classnames', 'styled-components', 'tailwindcss', 'postcss', 'sass', 'less',
  'esbuild', 'rollup', 'vite', 'turbo', 'nx', 'lerna', 'pnpm', 'yarn',
  'body-parser', 'cookie-parser', 'multer', 'formidable', 'busboy', 'sharp',
  'jimp', 'canvas', 'pdf-lib', 'exceljs', 'csv-parser', 'xml2js', 'cheerio',
  'marked', 'highlight.js', 'prismjs', 'three', 'd3', 'chart.js', 'echarts',
  'dayjs', 'date-fns', 'luxon', 'nanoid', 'cuid', 'fast-json-stringify',
  'pino', 'winston', 'bunyan', 'log4js', 'ora', 'listr', 'ink', 'blessed',
];

const TOP_PYPI = [
  'requests', 'numpy', 'pandas', 'flask', 'django', 'scipy', 'matplotlib',
  'pillow', 'beautifulsoup4', 'scrapy', 'selenium', 'pytest', 'setuptools',
  'pip', 'wheel', 'boto3', 'botocore', 'urllib3', 'certifi', 'charset-normalizer',
  'idna', 'six', 'pyyaml', 'cryptography', 'cffi', 'pycparser', 'jinja2',
  'markupsafe', 'click', 'packaging', 'attrs', 'pluggy', 'pyparsing',
  'python-dateutil', 'pytz', 'sqlalchemy', 'psycopg2', 'redis', 'celery',
  'gunicorn', 'uvicorn', 'fastapi', 'starlette', 'httpx', 'aiohttp',
  'tornado', 'twisted', 'paramiko', 'fabric', 'ansible', 'docker',
  'tensorflow', 'torch', 'keras', 'scikit-learn', 'xgboost', 'lightgbm',
  'transformers', 'tokenizers', 'openai', 'anthropic', 'langchain',
  'pydantic', 'mypy', 'black', 'ruff', 'isort', 'flake8', 'pylint',
  'tox', 'nox', 'poetry', 'pipenv', 'virtualenv', 'toml', 'tomli',
  'rich', 'typer', 'textual', 'httpie', 'pygments', 'sphinx',
];

const TOP_CARGO = [
  'serde', 'tokio', 'rand', 'clap', 'reqwest', 'hyper', 'actix-web',
  'axum', 'warp', 'rocket', 'diesel', 'sqlx', 'sea-orm', 'rusqlite',
  'serde_json', 'serde_yaml', 'toml', 'config', 'dotenv', 'env_logger',
  'log', 'tracing', 'anyhow', 'thiserror', 'eyre', 'color-eyre',
  'regex', 'lazy_static', 'once_cell', 'parking_lot', 'crossbeam',
  'rayon', 'futures', 'async-trait', 'pin-project', 'bytes', 'http',
  'tower', 'tonic', 'prost', 'rustls', 'openssl', 'ring', 'sha2',
  'aes', 'chacha20poly1305', 'argon2', 'bcrypt', 'uuid', 'chrono',
  'time', 'url', 'percent-encoding', 'base64', 'hex', 'itertools',
  'num', 'bitflags', 'strum', 'derive_more', 'syn', 'quote', 'proc-macro2',
  'bindgen', 'cc', 'cmake', 'pkg-config', 'libc', 'nix', 'winapi',
  'windows', 'image', 'wgpu', 'bevy', 'ggez', 'egui', 'iced',
  'tauri', 'dioxus', 'leptos', 'yew', 'seed', 'cargo', 'rustfmt',
  'clippy', 'miri', 'criterion', 'proptest', 'quickcheck',
];

const LISTS: Record<string, string[]> = {
  npm: TOP_NPM,
  pypi: TOP_PYPI,
  cargo: TOP_CARGO,
};

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

export function detectTyposquats(name: string, ecosystem: string): string[] {
  const list = LISTS[ecosystem] ?? LISTS['npm'];
  const matches: string[] = [];

  for (const pkg of list) {
    if (pkg === name) continue;
    const dist = levenshtein(name.toLowerCase(), pkg.toLowerCase());
    if (dist >= 1 && dist <= 2) {
      matches.push(pkg);
    }
  }

  return matches;
}
