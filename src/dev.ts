import { serve } from '@hono/node-server';
import app from './app.js';

const port = Number(process.env.PORT) || 3000;
console.log(`deps.sh dev server running at http://localhost:${port}`);
serve({ fetch: app.fetch, port });
