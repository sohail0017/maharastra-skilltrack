import { app, startServer } from '../server/index';

let initialized: Promise<void> | null = null;

function normalizeApiUrl(req: { url?: string; originalUrl?: string }): void {
  const current = req.originalUrl || req.url || '/';
  const qIndex = current.indexOf('?');
  const pathname = qIndex === -1 ? current : current.slice(0, qIndex);
  const search = qIndex === -1 ? '' : current.slice(qIndex);

  if (pathname === '/api' || pathname.startsWith('/api/')) {
    req.url = current;
    return;
  }

  const prefixed = pathname === '/' ? '/api' : `/api${pathname.startsWith('/') ? pathname : `/${pathname}`}`;
  req.url = prefixed + search;
}

export default async function handler(req: any, res: any) {
  if (!initialized) {
    initialized = startServer();
  }

  await initialized;
  normalizeApiUrl(req);

  return app(req, res);
}
