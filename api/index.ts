import { app, startServer } from '../server/index';

let initialized: Promise<void> | null = null;

export default async function handler(req: any, res: any) {
  if (!initialized) {
    initialized = startServer();
  }

  await initialized;

  return app(req, res);
}