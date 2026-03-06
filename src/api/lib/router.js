import crypto from 'node:crypto';

export class Router {
  constructor() {
    this.routes = [];
  }

  register(method, pathRegex, handler, options = {}) {
    this.routes.push({ method, pathRegex, handler, options });
  }

  async handle(req, res, ctx) {
    const method = req.method || 'GET';
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    for (const route of this.routes) {
      if (route.method !== method) {
        continue;
      }
      const match = route.pathRegex.exec(url.pathname);
      if (!match) {
        continue;
      }
      const traceId = crypto.randomUUID();
      const params = match.groups || {};
      await route.handler(req, res, {
        ...ctx,
        traceId,
        params,
        query: Object.fromEntries(url.searchParams.entries()),
        path: url.pathname,
        options: route.options,
      });
      return true;
    }

    return false;
  }
}
