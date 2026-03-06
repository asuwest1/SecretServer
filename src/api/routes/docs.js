import fs from 'node:fs';
import path from 'node:path';
import { text, sendError } from '../lib/http.js';
import { requireAuth, requireSuperAdmin } from '../services/security.js';

function normalizeIp(value) {
  const ip = String(value || '').trim();
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) {
    return ip.slice(7);
  }
  return ip;
}

function isInternalIp(ipAddress) {
  const ip = normalizeIp(ipAddress);
  if (!ip) return false;

  return (
    ip === '::1' ||
    ip === '127.0.0.1' ||
    ip.startsWith('127.') ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80:')
  );
}

function getClientIp(req, trustProxy) {
  if (!trustProxy) {
    return normalizeIp(req.socket.remoteAddress || '');
  }

  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const first = forwarded.split(',')[0].trim();
    return normalizeIp(first);
  }

  return normalizeIp(req.socket.remoteAddress || '');
}

export function registerDocsRoutes(router) {
  router.register('GET', /^\/api\/docs$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const clientIp = getClientIp(req, ctx.config.openApi.trustProxy);
    if (ctx.config.openApi.internalOnly && !isInternalIp(clientIp)) {
      sendError(res, 403, 'PERMISSION_DENIED', 'OpenAPI docs are restricted to internal networks.', ctx.traceId);
      return;
    }

    const source = path.join(process.cwd(), 'docs', 'openapi.yaml');
    const content = fs.readFileSync(source, 'utf8');
    text(res, 200, content, 'application/yaml; charset=utf-8');
  });
}

