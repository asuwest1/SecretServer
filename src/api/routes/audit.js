import { json, sendError } from '../lib/http.js';
import { requireAuth, requireSuperAdmin } from '../services/security.js';

function toCsv(records) {
  if (records.length === 0) {
    return 'id,eventTime,action,username,resource,resourceId\n';
  }

  const cols = ['id', 'eventTime', 'action', 'username', 'resource', 'resourceId'];
  const rows = [cols.join(',')];
  for (const rec of records) {
    rows.push(cols.map((c) => JSON.stringify(rec[c] ?? '')).join(','));
  }
  return rows.join('\n');
}

function parseTimestamp(value) {
  if (!value) return null;
  const ts = new Date(value).getTime();
  return Number.isFinite(ts) ? ts : NaN;
}

export function registerAuditRoutes(router) {
  router.register('GET', /^\/api\/v1\/audit$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const fromTs = parseTimestamp(ctx.query.from);
    const toTs = parseTimestamp(ctx.query.to);

    if (Number.isNaN(fromTs) || Number.isNaN(toTs)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'from/to must be valid ISO timestamps.', ctx.traceId);
      return;
    }

    const from = fromTs ?? 0;
    const to = toTs ?? Date.now();
    if (from > to) {
      sendError(res, 400, 'VALIDATION_ERROR', 'from must be <= to.', ctx.traceId);
      return;
    }

    const data = ctx.store.auditLog.filter((a) => {
      const ts = new Date(a.eventTime).getTime();
      return ts >= from && ts <= to;
    });

    json(res, 200, { data });
  });

  router.register('GET', /^\/api\/v1\/audit\/export$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const format = (ctx.query.format || 'json').toLowerCase();
    if (!['json', 'csv'].includes(format)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'format must be json or csv.', ctx.traceId);
      return;
    }

    const data = ctx.store.auditLog;

    if (format === 'csv') {
      res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8' });
      res.end(toCsv(data));
      return;
    }

    json(res, 200, { data });
  });

  router.register('GET', /^\/api\/v1\/audit\/verify$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const result = typeof ctx.store.verifyAuditIntegrity === 'function'
      ? ctx.store.verifyAuditIntegrity()
      : { ok: false, reason: 'AUDIT_VERIFICATION_UNSUPPORTED' };

    json(res, 200, { data: result });
  });
}
