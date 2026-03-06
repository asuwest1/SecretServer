import crypto from 'node:crypto';
import { sendError } from '../lib/http.js';

const buckets = new Map();

function hasScope(scopes, requiredScope) {
  const set = new Set((scopes || []).map((s) => String(s).toLowerCase()));
  if (set.has('admin')) return true;
  if (!requiredScope) return true;
  const need = requiredScope.toLowerCase();
  if (need === 'read') return set.has('read') || set.has('write');
  if (need === 'write') return set.has('write');
  return set.has(need);
}

export function allowRateLimit(key, limitPerMinute) {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const bucketKey = `${key}:${minute}`;
  const count = (buckets.get(bucketKey) || 0) + 1;
  buckets.set(bucketKey, count);
  return count <= limitPerMinute;
}

export function getBearerToken(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return null;
  }
  return auth.substring(7);
}

export function getApiToken(req) {
  return req.headers['x-api-token'] || null;
}

function authorizeWithScopes(res, ctx, scopes, requiredScope) {
  if (!hasScope(scopes, requiredScope)) {
    sendError(res, 403, 'PERMISSION_DENIED', `Required scope '${requiredScope}' is missing.`, ctx.traceId);
    return false;
  }
  return true;
}

function findApiTokenUser(req, ctx, rawToken) {
  const tokenHash = hashToken(rawToken);
  const token = ctx.store.findApiTokenByHash(tokenHash);
  if (!token) {
    return null;
  }

  if (token.expiresAt && new Date(token.expiresAt).getTime() < Date.now()) {
    return null;
  }

  const user = ctx.store.users.find((u) => u.id === token.userId && u.isActive);
  if (!user) {
    return null;
  }

  ctx.store.touchApiToken(token.id);
  ctx.store.appendAudit({
    userId: user.id,
    username: user.username,
    action: 'API_TOKEN_USED',
    resource: 'token',
    resourceId: token.id,
    ipAddress: req.socket.remoteAddress,
    detail: { scopes: token.scopes || [] },
  });

  return { user, scopes: token.scopes || ['read'] };
}

export function requireAuth(req, res, ctx, requiredScope = 'read') {
  const bearer = getBearerToken(req);
  if (bearer) {
    try {
      const claims = ctx.tokenService.verify(bearer);
      if (claims.type !== 'access' || ctx.store.isRevokedJti(claims.jti)) {
        sendError(res, 401, 'UNAUTHENTICATED', 'Missing or expired token.', ctx.traceId);
        return null;
      }
      const user = ctx.store.users.find((u) => u.id === claims.sub && u.isActive);
      if (!user) {
        sendError(res, 401, 'UNAUTHENTICATED', 'Missing or expired token.', ctx.traceId);
        return null;
      }

      const scopes = user.isSuperAdmin ? ['admin'] : ['read', 'write'];
      if (!authorizeWithScopes(res, ctx, scopes, requiredScope)) {
        return null;
      }
      return user;
    } catch {
      sendError(res, 401, 'UNAUTHENTICATED', 'Missing or expired token.', ctx.traceId);
      return null;
    }
  }

  const apiToken = getApiToken(req);
  if (apiToken) {
    const auth = findApiTokenUser(req, ctx, apiToken);
    if (auth) {
      if (!authorizeWithScopes(res, ctx, auth.scopes, requiredScope)) {
        return null;
      }
      return auth.user;
    }
  }

  sendError(res, 401, 'UNAUTHENTICATED', 'Missing or expired token.', ctx.traceId);
  return null;
}

export function requireSuperAdmin(res, ctx, user) {
  if (!user?.isSuperAdmin) {
    sendError(res, 403, 'PERMISSION_DENIED', 'Super Admin permission is required.', ctx.traceId);
    return false;
  }
  return true;
}

export function hashToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

export function hashApiToken(rawToken) {
  return hashToken(rawToken);
}
