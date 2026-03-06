import crypto from 'node:crypto';
import { json, readJson, sendError } from '../lib/http.js';
import { hashPassword } from '../lib/password.js';
import { buildOtpAuthUri, generateTotpSecret, verifyTotp } from '../lib/totp.js';
import { requireAuth, requireSuperAdmin, hashApiToken } from '../services/security.js';

function canManageUser(actor, targetUserId) {
  return actor.isSuperAdmin || actor.id === targetUserId;
}

function normalizeScopes(input) {
  if (!Array.isArray(input) || input.length === 0) {
    return ['read'];
  }
  const allowed = new Set(['read', 'write', 'admin']);
  const deduped = [...new Set(input.map((x) => String(x).toLowerCase()))].filter((x) => allowed.has(x));
  return deduped.length > 0 ? deduped : ['read'];
}

export function registerUserRoutes(router) {
  router.register('GET', /^\/api\/v1\/users$/, async (req, res, ctx) => {
    const user = requireAuth(req, res, ctx, 'admin');
    if (!user || !requireSuperAdmin(res, ctx, user)) return;
    json(res, 200, { data: ctx.store.users.map((u) => ({ ...u, passwordHash: undefined, mfaSecretEnc: undefined, mfaPendingSecretEnc: undefined })) });
  });

  router.register('POST', /^\/api\/v1\/users$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const body = await readJson(req);
    if (!body.username || !body.password || !body.displayName || !body.email) {
      sendError(res, 400, 'VALIDATION_ERROR', 'username, password, displayName, email are required.', ctx.traceId);
      return;
    }

    if (ctx.store.users.some((u) => u.username === body.username)) {
      sendError(res, 409, 'CONFLICT', 'Username already exists.', ctx.traceId);
      return;
    }

    const newUser = {
      id: crypto.randomUUID(),
      username: body.username,
      displayName: body.displayName,
      email: body.email,
      passwordHash: await hashPassword(body.password),
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaPendingSecretEnc: null,
      isActive: true,
      isSuperAdmin: !!body.isSuperAdmin,
      failedAttempts: 0,
      lockedUntil: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: null,
    };

    ctx.store.users.push(newUser);
    ctx.store.appendAudit({
      userId: actor.id,
      username: actor.username,
      action: 'USER_CREATED',
      resource: 'user',
      resourceId: newUser.id,
    });

    json(res, 201, { data: { id: newUser.id } });
  });

  router.register('DELETE', /^\/api\/v1\/users\/(?<id>[0-9a-f-]+)$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'admin');
    if (!actor || !requireSuperAdmin(res, ctx, actor)) return;

    const target = ctx.store.users.find((u) => u.id === ctx.params.id);
    if (!target) {
      sendError(res, 404, 'NOT_FOUND', 'User not found.', ctx.traceId);
      return;
    }

    target.isActive = false;
    target.updatedAt = new Date().toISOString();
    ctx.store.appendAudit({
      userId: actor.id,
      username: actor.username,
      action: 'USER_DEACTIVATED',
      resource: 'user',
      resourceId: target.id,
    });

    json(res, 200, { data: { ok: true } });
  });

  router.register('POST', /^\/api\/v1\/users\/(?<id>[0-9a-f-]+)\/api-tokens$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    if (actor.id !== ctx.params.id && !actor.isSuperAdmin) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Self or Super Admin only.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenRecord = {
      id: crypto.randomUUID(),
      userId: ctx.params.id,
      name: body.name || 'default',
      scopes: normalizeScopes(body.scopes),
      tokenHash: hashApiToken(rawToken),
      createdAt: new Date().toISOString(),
      expiresAt: body.expiresAt || null,
      lastUsed: null,
    };
    ctx.store.apiTokens.push(tokenRecord);

    ctx.store.appendAudit({
      userId: actor.id,
      username: actor.username,
      action: 'API_TOKEN_CREATED',
      resource: 'token',
      resourceId: tokenRecord.id,
      detail: { scopes: tokenRecord.scopes },
    });

    json(res, 201, { data: { tokenId: tokenRecord.id, rawToken, scopes: tokenRecord.scopes } });
  });

  router.register('POST', /^\/api\/v1\/users\/(?<id>[0-9a-f-]+)\/mfa\/setup$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    if (!canManageUser(actor, ctx.params.id)) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Self or Super Admin only.', ctx.traceId);
      return;
    }

    const target = ctx.store.users.find((u) => u.id === ctx.params.id && u.isActive);
    if (!target) {
      sendError(res, 404, 'NOT_FOUND', 'User not found.', ctx.traceId);
      return;
    }

    const secret = generateTotpSecret();
    const encrypted = ctx.crypto.encryptSecret(secret);
    target.mfaPendingSecretEnc = {
      valueEnc: encrypted.encryptedValue,
      dekEnc: encrypted.encryptedDek,
    };

    const issuer = ctx.config.issuer || 'SecretServer';
    const otpauthUri = buildOtpAuthUri({ accountName: target.username, issuer, secret });
    json(res, 200, { data: { otpauthUri, secret } });
  });

  router.register('POST', /^\/api\/v1\/users\/(?<id>[0-9a-f-]+)\/mfa\/verify$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    if (!canManageUser(actor, ctx.params.id)) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Self or Super Admin only.', ctx.traceId);
      return;
    }

    const target = ctx.store.users.find((u) => u.id === ctx.params.id && u.isActive);
    if (!target || !target.mfaPendingSecretEnc) {
      sendError(res, 404, 'NOT_FOUND', 'Pending MFA setup not found.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    const code = String(body.code || '');
    const secret = ctx.crypto.decryptSecret({
      valueEnc: target.mfaPendingSecretEnc.valueEnc,
      dekEnc: target.mfaPendingSecretEnc.dekEnc,
    });

    if (!verifyTotp({ secret, code })) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid MFA code.', ctx.traceId);
      return;
    }

    target.mfaSecretEnc = target.mfaPendingSecretEnc;
    target.mfaPendingSecretEnc = null;
    target.mfaEnabled = true;
    target.updatedAt = new Date().toISOString();

    ctx.store.appendAudit({
      userId: actor.id,
      username: actor.username,
      action: 'MFA_ENABLED',
      resource: 'user',
      resourceId: target.id,
    });

    json(res, 200, { data: { ok: true } });
  });
}
