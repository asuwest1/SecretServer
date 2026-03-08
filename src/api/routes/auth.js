import crypto from 'node:crypto';
import { json, readJson, sendError } from '../lib/http.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { verifyTotp } from '../lib/totp.js';
import { normalizeForLookup, validatePassword } from '../lib/validation.js';
import { allowRateLimit, hashToken, requireAuth, requireSuperAdmin } from '../services/security.js';

function isLocked(user) {
  return user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now();
}

function isLdapFallbackAllowed(config) {
  if (!config.ldap.fallbackLocal) {
    return false;
  }

  if (config.env === 'production' && !config.ldap.allowLocalFallbackInProduction) {
    return false;
  }

  return true;
}

function ensureLocalUserForLdap(store, ldapResult) {
  let user = store.users.find((u) => u.username.toLowerCase() === ldapResult.username.toLowerCase());
  if (user) {
    user.isActive = true;
    user.displayName = ldapResult.displayName || user.displayName;
    user.email = ldapResult.email || user.email;
    user.updatedAt = new Date().toISOString();
    return user;
  }

  user = {
    id: crypto.randomUUID(),
    username: ldapResult.username,
    displayName: ldapResult.displayName || ldapResult.username,
    email: ldapResult.email || '',
    passwordHash: '',
    mfaEnabled: false,
    mfaSecretEnc: null,
    mfaPendingSecretEnc: null,
    isActive: true,
    isSuperAdmin: false,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastLoginAt: null,
  };

  store.users.push(user);
  return user;
}

function normalizeGroup(value) {
  return String(value || '').trim().toLowerCase();
}

function resolveMappedRoleNames(groups, ldapConfig) {
  const normalizedGroups = new Set((groups || []).map((g) => normalizeGroup(g)).filter(Boolean));
  const configuredMap = ldapConfig.roleGroupMap || {};
  const configuredEntries = Object.entries(configuredMap);

  if (configuredEntries.length === 0) {
    return [...normalizedGroups];
  }

  const roleNames = new Set();
  for (const [groupName, mappedRoles] of configuredEntries) {
    if (!normalizedGroups.has(normalizeGroup(groupName))) {
      continue;
    }

    if (Array.isArray(mappedRoles)) {
      for (const roleName of mappedRoles) {
        const normalizedRole = normalizeGroup(roleName);
        if (normalizedRole) {
          roleNames.add(normalizedRole);
        }
      }
      continue;
    }

    const normalizedRole = normalizeGroup(mappedRoles);
    if (normalizedRole) {
      roleNames.add(normalizedRole);
    }
  }

  return [...roleNames];
}

function syncLdapGroupsToRoles(store, userId, groups, ldapConfig, logger) {
  const mappedRoleNames = new Set(resolveMappedRoleNames(groups, ldapConfig));
  const desiredRoleIds = new Set();

  for (const role of store.roles) {
    if (mappedRoleNames.has(normalizeGroup(role.name))) {
      desiredRoleIds.add(role.id);
    }
  }

  const staleLdapRoleIds = new Set(
    store.userRoles
      .filter((ur) => ur.userId === userId && ur.assignedBy === null && !desiredRoleIds.has(ur.roleId))
      .map((ur) => ur.roleId)
  );

  if (staleLdapRoleIds.size > 0) {
    store.userRoles = store.userRoles.filter((ur) => !(ur.userId === userId && staleLdapRoleIds.has(ur.roleId) && ur.assignedBy === null));
  }

  let assigned = 0;
  for (const roleId of desiredRoleIds) {
    if (!store.userRoles.some((x) => x.userId === userId && x.roleId === roleId)) {
      store.userRoles.push({
        userId,
        roleId,
        assignedAt: new Date().toISOString(),
        assignedBy: null,
      });
      assigned += 1;
    }
  }

  logger.debug('ldap_role_sync_completed', {
    userId,
    groupCount: (groups || []).length,
    desiredRoles: desiredRoleIds.size,
    assigned,
    removed: staleLdapRoleIds.size,
  });
}

function issueSessionTokens(ctx, user, parentJti = null) {
  const accessToken = ctx.tokenService.createAccessToken(user);
  const refreshToken = ctx.tokenService.createRefreshToken(user, parentJti);
  const refreshClaims = ctx.tokenService.verify(refreshToken);

  ctx.store.addRefreshSession({
    jti: refreshClaims.jti,
    parentJti: refreshClaims.parentJti || null,
    userId: user.id,
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(refreshClaims.exp * 1000).toISOString(),
    createdAt: new Date().toISOString(),
    revokedAt: null,
    lastUsedAt: null,
  });

  return { accessToken, refreshToken };
}

function verifyUserMfaCode(ctx, user, code) {
  if (!user.mfaEnabled || !user.mfaSecretEnc) {
    return true;
  }
  const secret = ctx.crypto.decryptSecret({ valueEnc: user.mfaSecretEnc.valueEnc, dekEnc: user.mfaSecretEnc.dekEnc });
  return verifyTotp({ secret, code, skew: 1 });
}

export function registerAuthRoutes(router) {
  router.register('POST', /^\/api\/v1\/auth\/login$/, async (req, res, ctx) => {
    if (!allowRateLimit('login:' + req.socket.remoteAddress, 10)) {
      sendError(res, 429, 'RATE_LIMITED', 'Too many requests.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    const { username, password } = body;

    const usernameText = String(username || '').trim();
    const passwordText = String(password || '');
    if (!usernameText || !passwordText) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Username and password are required.', ctx.traceId);
      return;
    }
    if (usernameText.length > 128 || passwordText.length > 512) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Credential input exceeds maximum length.', ctx.traceId);
      return;
    }

    let user = null;

    if (ctx.config.ldap.enabled) {
      const ldapResult = await ctx.ldap.authenticate(usernameText, passwordText);
      if (ldapResult.ok) {
        user = ensureLocalUserForLdap(ctx.store, ldapResult);
        syncLdapGroupsToRoles(ctx.store, user.id, ldapResult.groups, ctx.config.ldap, ctx.logger);
      } else if (!isLdapFallbackAllowed(ctx.config)) {
        ctx.logger.warn('ldap_auth_rejected_no_fallback', { reason: ldapResult.reason });
        sendError(res, 401, 'UNAUTHENTICATED', 'LDAP authentication failed.', ctx.traceId);
        return;
      }
    }

    if (!user) {
      const usernameLookup = normalizeForLookup(usernameText);
      user = ctx.store.users.find((u) => normalizeForLookup(u.username) === usernameLookup && u.isActive);
      if (!user || isLocked(user)) {
        sendError(res, 401, 'UNAUTHENTICATED', 'Invalid credentials.', ctx.traceId);
        return;
      }

      if (!user.passwordHash) {
        sendError(res, 401, 'UNAUTHENTICATED', 'Invalid credentials.', ctx.traceId);
        return;
      }

      const valid = await verifyPassword(passwordText, user.passwordHash);
      if (!valid) {
        user.failedAttempts += 1;
        if (user.failedAttempts >= ctx.config.lockoutThreshold) {
          user.lockedUntil = new Date(Date.now() + ctx.config.lockoutDurationMinutes * 60000).toISOString();
        }
        ctx.store.appendAudit({
          userId: user.id,
          username: user.username,
          action: 'AUTH_LOGIN_FAILURE',
          resource: 'user',
          resourceId: user.id,
          ipAddress: req.socket.remoteAddress,
        });
        sendError(res, 401, 'UNAUTHENTICATED', 'Invalid credentials.', ctx.traceId);
        return;
      }
    }

    user.failedAttempts = 0;
    user.lockedUntil = null;
    user.lastLoginAt = new Date().toISOString();

    if (ctx.config.requireMfa || user.mfaEnabled) {
      const mfaToken = ctx.tokenService.sign({ sub: user.id, type: 'mfa' }, 300);
      json(res, 200, { data: { mfaRequired: true, mfaToken } });
      return;
    }

    const tokens = issueSessionTokens(ctx, user);

    ctx.store.appendAudit({
      userId: user.id,
      username: user.username,
      action: 'AUTH_LOGIN_SUCCESS',
      resource: 'user',
      resourceId: user.id,
      ipAddress: req.socket.remoteAddress,
    });

    json(res, 200, { data: tokens });
  });

  router.register('POST', /^\/api\/v1\/auth\/mfa$/, async (req, res, ctx) => {
    if (!allowRateLimit('mfa:' + req.socket.remoteAddress, 5)) {
      sendError(res, 429, 'RATE_LIMITED', 'Too many requests.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    const { mfaToken, code } = body;
    if (!mfaToken || !code) {
      sendError(res, 400, 'VALIDATION_ERROR', 'mfaToken and code are required.', ctx.traceId);
      return;
    }

    let claims;
    try {
      claims = ctx.tokenService.verify(mfaToken);
    } catch {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid MFA token.', ctx.traceId);
      return;
    }

    if (claims.type !== 'mfa' || ctx.store.isRevokedJti(claims.jti)) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid MFA token.', ctx.traceId);
      return;
    }

    const user = ctx.store.users.find((u) => u.id === claims.sub && u.isActive);
    if (!user) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid MFA token.', ctx.traceId);
      return;
    }

    if (!verifyUserMfaCode(ctx, user, code)) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid MFA code.', ctx.traceId);
      return;
    }

    ctx.store.revokeSession(claims.jti);
    const tokens = issueSessionTokens(ctx, user);
    ctx.store.appendAudit({
      userId: user.id,
      username: user.username,
      action: 'AUTH_MFA_SUCCESS',
      resource: 'user',
      resourceId: user.id,
      ipAddress: req.socket.remoteAddress,
    });

    json(res, 200, { data: tokens });
  });

  router.register('POST', /^\/api\/v1\/auth\/refresh$/, async (req, res, ctx) => {
    if (!allowRateLimit('refresh:' + req.socket.remoteAddress, 10)) {
      sendError(res, 429, 'RATE_LIMITED', 'Too many requests.', ctx.traceId);
      return;
    }
    const body = await readJson(req);
    const { refreshToken } = body;

    if (!refreshToken) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid refresh token.', ctx.traceId);
      return;
    }

    let claims;
    try {
      claims = ctx.tokenService.verify(refreshToken);
    } catch {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid refresh token.', ctx.traceId);
      return;
    }

    if (claims.type !== 'refresh' || ctx.store.isRevokedJti(claims.jti)) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid refresh token.', ctx.traceId);
      return;
    }

    const session = ctx.store.findRefreshSession(claims.jti);
    if (!session || session.tokenHash !== hashToken(refreshToken)) {
      ctx.store.revokeSession(claims.jti);
      sendError(res, 401, 'UNAUTHENTICATED', 'Refresh token replay detected.', ctx.traceId);
      return;
    }

    const user = ctx.store.users.find((u) => u.id === claims.sub && u.isActive);
    if (!user) {
      sendError(res, 401, 'UNAUTHENTICATED', 'Invalid refresh token.', ctx.traceId);
      return;
    }

    session.lastUsedAt = new Date().toISOString();
    ctx.store.revokeSession(claims.jti);
    const tokens = issueSessionTokens(ctx, user, claims.jti);
    json(res, 200, { data: tokens });
  });

  router.register('POST', /^\/api\/v1\/auth\/logout$/, async (req, res, ctx) => {
    const body = await readJson(req);
    if (body.refreshToken) {
      try {
        const claims = ctx.tokenService.verify(body.refreshToken);
        if (claims.type === 'refresh') {
          ctx.store.revokeSession(claims.jti);
        }
      } catch {
        // ignore invalid token on logout
      }
    }
    json(res, 200, { data: { ok: true } });
  });

  router.register('POST', /^\/api\/v1\/auth\/logout-all$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'write');
    if (!actor) return;

    const body = await readJson(req);
    const targetUserId = body.userId || actor.id;
    if (targetUserId !== actor.id && !requireSuperAdmin(res, ctx, actor)) return;

    ctx.store.revokeUserSessions(targetUserId);
    json(res, 200, { data: { ok: true } });
  });

  router.register('POST', /^\/api\/v1\/auth\/bootstrap-super-admin$/, async (req, res, ctx) => {
    if (ctx.store.users.length > 0) {
      sendError(res, 409, 'CONFLICT', 'Super Admin already exists.', ctx.traceId);
      return;
    }

    const body = await readJson(req);
    if (!body.username || !body.password) {
      sendError(res, 400, 'VALIDATION_ERROR', 'username and password are required.', ctx.traceId);
      return;
    }

    const passwordCheck = validatePassword(body.password);
    if (!passwordCheck.ok) {
      sendError(res, 400, 'VALIDATION_ERROR', passwordCheck.error, ctx.traceId);
      return;
    }

    const passwordHash = await hashPassword(passwordCheck.value);
    ctx.store.seedSuperAdmin({ username: body.username, passwordHash });
    json(res, 201, { data: { created: true } });
  });
}



