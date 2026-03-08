import crypto from 'node:crypto';
import http from 'node:http';
import { Router } from './lib/router.js';
import { notFound, sendError } from './lib/http.js';
import { createLogger } from './lib/logger.js';
import { loadProtectedSecrets } from './lib/protected-secrets.js';
import { loadConfig } from './lib/config.js';
import { CryptoService } from './lib/crypto.js';
import { TokenService } from './lib/auth.js';
import { hashPassword } from './lib/password.js';
import { validatePassword } from './lib/validation.js';
import { createStore } from './data/factory.js';
import { SyslogService } from './services/syslog.js';
import { LdapService } from './services/ldap.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerUserRoutes } from './routes/users.js';
import { registerRoleRoutes } from './routes/roles.js';
import { registerFolderRoutes } from './routes/folders.js';
import { registerSecretRoutes } from './routes/secrets.js';
import { registerAuditRoutes } from './routes/audit.js';
import { registerDocsRoutes } from './routes/docs.js';
import { registerHealthRoutes } from './routes/health.js';

const logger = createLogger('api');
loadProtectedSecrets(logger);
const config = loadConfig();
const cryptoService = new CryptoService({ keyFilePath: config.keyFilePath });
const tokenService = new TokenService({
  jwtSigningKeyPath: config.jwtSigningKeyPath,
  accessTokenLifetimeMinutes: config.accessTokenLifetimeMinutes,
  refreshTokenLifetimeHours: config.refreshTokenLifetimeHours,
});
const store = await createStore(config, logger);
const syslog = new SyslogService(config.syslog, logger);
const ldap = new LdapService(config.ldap, logger);

if (config.ldap.enabled) {
  const ldapValidation = ldap.validateConfiguration();
  if (!ldapValidation.ok) {
    logger.error('ldap_config_invalid', { reason: ldapValidation.reason });
    process.exit(1);
  }

  if (config.env === 'production' && config.ldap.fallbackLocal && !config.ldap.allowLocalFallbackInProduction) {
    logger.error('ldap_config_invalid', { reason: 'LDAP_LOCAL_FALLBACK_DISABLED_IN_PRODUCTION' });
    process.exit(1);
  }

  // In production, the LDAP auth script hash must be pinned. Without it, an
  // attacker who can write to the script path could inject arbitrary code that
  // runs with the server's privileges on every authentication attempt.
  if (config.env === 'production' && !config.ldap.authScriptSha256) {
    logger.error('ldap_config_invalid', {
      reason: 'LDAP_AUTH_SCRIPT_HASH_REQUIRED_IN_PRODUCTION',
      envVar: 'SECRET_SERVER_LDAP_AUTH_SCRIPT_SHA256',
      message: 'Set SECRET_SERVER_LDAP_AUTH_SCRIPT_SHA256 to the SHA-256 hex digest of the LDAP auth script.',
    });
    process.exit(1);
  }
}

if (store.users.length === 0) {
  const bootstrapPassword = String(process.env.SECRET_SERVER_BOOTSTRAP_PASSWORD || '').trim();
  if (!bootstrapPassword) {
    logger.error('bootstrap_password_missing', {
      envVar: 'SECRET_SERVER_BOOTSTRAP_PASSWORD',
      message: 'Set bootstrap password explicitly before first start.',
    });
    process.exit(1);
  }

  const bootstrapPasswordCheck = validatePassword(bootstrapPassword);
  if (!bootstrapPasswordCheck.ok) {
    logger.error('bootstrap_password_weak', {
      envVar: 'SECRET_SERVER_BOOTSTRAP_PASSWORD',
      reason: bootstrapPasswordCheck.error,
      message: 'Bootstrap password does not meet strength requirements (12+ chars, upper, lower, number, symbol).',
    });
    process.exit(1);
  }

  hashPassword(bootstrapPassword)
    .then((passwordHash) => {
      store.seedSuperAdmin({ username: 'superadmin', passwordHash });
      logger.warn('bootstrap_superadmin_created', { username: 'superadmin' });
    })
    .catch((err) => {
      logger.error('bootstrap_failed', { error: err.message });
      process.exit(1);
    });
}

const router = new Router();
registerHealthRoutes(router);
registerAuthRoutes(router);
registerUserRoutes(router);
registerRoleRoutes(router);
registerFolderRoutes(router);
registerSecretRoutes(router);
registerAuditRoutes(router);
registerDocsRoutes(router);

let lastSyslogAuditId = 0;

function resolveAllowedCorsOrigin(req, appConfig) {
  const requestOrigin = String(req.headers.origin || '').trim();
  if (!requestOrigin) return null;
  const allowedOrigins = appConfig.cors?.allowedOrigins || [];
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) return null;
  return allowedOrigins.includes(requestOrigin) ? requestOrigin : null;
}

function applyCorsHeaders(req, res, appConfig) {
  const allowedOrigin = resolveAllowedCorsOrigin(req, appConfig);
  if (!allowedOrigin) return false;
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Expose-Headers', 'X-CSRF-Token');
  return true;
}

function isStateChangingMethod(method) {
  return method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH';
}

function hasAuthCredential(req) {
  return Boolean(req.headers.authorization || req.headers['x-api-token']);
}

function equalsSecure(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length === 0 || right.length === 0 || left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

const server = http.createServer(async (req, res) => {
  const start = Date.now();
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (config.csrf?.enabled && config.csrf?.token) {
    res.setHeader('X-CSRF-Token', config.csrf.token);
  }

  if (req.method === 'OPTIONS') {
    const allowed = applyCorsHeaders(req, res, config);
    if (!allowed && req.headers.origin) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Origin is not allowed.', 'cors');
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.headers.origin) {
    const allowed = applyCorsHeaders(req, res, config);
    if (!allowed) {
      sendError(res, 403, 'PERMISSION_DENIED', 'Origin is not allowed.', 'cors');
      return;
    }
  }

  if (config.csrf?.enabled && req.headers.origin && isStateChangingMethod(req.method || 'GET') && hasAuthCredential(req)) {
    const supplied = req.headers['x-csrf-token'];
    if (!equalsSecure(supplied, config.csrf.token)) {
      sendError(res, 403, 'PERMISSION_DENIED', 'CSRF token validation failed.', 'csrf');
      return;
    }
  }

  try {
    const handled = await router.handle(req, res, {
      config,
      logger,
      crypto: cryptoService,
      tokenService,
      store,
      syslog,
      ldap,
    });

    if (!handled) {
      notFound(res);
      return;
    }

    const latestAudit = store.auditLog[store.auditLog.length - 1];
    if (latestAudit && latestAudit.id > lastSyslogAuditId) {
      syslog.send(latestAudit);
      lastSyslogAuditId = latestAudit.id;
    }

    if (typeof store.enforceAuditRetention === 'function') {
      store.enforceAuditRetention(config.audit);
    }

    await store.flush();
    logger.info('request_completed', { method: req.method, path: req.url, statusCode: res.statusCode, durationMs: Date.now() - start });
  } catch (err) {
    logger.error('request_failed', { error: err.message, code: err.code });

    if (err.code === 'INVALID_JSON') {
      sendError(res, 400, 'INVALID_JSON', 'Malformed JSON request body.', 'request');
    } else if (err.code === 'PAYLOAD_TOO_LARGE') {
      sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'Request payload exceeds allowed size.', 'request');
    } else {
      sendError(res, 500, 'INTERNAL_ERROR', 'Request failed.', 'internal');
    }

    logger.error('request_failed_with_timing', { method: req.method, path: req.url, durationMs: Date.now() - start });
  }
});

server.listen(config.port, config.host, () => {
  logger.info('server_started', {
    host: config.host,
    port: config.port,
    env: config.env,
  });
});
