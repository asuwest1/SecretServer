import http from 'node:http';
import { Router } from './lib/router.js';
import { notFound, sendError } from './lib/http.js';
import { createLogger } from './lib/logger.js';
import { loadProtectedSecrets } from './lib/protected-secrets.js';
import { loadConfig } from './lib/config.js';
import { CryptoService } from './lib/crypto.js';
import { TokenService } from './lib/auth.js';
import { hashPassword } from './lib/password.js';
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
}

if (store.users.length === 0) {
  const bootstrapPassword = process.env.SECRET_SERVER_BOOTSTRAP_PASSWORD || 'ChangeMeNow!123';
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

const server = http.createServer(async (req, res) => {
  const start = Date.now();
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    });
    res.end();
    return;
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


