import crypto from 'node:crypto';
import fs from 'node:fs';

function env(name, fallback = '') {
  return process.env[name] ?? fallback;
}

function bool(name, fallback = false) {
  const value = env(name, fallback ? 'true' : 'false').toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

function int(name, fallback) {
  const raw = env(name, String(fallback));
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function jsonObject(name, fallback = {}) {
  const raw = env(name, '');
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function csvList(name, fallback = []) {
  const raw = env(name, '');
  if (!raw) return fallback;
  return raw.split(',').map((x) => x.trim()).filter((x) => x.length > 0);
}

export function loadConfig() {
  const keyFilePath = env('SECRET_SERVER_KEY_FILE', './secrets/master.key');
  const jwtSigningKeyPath = env('SECRET_SERVER_JWT_KEY_FILE', './secrets/jwt.key');

  // CSRF token: use explicitly configured value (required in multi-instance deployments
  // where all nodes must share the same token) or generate a cryptographically random
  // token at startup. The random fallback means each server restart issues a new token,
  // which is correct — clients must re-fetch it via the X-CSRF-Token response header.
  const csrfToken = env('SECRET_SERVER_CSRF_TOKEN', crypto.randomBytes(32).toString('hex'));

  return {
    env: env('NODE_ENV', 'development'),
    host: env('SECRET_SERVER_HOST', '0.0.0.0'),
    port: int('SECRET_SERVER_PORT', 8080),
    issuer: env('SECRET_SERVER_ISSUER', 'SecretServer'),
    accessTokenLifetimeMinutes: int('SECRET_SERVER_ACCESS_TOKEN_LIFETIME_MINUTES', 15),
    refreshTokenLifetimeHours: int('SECRET_SERVER_REFRESH_TOKEN_LIFETIME_HOURS', 8),
    maxApiTokensPerUser: int('SECRET_SERVER_MAX_API_TOKENS_PER_USER', 20),
    maxApiTokenLifetimeDays: int('SECRET_SERVER_MAX_API_TOKEN_LIFETIME_DAYS', 30),
    csrf: {
      enabled: bool('SECRET_SERVER_CSRF_ENABLED', true),
      token: csrfToken,
    },
    cors: {
      allowedOrigins: csvList('SECRET_SERVER_CORS_ALLOWED_ORIGINS', []),
    },
    lockoutThreshold: int('SECRET_SERVER_LOCKOUT_THRESHOLD', 5),
    lockoutDurationMinutes: int('SECRET_SERVER_LOCKOUT_DURATION_MINUTES', 30),
    requireMfa: bool('SECRET_SERVER_REQUIRE_MFA', false),
    keyFilePath,
    jwtSigningKeyPath,
    syslog: {
      enabled: bool('SECRET_SERVER_SYSLOG_ENABLED', false),
      server: env('SECRET_SERVER_SYSLOG_SERVER', '127.0.0.1'),
      port: int('SECRET_SERVER_SYSLOG_PORT', 514),
      protocol: env('SECRET_SERVER_SYSLOG_PROTOCOL', 'udp').toLowerCase(),
      tlsEnabled: bool('SECRET_SERVER_SYSLOG_TLS_ENABLED', false),
      tlsRejectUnauthorized: bool('SECRET_SERVER_SYSLOG_TLS_REJECT_UNAUTHORIZED', true),
    },
    ldap: {
      enabled: bool('SECRET_SERVER_LDAP_ENABLED', false),
      fallbackLocal: bool('SECRET_SERVER_LDAP_FALLBACK_LOCAL', true),
      server: env('SECRET_SERVER_LDAP_SERVER', ''),
      port: int('SECRET_SERVER_LDAP_PORT', 636),
      baseDn: env('SECRET_SERVER_LDAP_BASE_DN', ''),
      domain: env('SECRET_SERVER_LDAP_DOMAIN', ''),
      serviceAccountDn: env('SECRET_SERVER_LDAP_SERVICE_ACCOUNT_DN', ''),
      serviceAccountPassword: env(env('SECRET_SERVER_LDAP_PASSWORD_ENV', 'SECRET_SERVER_LDAP_PASSWORD'), ''),
      authScriptPath: env('SECRET_SERVER_LDAP_AUTH_SCRIPT', './infra/scripts/ldap-auth.ps1'),
      authScriptSha256: env('SECRET_SERVER_LDAP_AUTH_SCRIPT_SHA256', '').toLowerCase(),
      authTimeoutMs: int('SECRET_SERVER_LDAP_AUTH_TIMEOUT_MS', 8000),
      maxGroups: int('SECRET_SERVER_LDAP_MAX_GROUPS', 256),
      requireLdaps: bool('SECRET_SERVER_LDAP_REQUIRE_LDAPS', true),
      allowLocalFallbackInProduction: bool('SECRET_SERVER_LDAP_ALLOW_LOCAL_FALLBACK_IN_PRODUCTION', false),
      roleGroupMap: jsonObject('SECRET_SERVER_LDAP_ROLE_GROUP_MAP', {}),
    },
    sql: {
      enabled: bool('SECRET_SERVER_SQL_ENABLED', false),
      mode: env('SECRET_SERVER_SQL_MODE', 'sqlcmd').toLowerCase(),
      server: env('SECRET_SERVER_SQL_SERVER', 'localhost'),
      database: env('SECRET_SERVER_SQL_DATABASE', 'secret_server'),
      username: env('SECRET_SERVER_SQL_USERNAME', ''),
      password: env('SECRET_SERVER_SQL_PASSWORD', ''),
      sqlcmdPath: env('SECRET_SERVER_SQLCMD_PATH', 'sqlcmd'),
      appStateTable: env('SECRET_SERVER_SQL_STATE_TABLE', 'secret_server_state'),
      requiredMigration: env('SECRET_SERVER_SQL_REQUIRED_MIGRATION', '3'),
      trustServerCertificate: bool('SECRET_SERVER_SQL_TRUST_SERVER_CERTIFICATE', false),
    },
    audit: {
      retentionDays: int('SECRET_SERVER_AUDIT_RETENTION_DAYS', 90),
      maxEntries: int('SECRET_SERVER_AUDIT_MAX_ENTRIES', 200000),
      // When set, records purged by the retention policy are written to JSONL
      // files in this directory before being discarded. Each purge run produces
      // one file named audit-<ISO-timestamp>.jsonl. Leave empty to disable.
      archiveDir: env('SECRET_SERVER_AUDIT_ARCHIVE_DIR', ''),
    },
    openApi: {
      internalOnly: bool('SECRET_SERVER_OPENAPI_INTERNAL_ONLY', true),
      trustProxy: bool('SECRET_SERVER_OPENAPI_TRUST_PROXY', true),
      trustedProxyIps: csvList('SECRET_SERVER_OPENAPI_TRUSTED_PROXY_IPS', []),
    },
    fileExists: (filePath) => fs.existsSync(filePath),
  };
}
