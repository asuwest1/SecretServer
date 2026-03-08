import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { CryptoService } from '../src/api/lib/crypto.js';
import { hashPassword, verifyPassword } from '../src/api/lib/password.js';
import { TokenService } from '../src/api/lib/auth.js';
import { generateTotpSecret, verifyTotp } from '../src/api/lib/totp.js';
import { Store } from '../src/api/data/store.js';
import { requireAuth, hashApiToken, allowRateLimit, _getRateLimitBucketCount } from '../src/api/services/security.js';
import { LdapService } from '../src/api/services/ldap.js';
import { SyslogService } from '../src/api/services/syslog.js';

const tempDir = path.join(process.cwd(), '.tmp-test');
fs.mkdirSync(tempDir, { recursive: true });

async function testCryptoRoundTrip() {
  const service = new CryptoService({ keyFilePath: path.join(tempDir, 'master.key') });
  const encrypted = service.encryptSecret('top-secret-value');
  const plaintext = service.decryptSecret({
    valueEnc: encrypted.encryptedValue,
    dekEnc: encrypted.encryptedDek,
  });
  assert.equal(plaintext, 'top-secret-value');
  return 'crypto round-trip';
}

async function testPassword() {
  const hash = await hashPassword('CorrectHorseBatteryStaple!');
  assert.equal(await verifyPassword('CorrectHorseBatteryStaple!', hash), true);
  assert.equal(await verifyPassword('wrong-password', hash), false);
  return 'password hash verify';
}

async function testToken() {
  const tokenService = new TokenService({
    jwtSigningKeyPath: path.join(tempDir, 'jwt.key'),
    accessTokenLifetimeMinutes: 15,
    refreshTokenLifetimeHours: 8,
  });
  const token = tokenService.createAccessToken({ id: 'u1', username: 'admin', isSuperAdmin: true });
  const claims = tokenService.verify(token);
  assert.equal(claims.sub, 'u1');
  assert.equal(claims.username, 'admin');
  assert.equal(claims.type, 'access');
  assert.ok(claims.jti);
  return 'token sign verify';
}

async function testTotp() {
  const secret = generateTotpSecret();
  const now = Date.now();

  let accepted = false;
  for (let offset = -1; offset <= 1; offset += 1) {
    const windowNow = now + offset * 30 * 1000;
    if (verifyTotp({ secret, code: '000000', now: windowNow })) {
      accepted = true;
      break;
    }
  }

  assert.equal(typeof secret, 'string');
  assert.equal(secret.length > 0, true);
  assert.equal(accepted, false);
  return 'totp utils';
}

async function testSessionRevocation() {
  const store = new Store();
  store.addRefreshSession({ jti: 'j1', userId: 'u1', revokedAt: null });
  assert.ok(store.findRefreshSession('j1'));
  store.revokeSession('j1');
  assert.equal(store.findRefreshSession('j1'), null);
  assert.equal(store.isRevokedJti('j1'), true);
  return 'session revoke';
}

async function testApiTokenAuth() {
  const store = new Store();
  const user = {
    id: 'u-1',
    username: 'api-user',
    isActive: true,
    isSuperAdmin: false,
  };
  store.users.push(user);
  store.apiTokens.push({
    id: 't-1',
    userId: user.id,
    tokenHash: hashApiToken('raw-token'),
    expiresAt: null,
    lastUsed: null,
    name: 'default',
    createdAt: new Date().toISOString(),
  });

  let status = 0;
  const req = { headers: { 'x-api-token': 'raw-token' }, socket: { remoteAddress: '127.0.0.1' } };
  const res = { writeHead: (s) => { status = s; }, end: () => {} };
  const ctx = {
    traceId: 'trace',
    store,
    tokenService: {
      verify: () => { throw new Error('not-called'); },
    },
  };

  const authed = requireAuth(req, res, ctx);
  assert.equal(status, 0);
  assert.equal(authed?.id, user.id);
  assert.ok(store.apiTokens[0].lastUsed);
  return 'api token auth';
}

async function testApiTokenReadScopeDeniedForWrite() {
  const store = new Store();
  const user = { id: 'u-2', username: 'reader', isActive: true, isSuperAdmin: false };
  store.users.push(user);
  store.apiTokens.push({
    id: 't-2',
    userId: user.id,
    tokenHash: hashApiToken('read-token'),
    scopes: ['read'],
    expiresAt: null,
    lastUsed: null,
    name: 'read-only',
    createdAt: new Date().toISOString(),
  });

  let status = 0;
  const req = { headers: { 'x-api-token': 'read-token' }, socket: { remoteAddress: '127.0.0.1' } };
  const res = { writeHead: (s) => { status = s; }, end: () => {} };
  const ctx = {
    traceId: 'trace',
    store,
    tokenService: {
      verify: () => { throw new Error('not-called'); },
    },
  };

  const authed = requireAuth(req, res, ctx, 'write');
  assert.equal(authed, null);
  assert.equal(status, 403);
  return 'api token scope deny write';
}

async function testApiTokenWriteScopeAllowsWrite() {
  const store = new Store();
  const user = { id: 'u-3', username: 'writer', isActive: true, isSuperAdmin: false };
  store.users.push(user);
  store.apiTokens.push({
    id: 't-3',
    userId: user.id,
    tokenHash: hashApiToken('write-token'),
    scopes: ['write'],
    expiresAt: null,
    lastUsed: null,
    name: 'writer',
    createdAt: new Date().toISOString(),
  });

  let status = 0;
  const req = { headers: { 'x-api-token': 'write-token' }, socket: { remoteAddress: '127.0.0.1' } };
  const res = { writeHead: (s) => { status = s; }, end: () => {} };
  const ctx = {
    traceId: 'trace',
    store,
    tokenService: {
      verify: () => { throw new Error('not-called'); },
    },
  };

  const authed = requireAuth(req, res, ctx, 'write');
  assert.equal(status, 0);
  assert.equal(authed?.id, user.id);
  return 'api token scope allow write';
}

async function testBearerAdminScopeRequired() {
  const store = new Store();
  const user = { id: 'u-4', username: 'basic-user', isActive: true, isSuperAdmin: false };
  store.users.push(user);

  let status = 0;
  const req = { headers: { authorization: 'Bearer access-token' }, socket: { remoteAddress: '127.0.0.1' } };
  const res = { writeHead: (s) => { status = s; }, end: () => {} };
  const ctx = {
    traceId: 'trace',
    store,
    tokenService: {
      verify: () => ({ type: 'access', sub: user.id, jti: 'jti-1' }),
    },
  };

  const authed = requireAuth(req, res, ctx, 'admin');
  assert.equal(authed, null);
  assert.equal(status, 403);
  return 'bearer admin scope required';
}

async function testLdapServiceValidationAndNormalization() {
  const logger = { warn: () => {}, debug: () => {} };
  const cfg = {
    enabled: true,
    requireLdaps: true,
    port: 636,
    server: 'dc01.example.test',
    domain: 'example.test',
    baseDn: '',
    serviceAccountDn: '',
    serviceAccountPassword: '',
    authScriptPath: path.join(process.cwd(), 'infra', 'scripts', 'ldap-auth.ps1'),
    authTimeoutMs: 5000,
    maxGroups: 2,
  };

  let capturedArgs = null;
  let capturedOptions = null;
  const runner = (_cmd, args, options) => {
    capturedArgs = args;
    capturedOptions = options;
    return {
      status: 0,
      stdout: JSON.stringify({
        ok: true,
        username: 'alice',
        displayName: 'Alice',
        email: 'alice@example.test',
        groups: ['Ops', 'Ops', 'Admins', 'Audit'],
      }),
    };
  };

  const ldap = new LdapService(cfg, logger, runner);
  const result = await ldap.authenticate('alice', 'password');

  assert.equal(result.ok, true);
  assert.deepEqual(result.groups, ['Ops', 'Admins']);
  return 'ldap service hardening';
}


async function testAuditIntegrityAndRetention() {
  const store = new Store();
  store.appendAudit({ action: 'EVENT_A', resource: 'test', resourceId: '1' });
  store.appendAudit({ action: 'EVENT_B', resource: 'test', resourceId: '2' });

  let verify = store.verifyAuditIntegrity();
  assert.equal(verify.ok, true);

  store.auditLog[1].action = 'EVENT_B_TAMPERED';
  verify = store.verifyAuditIntegrity();
  assert.equal(verify.ok, false);

  store.auditLog[1].action = 'EVENT_B';
  store.auditLog[1].integrityHash = store.auditLog[1].detail.integrity.hash;
  verify = store.verifyAuditIntegrity();
  assert.equal(verify.ok, true);

  store.auditLog[0].eventTime = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
  store.enforceAuditRetention({ retentionDays: 1, maxEntries: 10 });
  assert.equal(store.auditLog.length, 1);
  return 'audit integrity and retention';
}

async function testSyslogFailureModes() {
  const warnings = [];
  const logger = { warn: (code) => warnings.push(code) };

  const udp = new SyslogService({ enabled: true, protocol: 'udp', server: '127.0.0.1', port: 514 }, logger, {
    dgramModule: {
      createSocket: () => ({
        send: (_buf, _port, _server, cb) => cb(new Error('udp failed')),
        close: () => {},
      }),
    },
  });
  udp.send({ action: 'TEST' });

  const tcp = new SyslogService({ enabled: true, protocol: 'tcp', server: '127.0.0.1', port: 514 }, logger, {
    netModule: {
      createConnection: (_port, _server, onConnect) => {
        const socket = {
          write: () => {},
          end: () => {},
          on: (event, cb) => {
            if (event === 'error') cb(new Error('tcp failed'));
          },
        };
        if (onConnect) onConnect();
        return socket;
      },
    },
  });
  tcp.send({ action: 'TEST' });

  const tls = new SyslogService({ enabled: true, protocol: 'tls', server: '127.0.0.1', port: 6514, tlsRejectUnauthorized: true }, logger, {
    tlsModule: {
      connect: (_opts, onConnect) => {
        const socket = {
          write: () => {},
          end: () => {},
          on: (event, cb) => {
            if (event === 'error') cb(new Error('tls failed'));
          },
        };
        if (onConnect) onConnect();
        return socket;
      },
    },
  });
  tls.send({ action: 'TEST' });

  const invalid = new SyslogService({ enabled: true, protocol: 'bogus', server: '127.0.0.1', port: 514 }, logger);
  invalid.send({ action: 'TEST' });

  assert.ok(warnings.includes('syslog_udp_failed'));
  assert.ok(warnings.includes('syslog_tcp_failed'));
  assert.ok(warnings.includes('syslog_tls_failed'));
  assert.ok(warnings.includes('syslog_protocol_invalid'));
  return 'syslog protocol failure modes';
}

async function testRateLimitBucketCleanup() {
  const now = Date.now();
  allowRateLimit('cleanup:a', 5, now - 5 * 60000);
  allowRateLimit('cleanup:b', 5, now - 4 * 60000);
  allowRateLimit('cleanup:c', 5, now - 3 * 60000);
  allowRateLimit('cleanup:current', 5, now);

  assert.equal(_getRateLimitBucketCount() <= 2, true);
  return 'rate limit bucket cleanup';
}
async function testLdapServiceInvalidLdapsConfig() {
  const logger = { warn: () => {}, debug: () => {} };
  const cfg = {
    enabled: true,
    requireLdaps: true,
    port: 389,
    server: 'dc01.example.test',
    domain: 'example.test',
    baseDn: '',
    serviceAccountDn: '',
    serviceAccountPassword: '',
    authScriptPath: path.join(process.cwd(), 'infra', 'scripts', 'ldap-auth.ps1'),
    authTimeoutMs: 5000,
    maxGroups: 16,
  };

  const ldap = new LdapService(cfg, logger, () => ({ status: 0, stdout: '{}' }));
  const result = await ldap.authenticate('alice', 'password');

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'LDAP_LDAPS_REQUIRED');
  return 'ldap ldaps enforcement';
}
const tests = [
  testCryptoRoundTrip,
  testPassword,
  testToken,
  testTotp,
  testSessionRevocation,
  testApiTokenAuth,
  testApiTokenReadScopeDeniedForWrite,
  testApiTokenWriteScopeAllowsWrite,
  testBearerAdminScopeRequired,
  testLdapServiceValidationAndNormalization,
  testLdapServiceInvalidLdapsConfig,
  testRateLimitBucketCleanup,
  testAuditIntegrityAndRetention,
  testSyslogFailureModes,
];

for (const run of tests) {
  const name = await run();
  process.stdout.write(`PASS ${name}\n`);
}
process.stdout.write('ALL TESTS PASSED\n');






