import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { Router } from '../src/api/lib/router.js';
import { notFound } from '../src/api/lib/http.js';
import { CryptoService } from '../src/api/lib/crypto.js';
import { TokenService } from '../src/api/lib/auth.js';
import { hashPassword } from '../src/api/lib/password.js';
import { Store } from '../src/api/data/store.js';
import { registerAuthRoutes } from '../src/api/routes/auth.js';

const tempDir = path.join(process.cwd(), '.tmp-test');
fs.mkdirSync(tempDir, { recursive: true });

function createLogger() {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  };
}

function requestJson({ method, port, pathName, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathName,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        if (raw) {
          try {
            json = JSON.parse(raw);
          } catch {
            json = null;
          }
        }
        resolve({ status: res.statusCode || 0, json, raw });
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withServer({ config, store, ldap }) {
  const logger = createLogger();
  const crypto = new CryptoService({ keyFilePath: path.join(tempDir, `master-${Date.now()}-${Math.random()}.key`) });
  const tokenService = new TokenService({
    jwtSigningKeyPath: path.join(tempDir, `jwt-${Date.now()}-${Math.random()}.key`),
    accessTokenLifetimeMinutes: 15,
    refreshTokenLifetimeHours: 8,
  });

  const ctx = {
    config,
    logger,
    crypto,
    tokenService,
    store,
    ldap,
    syslog: { send: () => {} },
  };

  const router = new Router();
  registerAuthRoutes(router);

  const server = http.createServer(async (req, res) => {
    const handled = await router.handle(req, res, ctx);
    if (!handled) notFound(res);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  return {
    port,
    close: async () => {
      server.close();
      await once(server, 'close');
    },
  };
}

async function testLdapSuccessAndGroupMappingSync() {
  const store = new Store();
  store.roles.push({ id: 'r-ops', name: 'VaultOperators', description: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  store.roles.push({ id: 'r-read', name: 'ReadOnly', description: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });

  let groups = ['AD-Ops'];
  const ldap = {
    authenticate: async (username) => ({
      ok: true,
      username,
      displayName: 'Alice LDAP',
      email: 'alice@example.test',
      groups,
    }),
  };

  const config = {
    env: 'development',
    issuer: 'SecretServer',
    lockoutThreshold: 5,
    lockoutDurationMinutes: 30,
    requireMfa: false,
    ldap: {
      enabled: true,
      fallbackLocal: false,
      allowLocalFallbackInProduction: false,
      roleGroupMap: {
        'AD-Ops': 'VaultOperators',
        'AD-Read': 'ReadOnly',
      },
    },
  };

  const server = await withServer({ config, store, ldap });
  try {
    const loginA = await requestJson({
      method: 'POST',
      port: server.port,
      pathName: '/api/v1/auth/login',
      body: { username: 'alice', password: 'LdapPass!1' },
    });
    assert.equal(loginA.status, 200);

    const alice = store.users.find((u) => u.username === 'alice');
    assert.ok(alice);
    let aliceRoles = store.userRoles.filter((ur) => ur.userId === alice.id).map((ur) => ur.roleId);
    assert.deepEqual(aliceRoles, ['r-ops']);

    groups = ['AD-Read'];
    const loginB = await requestJson({
      method: 'POST',
      port: server.port,
      pathName: '/api/v1/auth/login',
      body: { username: 'alice', password: 'LdapPass!1' },
    });
    assert.equal(loginB.status, 200);

    aliceRoles = store.userRoles.filter((ur) => ur.userId === alice.id).map((ur) => ur.roleId);
    assert.deepEqual(aliceRoles, ['r-read']);
  } finally {
    await server.close();
  }
}

async function testLdapFailureWithoutFallbackDenied() {
  const store = new Store();
  store.users.push({
    id: 'u-local',
    username: 'alice',
    displayName: 'Alice Local',
    email: 'alice@local',
    passwordHash: await hashPassword('StrongPass!123'),
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
  });

  const ldap = { authenticate: async () => ({ ok: false, reason: 'LDAP_AUTH_FAILED' }) };
  const config = {
    env: 'development',
    issuer: 'SecretServer',
    lockoutThreshold: 5,
    lockoutDurationMinutes: 30,
    requireMfa: false,
    ldap: {
      enabled: true,
      fallbackLocal: false,
      allowLocalFallbackInProduction: false,
      roleGroupMap: {},
    },
  };

  const server = await withServer({ config, store, ldap });
  try {
    const login = await requestJson({
      method: 'POST',
      port: server.port,
      pathName: '/api/v1/auth/login',
      body: { username: 'alice', password: 'StrongPass!123' },
    });
    assert.equal(login.status, 401);
  } finally {
    await server.close();
  }
}

async function testLdapFailureWithFallbackUsesLocal() {
  const store = new Store();
  store.users.push({
    id: 'u-local-2',
    username: 'bob',
    displayName: 'Bob Local',
    email: 'bob@local',
    passwordHash: await hashPassword('StrongPass!123'),
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
  });

  const ldap = { authenticate: async () => ({ ok: false, reason: 'LDAP_AUTH_FAILED' }) };
  const config = {
    env: 'development',
    issuer: 'SecretServer',
    lockoutThreshold: 5,
    lockoutDurationMinutes: 30,
    requireMfa: false,
    ldap: {
      enabled: true,
      fallbackLocal: true,
      allowLocalFallbackInProduction: false,
      roleGroupMap: {},
    },
  };

  const server = await withServer({ config, store, ldap });
  try {
    const login = await requestJson({
      method: 'POST',
      port: server.port,
      pathName: '/api/v1/auth/login',
      body: { username: 'bob', password: 'StrongPass!123' },
    });
    assert.equal(login.status, 200);
    assert.ok(login.json?.data?.accessToken);
  } finally {
    await server.close();
  }
}

async function main() {
  await testLdapSuccessAndGroupMappingSync();
  await testLdapFailureWithoutFallbackDenied();
  await testLdapFailureWithFallbackUsesLocal();
  console.log('LDAP integration test passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
