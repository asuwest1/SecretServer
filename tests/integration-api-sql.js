import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { SqlStore } from '../src/api/data/sql-store.js';
import { Router } from '../src/api/lib/router.js';
import { notFound } from '../src/api/lib/http.js';
import { CryptoService } from '../src/api/lib/crypto.js';
import { TokenService } from '../src/api/lib/auth.js';
import { hashPassword } from '../src/api/lib/password.js';
import { registerAuthRoutes } from '../src/api/routes/auth.js';
import { registerUserRoutes } from '../src/api/routes/users.js';
import { registerRoleRoutes } from '../src/api/routes/roles.js';
import { registerFolderRoutes } from '../src/api/routes/folders.js';
import { registerSecretRoutes } from '../src/api/routes/secrets.js';
import { applyMigrations, createSqlConfig } from './sql-test-utils.js';

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
        resolve({ status: res.statusCode || 0, json: raw ? JSON.parse(raw) : null });
      });
    });

    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function main() {
  applyMigrations();

  const config = {
    issuer: 'SecretServer',
    lockoutThreshold: 5,
    lockoutDurationMinutes: 30,
    requireMfa: false,
    ldap: { enabled: false, fallbackLocal: true },
    openApi: { internalOnly: false },
  };

  const logger = createLogger();
  const crypto = new CryptoService({ keyFilePath: path.join(tempDir, 'master.key') });
  const tokenService = new TokenService({
    jwtSigningKeyPath: path.join(tempDir, 'jwt.key'),
    accessTokenLifetimeMinutes: 15,
    refreshTokenLifetimeHours: 8,
  });

  const store = new SqlStore(createSqlConfig(), logger);
  await store.load();

  if (!store.users.some((u) => u.username === 'superadmin')) {
    store.seedSuperAdmin({ username: 'superadmin', passwordHash: await hashPassword('ChangeMeNow!123') });
    await store.flush();
  }

  const ctx = {
    config,
    logger,
    crypto,
    tokenService,
    store,
    syslog: { send: () => {} },
    ldap: { authenticate: async () => ({ ok: false }) },
  };

  const router = new Router();
  registerAuthRoutes(router);
  registerUserRoutes(router);
  registerRoleRoutes(router);
  registerFolderRoutes(router);
  registerSecretRoutes(router);

  const server = http.createServer(async (req, res) => {
    const handled = await router.handle(req, res, ctx);
    if (!handled) {
      notFound(res);
      return;
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method || 'GET')) {
      await store.flush();
    }
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  try {
    const loginAdmin = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'superadmin', password: 'ChangeMeNow!123' },
    });
    assert.equal(loginAdmin.status, 200);
    const adminAuth = { Authorization: `Bearer ${loginAdmin.json?.data?.accessToken}` };

    const createRole = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/roles',
      headers: adminAuth,
      body: { name: 'SqlOpsRole', description: 'sql api role' },
    });
    assert.equal(createRole.status, 201);
    const roleId = createRole.json?.data?.id;

    const createUser = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/users',
      headers: adminAuth,
      body: {
        username: 'sqlalice',
        password: 'StrongPass!123',
        displayName: 'Sql Alice',
        email: `sqlalice+${Date.now()}@example.test`,
      },
    });
    assert.equal(createUser.status, 201);
    const userId = createUser.json?.data?.id;

    const member = await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/roles/${roleId}/members`,
      headers: adminAuth,
      body: { userId },
    });
    assert.equal(member.status, 200);

    const createFolder = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/folders',
      headers: adminAuth,
      body: { name: `SQL-Ops-${Date.now()}` },
    });
    assert.equal(createFolder.status, 201);
    const folderId = createFolder.json?.data?.id;

    const acl = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/folders/${folderId}/acl`,
      headers: adminAuth,
      body: {
        entries: [{ roleId, canAdd: true, canView: true, canChange: true, canDelete: true }],
      },
    });
    assert.equal(acl.status, 200);

    const loginUser = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'sqlalice', password: 'StrongPass!123' },
    });
    assert.equal(loginUser.status, 200);
    const userAuth = { Authorization: `Bearer ${loginUser.json?.data?.accessToken}` };

    const createSecret = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/secrets',
      headers: userAuth,
      body: {
        folderId,
        name: 'SQL-Secret',
        value: 'sql-value-1',
        notes: 'sql-notes',
        tags: ['sql'],
      },
    });
    assert.equal(createSecret.status, 201);
    const secretId = createSecret.json?.data?.id;

    const updateSecret = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${secretId}`,
      headers: userAuth,
      body: { value: 'sql-value-2' },
    });
    assert.equal(updateSecret.status, 200);

    const versions = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${secretId}/versions`,
      headers: userAuth,
    });
    assert.equal(versions.status, 200);
    assert.equal((versions.json?.data || []).length, 1);

    const reload = new SqlStore(createSqlConfig(), logger);
    await reload.load();
    assert.ok(reload.secrets.find((s) => s.id === secretId), 'secret persisted in SQL');

    console.log('SQL API integration test passed');
  } finally {
    server.close();
    await once(server, 'close');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

