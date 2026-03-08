import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { Router } from '../src/api/lib/router.js';
import { notFound, sendError } from '../src/api/lib/http.js';
import { CryptoService } from '../src/api/lib/crypto.js';
import { TokenService } from '../src/api/lib/auth.js';
import { hashPassword } from '../src/api/lib/password.js';
import { Store } from '../src/api/data/store.js';
import { registerAuthRoutes } from '../src/api/routes/auth.js';
import { registerUserRoutes } from '../src/api/routes/users.js';
import { registerRoleRoutes } from '../src/api/routes/roles.js';
import { registerFolderRoutes } from '../src/api/routes/folders.js';
import { registerSecretRoutes } from '../src/api/routes/secrets.js';
import { registerAuditRoutes } from '../src/api/routes/audit.js';
import { registerDocsRoutes } from '../src/api/routes/docs.js';

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
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

function requestRaw({ method, port, pathName, rawBody, headers = {} }) {
  return new Promise((resolve, reject) => {
    const payload = rawBody ?? '';
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathName,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
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
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}
async function main() {
  const config = {
    issuer: 'SecretServer',
    lockoutThreshold: 5,
    lockoutDurationMinutes: 30,
    requireMfa: false,
    ldap: { enabled: false, fallbackLocal: true },
    openApi: { internalOnly: true, trustProxy: true },
  };

  const logger = createLogger();
  const crypto = new CryptoService({ keyFilePath: path.join(tempDir, 'master.key') });
  const tokenService = new TokenService({
    jwtSigningKeyPath: path.join(tempDir, 'jwt.key'),
    accessTokenLifetimeMinutes: 15,
    refreshTokenLifetimeHours: 8,
  });

  const store = new Store();
  store.seedSuperAdmin({ username: 'superadmin', passwordHash: await hashPassword('ChangeMeNow!123') });

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
  registerAuditRoutes(router);
  registerDocsRoutes(router);

  const server = http.createServer(async (req, res) => {
    try {
      const handled = await router.handle(req, res, ctx);
      if (!handled) {
        notFound(res);
      }
    } catch (err) {
      if (err.code === 'INVALID_JSON') {
        sendError(res, 400, 'INVALID_JSON', 'Malformed JSON request body.', 'test');
      } else if (err.code === 'PAYLOAD_TOO_LARGE') {
        sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'Request payload exceeds allowed size.', 'test');
      } else {
        throw err;
      }
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
    const adminAccessToken = loginAdmin.json?.data?.accessToken;
    assert.ok(adminAccessToken);
    const adminAuth = { Authorization: `Bearer ${adminAccessToken}` };

    const docsDenied = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/docs',
      headers: {
        ...adminAuth,
        'x-forwarded-for': '8.8.8.8',
      },
    });
    assert.equal(docsDenied.status, 403);

    const docsAllowed = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/docs',
      headers: {
        ...adminAuth,
        'x-forwarded-for': '10.10.0.15',
      },
    });
    assert.equal(docsAllowed.status, 200);
    assert.ok((docsAllowed.raw || '').includes('openapi'));

    const invalidJsonRoleCreate = await requestRaw({
      method: 'POST',
      port,
      pathName: '/api/v1/roles',
      headers: adminAuth,
      rawBody: '{"name":',
    });
    assert.equal(invalidJsonRoleCreate.status, 400);
    assert.equal(invalidJsonRoleCreate.json?.error?.code, 'INVALID_JSON');

    const createRole = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/roles',
      headers: adminAuth,
      body: { name: 'VaultOperators', description: 'test role' },
    });
    assert.equal(createRole.status, 201);
    const roleId = createRole.json?.data?.id;

    const createIsolatedRole = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/roles',
      headers: adminAuth,
      body: { name: 'Isolated', description: 'override-only role' },
    });
    assert.equal(createIsolatedRole.status, 201);
    const isolatedRoleId = createIsolatedRole.json?.data?.id;

    const createUser = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/users',
      headers: adminAuth,
      body: {
        username: 'alice',
        password: 'StrongPass!123',
        displayName: 'Alice',
        email: 'alice@example.test',
      },
    });
    assert.equal(createUser.status, 201);
    const aliceId = createUser.json?.data?.id;

    const createOtherUser = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/users',
      headers: adminAuth,
      body: {
        username: 'bob',
        password: 'StrongPass!123',
        displayName: 'Bob',
        email: 'bob@example.test',
      },
    });
    assert.equal(createOtherUser.status, 201);
    const bobId = createOtherUser.json?.data?.id;

    const addMember = await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/roles/${roleId}/members`,
      headers: adminAuth,
      body: { userId: aliceId },
    });
    assert.equal(addMember.status, 200);

    const createFolder = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/folders',
      headers: adminAuth,
      body: { name: 'Ops' },
    });
    assert.equal(createFolder.status, 201);
    const folderId = createFolder.json?.data?.id;

    const setFolderAcl = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/folders/${folderId}/acl`,
      headers: adminAuth,
      body: {
        entries: [{ roleId, canAdd: true, canView: true, canChange: true, canDelete: true }],
      },
    });
    assert.equal(setFolderAcl.status, 200);

    const createChildFolder = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/folders',
      headers: adminAuth,
      body: { name: 'Ops-Child', parentFolderId: folderId },
    });
    assert.equal(createChildFolder.status, 201);
    const childFolderId = createChildFolder.json?.data?.id;

    const loginAlice = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'alice', password: 'StrongPass!123' },
    });
    assert.equal(loginAlice.status, 200);
    const aliceAccessToken = loginAlice.json?.data?.accessToken;
    assert.ok(aliceAccessToken);
    const aliceAuth = { Authorization: `Bearer ${aliceAccessToken}` };

    const createSecret = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/secrets',
      headers: aliceAuth,
      body: {
        folderId,
        name: 'DB-Password',
        value: 'Value#1',
        notes: 'contains key phrase: unicorn',
        username: 'svc-ops',
        tags: ['ops'],
      },
    });
    assert.equal(createSecret.status, 201);
    const secretId = createSecret.json?.data?.id;

    const createChildSecret = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/secrets',
      headers: aliceAuth,
      body: {
        folderId: childFolderId,
        name: 'Child-Password',
        value: 'Child#1',
        notes: 'nested folder inheritance check',
        username: 'svc-child',
        tags: ['ops', 'child'],
      },
    });
    assert.equal(createChildSecret.status, 201);
    const childSecretId = createChildSecret.json?.data?.id;

    const revealChildSecret = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${childSecretId}/value`,
      headers: aliceAuth,
    });
    assert.equal(revealChildSecret.status, 200);
    assert.equal(revealChildSecret.json?.data?.value, 'Child#1');

    const setChildSecretAcl = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${childSecretId}/acl`,
      headers: aliceAuth,
      body: { entries: [{ roleId: isolatedRoleId, canView: true, canAdd: false, canChange: false, canDelete: false }] },
    });
    assert.equal(setChildSecretAcl.status, 200);

    const searchChildAfterOverride = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/v1/secrets?q=child',
      headers: aliceAuth,
    });
    assert.equal(searchChildAfterOverride.status, 200);
    assert.equal((searchChildAfterOverride.json?.data || []).some((s) => s.id === childSecretId), false);

    const revealChildAfterOverride = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${childSecretId}/value`,
      headers: aliceAuth,
    });
    assert.equal(revealChildAfterOverride.status, 403);

    const updateChildAfterOverride = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${childSecretId}`,
      headers: aliceAuth,
      body: { notes: 'should fail after override' },
    });
    assert.equal(updateChildAfterOverride.status, 403);

    const deleteChildAfterOverride = await requestJson({
      method: 'DELETE',
      port,
      pathName: `/api/v1/secrets/${childSecretId}`,
      headers: aliceAuth,
    });
    assert.equal(deleteChildAfterOverride.status, 403);

    const revealSecret = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${secretId}/value`,
      headers: aliceAuth,
    });
    assert.equal(revealSecret.status, 200);
    assert.equal(revealSecret.json?.data?.value, 'Value#1');

    const updateSecret = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${secretId}`,
      headers: aliceAuth,
      body: { value: 'Value#2', notes: 'rotated note phrase' },
    });
    assert.equal(updateSecret.status, 200);

    const versions = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${secretId}/versions`,
      headers: aliceAuth,
    });
    assert.equal(versions.status, 200);
    assert.equal((versions.json?.data || []).length, 1);

    const searchByNotes = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/v1/secrets?q=rotated',
      headers: aliceAuth,
    });
    assert.equal(searchByNotes.status, 200);
    assert.ok((searchByNotes.json?.data || []).some((s) => s.id === secretId));

    const deleteSecret = await requestJson({
      method: 'DELETE',
      port,
      pathName: `/api/v1/secrets/${secretId}`,
      headers: aliceAuth,
    });
    assert.equal(deleteSecret.status, 200);

    const restoreSecret = await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/secrets/${secretId}/restore`,
      headers: aliceAuth,
    });
    assert.equal(restoreSecret.status, 200);

    const createReadToken = await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/users/${aliceId}/api-tokens`,
      headers: aliceAuth,
      body: { name: 'ro', scopes: ['read'] },
    });
    assert.equal(createReadToken.status, 201);
    const readToken = createReadToken.json?.data?.rawToken;

    const writeDenied = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${secretId}`,
      headers: { 'x-api-token': readToken },
      body: { value: 'Value#3' },
    });
    assert.equal(writeDenied.status, 403);

    const createWriteToken = await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/users/${aliceId}/api-tokens`,
      headers: aliceAuth,
      body: { name: 'rw', scopes: ['write'] },
    });
    assert.equal(createWriteToken.status, 201);
    const writeToken = createWriteToken.json?.data?.rawToken;

    const writeAllowed = await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/secrets/${secretId}`,
      headers: { 'x-api-token': writeToken },
      body: { value: 'Value#3' },
    });
    assert.equal(writeAllowed.status, 200);

    const loginBob = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'bob', password: 'StrongPass!123' },
    });
    assert.equal(loginBob.status, 200);
    const bobToken = loginBob.json?.data?.accessToken;
    const bobAuth = { Authorization: `Bearer ${bobToken}` };

    const bobList = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/v1/secrets',
      headers: bobAuth,
    });
    assert.equal(bobList.status, 200);
    assert.equal((bobList.json?.data || []).length, 0);

    const bobReveal = await requestJson({
      method: 'GET',
      port,
      pathName: `/api/v1/secrets/${secretId}/value`,
      headers: bobAuth,
    });
    assert.equal(bobReveal.status, 403);

    const audit = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/v1/audit',
      headers: adminAuth,
    });
    assert.equal(audit.status, 200);
    const actions = new Set((audit.json?.data || []).map((a) => a.action));
    assert.ok(actions.has('SECRET_CREATED'));
    assert.ok(actions.has('SECRET_UPDATED'));
    assert.ok(actions.has('SECRET_DELETED'));
    assert.ok(actions.has('SECRET_RESTORED'));

    const auditVerify = await requestJson({
      method: 'GET',
      port,
      pathName: '/api/v1/audit/verify',
      headers: adminAuth,
    });
    assert.equal(auditVerify.status, 200);
    assert.equal(auditVerify.json?.data?.ok, true);

    console.log('API integration test passed');
  } finally {
    server.close();
    await once(server, 'close');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

















