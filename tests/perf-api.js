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

const tempDir = path.join(process.cwd(), '.tmp-test');
fs.mkdirSync(tempDir, { recursive: true });

function createLogger() {
  return { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
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
        resolve({ status: res.statusCode || 0, json });
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

async function timeOperation(fn) {
  const started = process.hrtime.bigint();
  await fn();
  const ended = process.hrtime.bigint();
  return Number(ended - started) / 1_000_000;
}

async function runLoad({ iterations, concurrency, operation }) {
  const latencies = [];
  const workers = [];
  const perWorker = Math.ceil(iterations / concurrency);

  for (let i = 0; i < concurrency; i += 1) {
    workers.push((async () => {
      for (let j = 0; j < perWorker; j += 1) {
        if (latencies.length >= iterations) break;
        latencies.push(await timeOperation(operation));
      }
    })());
  }

  await Promise.all(workers);
  return {
    count: latencies.length,
    p95Ms: Number(percentile(latencies, 95).toFixed(2)),
    p99Ms: Number(percentile(latencies, 99).toFixed(2)),
    avgMs: Number((latencies.reduce((a, b) => a + b, 0) / Math.max(1, latencies.length)).toFixed(2)),
  };
}

async function main() {
  const iterations = Number.parseInt(process.env.PERF_ITERATIONS || '120', 10);
  const concurrency = Number.parseInt(process.env.PERF_CONCURRENCY || '12', 10);

  const config = {
    issuer: 'SecretServer',
    lockoutThreshold: 50,
    lockoutDurationMinutes: 1,
    requireMfa: false,
    ldap: { enabled: false, fallbackLocal: true },
    openApi: { internalOnly: false, trustProxy: false },
  };

  const logger = createLogger();
  const crypto = new CryptoService({ keyFilePath: path.join(tempDir, 'perf-master.key') });
  const tokenService = new TokenService({
    jwtSigningKeyPath: path.join(tempDir, 'perf-jwt.key'),
    accessTokenLifetimeMinutes: 30,
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

  const server = http.createServer(async (req, res) => {
    try {
      const handled = await router.handle(req, res, ctx);
      if (!handled) notFound(res);
    } catch (err) {
      if (err.code === 'INVALID_JSON') {
        sendError(res, 400, 'INVALID_JSON', 'Malformed JSON request body.', 'perf');
      } else if (err.code === 'PAYLOAD_TOO_LARGE') {
        sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'Request payload exceeds allowed size.', 'perf');
      } else {
        throw err;
      }
    }
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;

  try {
    const adminLogin = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'superadmin', password: 'ChangeMeNow!123' },
    });
    assert.equal(adminLogin.status, 200);
    const adminAuth = { Authorization: `Bearer ${adminLogin.json.data.accessToken}` };

    const role = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/roles',
      headers: adminAuth,
      body: { name: 'PerfRole', description: 'perf role' },
    });
    assert.equal(role.status, 201);

    const user = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/users',
      headers: adminAuth,
      body: {
        username: 'perfuser',
        password: 'StrongPass!123',
        displayName: 'Perf User',
        email: 'perf@example.test',
      },
    });
    assert.equal(user.status, 201);

    await requestJson({
      method: 'POST',
      port,
      pathName: `/api/v1/roles/${role.json.data.id}/members`,
      headers: adminAuth,
      body: { userId: user.json.data.id },
    });

    const folder = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/folders',
      headers: adminAuth,
      body: { name: 'PerfFolder' },
    });
    assert.equal(folder.status, 201);

    await requestJson({
      method: 'PUT',
      port,
      pathName: `/api/v1/folders/${folder.json.data.id}/acl`,
      headers: adminAuth,
      body: { entries: [{ roleId: role.json.data.id, canAdd: true, canView: true, canChange: true, canDelete: true }] },
    });

    const userLogin = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/auth/login',
      body: { username: 'perfuser', password: 'StrongPass!123' },
    });
    assert.equal(userLogin.status, 200);
    const userAuth = { Authorization: `Bearer ${userLogin.json.data.accessToken}` };

    const secret = await requestJson({
      method: 'POST',
      port,
      pathName: '/api/v1/secrets',
      headers: userAuth,
      body: { folderId: folder.json.data.id, name: 'PerfSecret', value: 'PerfValue', notes: 'perf-notes', tags: ['perf'] },
    });
    assert.equal(secret.status, 201);

    const loginMetrics = await runLoad({
      iterations: Math.min(iterations, 8),
      concurrency: 1,
      operation: async () => {
        const res = await requestJson({
          method: 'POST',
          port,
          pathName: '/api/v1/auth/login',
          body: { username: 'perfuser', password: 'StrongPass!123' },
        });
        if (res.status !== 200) throw new Error('login failed');
      },
    });

    const listMetrics = await runLoad({
      iterations,
      concurrency,
      operation: async () => {
        const res = await requestJson({ method: 'GET', port, pathName: '/api/v1/secrets', headers: userAuth });
        if (res.status !== 200) throw new Error('list failed');
      },
    });

    const searchMetrics = await runLoad({
      iterations,
      concurrency,
      operation: async () => {
        const res = await requestJson({ method: 'GET', port, pathName: '/api/v1/secrets?q=perf', headers: userAuth });
        if (res.status !== 200) throw new Error('search failed');
      },
    });

    const revealMetrics = await runLoad({
      iterations,
      concurrency,
      operation: async () => {
        const res = await requestJson({ method: 'GET', port, pathName: `/api/v1/secrets/${secret.json.data.id}/value`, headers: userAuth });
        if (res.status !== 200) throw new Error('reveal failed');
      },
    });

    const report = {
      generatedAt: new Date().toISOString(),
      iterations,
      concurrency,
      metrics: {
        authLogin: loginMetrics,
        secretList: listMetrics,
        secretSearch: searchMetrics,
        secretReveal: revealMetrics,
      },
    };

    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } finally {
    server.close();
    await once(server, 'close');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

