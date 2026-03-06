import assert from 'node:assert/strict';
import { SqlStore } from '../src/api/data/sql-store.js';
import { hashPassword } from '../src/api/lib/password.js';
import { applyMigrations, createSqlConfig } from './sql-test-utils.js';

async function main() {
  applyMigrations();

  const logger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
  const store = new SqlStore(createSqlConfig(), logger);
  await store.load();

  const migrations = store.getAppliedMigrations();
  assert.ok(migrations.find((m) => m.version === '001_initial_schema'));
  assert.ok(migrations.find((m) => m.version === '002_indexes'));
  assert.ok(migrations.find((m) => m.version === '003_token_scopes_cleanup'));

  const userId = '00000000-0000-0000-0000-00000000aa01';
  const roleId = '00000000-0000-0000-0000-00000000bb01';
  const folderId = '00000000-0000-0000-0000-00000000cc01';
  const secretId = '00000000-0000-0000-0000-00000000dd01';

  store.users.push({
    id: userId,
    username: 'integration-admin',
    displayName: 'Integration Admin',
    email: 'integration-admin@example.test',
    passwordHash: await hashPassword('StrongPass!123'),
    mfaEnabled: false,
    mfaSecretEnc: null,
    mfaPendingSecretEnc: null,
    isActive: true,
    isSuperAdmin: true,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastLoginAt: null,
  });

  store.roles.push({
    id: roleId,
    name: 'Integration-Role',
    description: 'integration role',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  store.userRoles.push({ userId, roleId, assignedAt: new Date().toISOString(), assignedBy: userId });
  store.folders.push({ id: folderId, name: 'Integration-Folder', parentFolderId: null, createdBy: userId, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  store.secrets.push({
    id: secretId,
    folderId,
    name: 'Integration-Secret',
    secretType: 'password',
    username: 'svc-user',
    url: 'https://example.test',
    notesEnc: { ciphertext: 'A', nonce: 'B', tag: 'C' },
    tags: ['integration'],
    valueEnc: { ciphertext: 'D', nonce: 'E', tag: 'F' },
    dekEnc: { ciphertext: 'G', nonce: 'H', tag: 'I' },
    isDeleted: false,
    deletedAt: null,
    purgeAfter: null,
    createdBy: userId,
    createdAt: new Date().toISOString(),
    updatedBy: userId,
    updatedAt: new Date().toISOString(),
  });

  store.appendAudit({ userId, username: 'integration-admin', action: 'INTEGRATION_TEST_EVENT', resource: 'system', resourceId: null });
  await store.flush();

  const reload = new SqlStore(createSqlConfig(), logger);
  await reload.load();
  const persistedUser = reload.users.find((u) => u.id === userId);
  assert.ok(persistedUser, 'user persisted after flush');

  persistedUser.displayName = 'Integration Admin Updated';
  reload.appendAudit({ userId, username: 'integration-admin', action: 'INTEGRATION_TEST_EVENT_2', resource: 'system', resourceId: null });
  await reload.flush();

  const reload2 = new SqlStore(createSqlConfig(), logger);
  await reload2.load();
  const updated = reload2.users.find((u) => u.id === userId);
  assert.equal(updated.displayName, 'Integration Admin Updated');
  assert.ok(reload2.auditLog.find((a) => a.action === 'INTEGRATION_TEST_EVENT_2'));

  console.log('SQL integration test passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
