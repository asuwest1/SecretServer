import { spawnSync } from 'node:child_process';
import { Store } from './store.js';

function sqlLiteral(value) {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number') return String(value);
  const text = String(value).replace(/'/g, "''");
  return `N'${text}'`;
}

function jsonLiteral(value) {
  if (value === null || value === undefined) return 'NULL';
  return sqlLiteral(JSON.stringify(value));
}

function parseJsonOutput(raw) {
  const trimmed = (raw || '').trim();
  if (!trimmed) return [];
  const lines = trimmed.split(/\r?\n/).map((x) => x.trim()).filter((x) => x.length > 0);
  const payload = lines.join('');
  try {
    return JSON.parse(payload || '[]');
  } catch {
    return [];
  }
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalize(value) {
  if (Array.isArray(value)) {
    return value.map((v) => normalize(v));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = normalize(value[key]);
    }
    return out;
  }
  return value;
}

function stableString(value) {
  return JSON.stringify(normalize(value));
}

function diffRows(currentRows, persistedRows, keyFn) {
  const currentMap = new Map(currentRows.map((row) => [keyFn(row), row]));
  const persistedMap = new Map(persistedRows.map((row) => [keyFn(row), row]));

  const upserts = [];
  const deletes = [];

  for (const [key, row] of currentMap) {
    const prev = persistedMap.get(key);
    if (!prev || stableString(prev) !== stableString(row)) {
      upserts.push(row);
    }
  }

  for (const [key, row] of persistedMap) {
    if (!currentMap.has(key)) {
      deletes.push(row);
    }
  }

  return { upserts, deletes };
}

function mergeSql({ table, keyColumns, allColumns, row }) {
  const selectCols = allColumns.map((c) => `${c.value(row)} AS ${c.db}`).join(', ');
  const onClause = keyColumns.map((k) => `target.${k} = source.${k}`).join(' AND ');
  const updateCols = allColumns.filter((c) => !keyColumns.includes(c.db)).map((c) => `${c.db} = source.${c.db}`).join(', ');
  const insertCols = allColumns.map((c) => c.db).join(', ');
  const insertVals = allColumns.map((c) => `source.${c.db}`).join(', ');

  if (!updateCols) {
    return `
MERGE ${table} AS target
USING (SELECT ${selectCols}) AS source
ON ${onClause}
WHEN NOT MATCHED THEN
  INSERT (${insertCols}) VALUES (${insertVals});
`;
  }

  return `
MERGE ${table} AS target
USING (SELECT ${selectCols}) AS source
ON ${onClause}
WHEN MATCHED THEN
  UPDATE SET ${updateCols}
WHEN NOT MATCHED THEN
  INSERT (${insertCols}) VALUES (${insertVals});
`;
}

function deleteSql({ table, keyColumns, row, keyValueMap }) {
  const where = keyColumns.map((k) => ` ${k} = ${keyValueMap(k, row)} `).join(' AND ');
  return `DELETE FROM ${table} WHERE ${where};`;
}

export class SqlStore extends Store {
  constructor(sqlConfig, logger) {
    super();
    this.sql = sqlConfig;
    this.logger = logger;
    this.persistedState = this.snapshot();
    this.persistedAuditId = 0;
  }

  runSql(query) {
    const args = ['-S', this.sql.server, '-d', this.sql.database, '-h', '-1', '-W', '-y', '0', '-Y', '0', '-Q', query];
    if (this.sql.trustServerCertificate) {
      args.push('-C');
    }
    if (this.sql.username) {
      args.push('-U', this.sql.username, '-P', this.sql.password);
    } else {
      args.push('-E');
    }

    const result = spawnSync(this.sql.sqlcmdPath, args, { encoding: 'utf8' });
    if (result.status !== 0) {
      throw new Error(result.stderr || result.stdout || 'SQLCMD_FAILED');
    }
    return result.stdout || '';
  }

  runJsonQuery(query) {
    return parseJsonOutput(this.runSql(query));
  }

  ensureRuntimeTables() {
    const q = `
SET NOCOUNT ON;
IF OBJECT_ID('schema_migrations','U') IS NULL
BEGIN
  CREATE TABLE schema_migrations (
    version NVARCHAR(64) NOT NULL PRIMARY KEY,
    applied_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
  );
END;
IF COL_LENGTH('users', 'mfa_pending_secret_enc') IS NULL
  ALTER TABLE users ADD mfa_pending_secret_enc NVARCHAR(MAX) NULL;
IF COL_LENGTH('users', 'last_login_at') IS NULL
  ALTER TABLE users ADD last_login_at DATETIME2 NULL;
IF OBJECT_ID('refresh_sessions','U') IS NULL
BEGIN
  CREATE TABLE refresh_sessions (
    jti NVARCHAR(128) NOT NULL PRIMARY KEY,
    parent_jti NVARCHAR(128) NULL,
    user_id UNIQUEIDENTIFIER NOT NULL,
    token_hash NVARCHAR(256) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    created_at DATETIME2 NOT NULL,
    revoked_at DATETIME2 NULL,
    last_used_at DATETIME2 NULL
  );
END;
IF OBJECT_ID('revoked_token_jti','U') IS NULL
BEGIN
  CREATE TABLE revoked_token_jti (
    jti NVARCHAR(128) NOT NULL PRIMARY KEY,
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
  );
END;
`;
    this.runSql(q);
  }


  getAppliedMigrations() {
    const rows = this.runJsonQuery("SET NOCOUNT ON; SELECT version, applied_at AS appliedAt FROM schema_migrations ORDER BY version FOR JSON PATH, INCLUDE_NULL_VALUES;");
    return rows || [];
  }
  async load() {
    this.ensureRuntimeTables();

    this.users = this.runJsonQuery("SET NOCOUNT ON; SELECT id, username, display_name AS displayName, email, password_hash AS passwordHash, mfa_enabled AS mfaEnabled, mfa_secret_enc AS mfaSecretEnc, mfa_pending_secret_enc AS mfaPendingSecretEnc, is_active AS isActive, is_super_admin AS isSuperAdmin, failed_attempts AS failedAttempts, locked_until AS lockedUntil, created_at AS createdAt, updated_at AS updatedAt, last_login_at AS lastLoginAt FROM users FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((u) => ({ ...u, mfaSecretEnc: u.mfaSecretEnc ? JSON.parse(u.mfaSecretEnc) : null, mfaPendingSecretEnc: u.mfaPendingSecretEnc ? JSON.parse(u.mfaPendingSecretEnc) : null, mfaEnabled: !!u.mfaEnabled, isActive: !!u.isActive, isSuperAdmin: !!u.isSuperAdmin }));

    this.roles = this.runJsonQuery("SET NOCOUNT ON; SELECT id, name, description, created_at AS createdAt, updated_at AS updatedAt FROM roles FOR JSON PATH, INCLUDE_NULL_VALUES;");
    this.userRoles = this.runJsonQuery("SET NOCOUNT ON; SELECT user_id AS userId, role_id AS roleId, assigned_at AS assignedAt, assigned_by AS assignedBy FROM user_roles FOR JSON PATH, INCLUDE_NULL_VALUES;");
    this.folders = this.runJsonQuery("SET NOCOUNT ON; SELECT id, name, parent_folder_id AS parentFolderId, created_by AS createdBy, created_at AS createdAt, updated_at AS updatedAt FROM folders FOR JSON PATH, INCLUDE_NULL_VALUES;");

    this.secrets = this.runJsonQuery("SET NOCOUNT ON; SELECT id, folder_id AS folderId, name, secret_type AS secretType, username, url, notes_enc AS notesEnc, tags, value_enc AS valueEnc, dek_enc AS dekEnc, is_deleted AS isDeleted, deleted_at AS deletedAt, purge_after AS purgeAfter, created_by AS createdBy, created_at AS createdAt, updated_by AS updatedBy, updated_at AS updatedAt FROM secrets FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((s) => ({ ...s, tags: s.tags ? JSON.parse(s.tags) : [], valueEnc: JSON.parse(s.valueEnc), dekEnc: JSON.parse(s.dekEnc), notesEnc: s.notesEnc ? JSON.parse(s.notesEnc) : null, isDeleted: !!s.isDeleted }));

    this.secretVersions = this.runJsonQuery("SET NOCOUNT ON; SELECT id, secret_id AS secretId, version_num AS versionNum, value_enc AS valueEnc, dek_enc AS dekEnc, changed_by AS changedBy, changed_at AS changedAt FROM secret_versions FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((v) => ({ ...v, valueEnc: JSON.parse(v.valueEnc), dekEnc: JSON.parse(v.dekEnc) }));

    this.secretAcl = this.runJsonQuery("SET NOCOUNT ON; SELECT secret_id AS secretId, role_id AS roleId, can_add AS canAdd, can_view AS canView, can_change AS canChange, can_delete AS canDelete FROM secret_acl FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((x) => ({ ...x, canAdd: !!x.canAdd, canView: !!x.canView, canChange: !!x.canChange, canDelete: !!x.canDelete }));

    this.folderAcl = this.runJsonQuery("SET NOCOUNT ON; SELECT folder_id AS folderId, role_id AS roleId, can_add AS canAdd, can_view AS canView, can_change AS canChange, can_delete AS canDelete FROM folder_acl FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((x) => ({ ...x, canAdd: !!x.canAdd, canView: !!x.canView, canChange: !!x.canChange, canDelete: !!x.canDelete }));

    this.apiTokens = this.runJsonQuery("SET NOCOUNT ON; SELECT id, user_id AS userId, name, scopes, token_hash AS tokenHash, last_used AS lastUsed, expires_at AS expiresAt, created_at AS createdAt FROM api_tokens FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((t) => ({ ...t, scopes: t.scopes ? JSON.parse(t.scopes) : ['read'] }));

    this.auditLog = this.runJsonQuery("SET NOCOUNT ON; SELECT id, event_time AS eventTime, user_id AS userId, username, action, resource, resource_id AS resourceId, secret_name AS secretName, ip_address AS ipAddress, user_agent AS userAgent, detail FROM audit_log ORDER BY id FOR JSON PATH, INCLUDE_NULL_VALUES;")
      .map((a) => ({ ...a, detail: a.detail ? JSON.parse(a.detail) : null }));

    this.refreshSessions = this.runJsonQuery("SET NOCOUNT ON; SELECT jti, parent_jti AS parentJti, user_id AS userId, token_hash AS tokenHash, expires_at AS expiresAt, created_at AS createdAt, revoked_at AS revokedAt, last_used_at AS lastUsedAt FROM refresh_sessions FOR JSON PATH, INCLUDE_NULL_VALUES;");
    this.revokedTokenJti = this.runJsonQuery("SET NOCOUNT ON; SELECT jti FROM revoked_token_jti FOR JSON PATH, INCLUDE_NULL_VALUES;").map((x) => x.jti);

    this.auditSequence = this.auditLog.length > 0 ? Math.max(...this.auditLog.map((a) => Number(a.id) || 0)) : 0;
    this.persistedAuditId = this.auditSequence;
    this.persistedState = deepClone(this.snapshot());
  }

  async flush() {
    const statements = [];
    const current = this.snapshot();
    const persisted = this.persistedState;

    const plans = [
      {
        currentRows: current.users,
        persistedRows: persisted.users,
        keyFn: (r) => r.id,
        table: 'users',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'username', value: (r) => sqlLiteral(r.username) },
          { db: 'display_name', value: (r) => sqlLiteral(r.displayName) },
          { db: 'email', value: (r) => sqlLiteral(r.email) },
          { db: 'password_hash', value: (r) => sqlLiteral(r.passwordHash || '') },
          { db: 'mfa_secret_enc', value: (r) => jsonLiteral(r.mfaSecretEnc) },
          { db: 'mfa_pending_secret_enc', value: (r) => jsonLiteral(r.mfaPendingSecretEnc) },
          { db: 'mfa_enabled', value: (r) => sqlLiteral(!!r.mfaEnabled) },
          { db: 'is_active', value: (r) => sqlLiteral(!!r.isActive) },
          { db: 'is_super_admin', value: (r) => sqlLiteral(!!r.isSuperAdmin) },
          { db: 'failed_attempts', value: (r) => sqlLiteral(r.failedAttempts || 0) },
          { db: 'locked_until', value: (r) => sqlLiteral(r.lockedUntil) },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
          { db: 'updated_at', value: (r) => sqlLiteral(r.updatedAt) },
          { db: 'last_login_at', value: (r) => sqlLiteral(r.lastLoginAt) },
        ],
        deleteValue: (col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.roles,
        persistedRows: persisted.roles,
        keyFn: (r) => r.id,
        table: 'roles',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'name', value: (r) => sqlLiteral(r.name) },
          { db: 'description', value: (r) => sqlLiteral(r.description || '') },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
          { db: 'updated_at', value: (r) => sqlLiteral(r.updatedAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.userRoles,
        persistedRows: persisted.userRoles,
        keyFn: (r) => `${r.userId}|${r.roleId}`,
        table: 'user_roles',
        keyColumns: ['user_id', 'role_id'],
        allColumns: [
          { db: 'user_id', value: (r) => sqlLiteral(r.userId) },
          { db: 'role_id', value: (r) => sqlLiteral(r.roleId) },
          { db: 'assigned_at', value: (r) => sqlLiteral(r.assignedAt) },
          { db: 'assigned_by', value: (r) => sqlLiteral(r.assignedBy) },
        ],
        deleteValue: (col, row) => sqlLiteral(col === 'user_id' ? row.userId : row.roleId),
      },
      {
        currentRows: current.folders,
        persistedRows: persisted.folders,
        keyFn: (r) => r.id,
        table: 'folders',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'name', value: (r) => sqlLiteral(r.name) },
          { db: 'parent_folder_id', value: (r) => sqlLiteral(r.parentFolderId) },
          { db: 'created_by', value: (r) => sqlLiteral(r.createdBy) },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
          { db: 'updated_at', value: (r) => sqlLiteral(r.updatedAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.secrets,
        persistedRows: persisted.secrets,
        keyFn: (r) => r.id,
        table: 'secrets',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'folder_id', value: (r) => sqlLiteral(r.folderId) },
          { db: 'name', value: (r) => sqlLiteral(r.name) },
          { db: 'secret_type', value: (r) => sqlLiteral(r.secretType) },
          { db: 'username', value: (r) => sqlLiteral(r.username) },
          { db: 'url', value: (r) => sqlLiteral(r.url) },
          { db: 'notes_enc', value: (r) => jsonLiteral(r.notesEnc) },
          { db: 'tags', value: (r) => jsonLiteral(r.tags || []) },
          { db: 'value_enc', value: (r) => jsonLiteral(r.valueEnc) },
          { db: 'dek_enc', value: (r) => jsonLiteral(r.dekEnc) },
          { db: 'is_deleted', value: (r) => sqlLiteral(!!r.isDeleted) },
          { db: 'deleted_at', value: (r) => sqlLiteral(r.deletedAt) },
          { db: 'purge_after', value: (r) => sqlLiteral(r.purgeAfter) },
          { db: 'created_by', value: (r) => sqlLiteral(r.createdBy) },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
          { db: 'updated_by', value: (r) => sqlLiteral(r.updatedBy) },
          { db: 'updated_at', value: (r) => sqlLiteral(r.updatedAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.secretVersions,
        persistedRows: persisted.secretVersions,
        keyFn: (r) => r.id,
        table: 'secret_versions',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'secret_id', value: (r) => sqlLiteral(r.secretId) },
          { db: 'version_num', value: (r) => sqlLiteral(r.versionNum) },
          { db: 'value_enc', value: (r) => jsonLiteral(r.valueEnc) },
          { db: 'dek_enc', value: (r) => jsonLiteral(r.dekEnc) },
          { db: 'changed_by', value: (r) => sqlLiteral(r.changedBy) },
          { db: 'changed_at', value: (r) => sqlLiteral(r.changedAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.secretAcl,
        persistedRows: persisted.secretAcl,
        keyFn: (r) => `${r.secretId}|${r.roleId}`,
        table: 'secret_acl',
        keyColumns: ['secret_id', 'role_id'],
        allColumns: [
          { db: 'secret_id', value: (r) => sqlLiteral(r.secretId) },
          { db: 'role_id', value: (r) => sqlLiteral(r.roleId) },
          { db: 'can_add', value: (r) => sqlLiteral(!!r.canAdd) },
          { db: 'can_view', value: (r) => sqlLiteral(!!r.canView) },
          { db: 'can_change', value: (r) => sqlLiteral(!!r.canChange) },
          { db: 'can_delete', value: (r) => sqlLiteral(!!r.canDelete) },
        ],
        deleteValue: (col, row) => sqlLiteral(col === 'secret_id' ? row.secretId : row.roleId),
      },
      {
        currentRows: current.folderAcl,
        persistedRows: persisted.folderAcl,
        keyFn: (r) => `${r.folderId}|${r.roleId}`,
        table: 'folder_acl',
        keyColumns: ['folder_id', 'role_id'],
        allColumns: [
          { db: 'folder_id', value: (r) => sqlLiteral(r.folderId) },
          { db: 'role_id', value: (r) => sqlLiteral(r.roleId) },
          { db: 'can_add', value: (r) => sqlLiteral(!!r.canAdd) },
          { db: 'can_view', value: (r) => sqlLiteral(!!r.canView) },
          { db: 'can_change', value: (r) => sqlLiteral(!!r.canChange) },
          { db: 'can_delete', value: (r) => sqlLiteral(!!r.canDelete) },
        ],
        deleteValue: (col, row) => sqlLiteral(col === 'folder_id' ? row.folderId : row.roleId),
      },
      {
        currentRows: current.apiTokens,
        persistedRows: persisted.apiTokens,
        keyFn: (r) => r.id,
        table: 'api_tokens',
        keyColumns: ['id'],
        allColumns: [
          { db: 'id', value: (r) => sqlLiteral(r.id) },
          { db: 'user_id', value: (r) => sqlLiteral(r.userId) },
          { db: 'name', value: (r) => sqlLiteral(r.name) },
          { db: 'token_hash', value: (r) => sqlLiteral(r.tokenHash) },
          { db: 'last_used', value: (r) => sqlLiteral(r.lastUsed) },
          { db: 'expires_at', value: (r) => sqlLiteral(r.expiresAt) },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.id),
      },
      {
        currentRows: current.refreshSessions,
        persistedRows: persisted.refreshSessions,
        keyFn: (r) => r.jti,
        table: 'refresh_sessions',
        keyColumns: ['jti'],
        allColumns: [
          { db: 'jti', value: (r) => sqlLiteral(r.jti) },
          { db: 'parent_jti', value: (r) => sqlLiteral(r.parentJti) },
          { db: 'user_id', value: (r) => sqlLiteral(r.userId) },
          { db: 'token_hash', value: (r) => sqlLiteral(r.tokenHash) },
          { db: 'expires_at', value: (r) => sqlLiteral(r.expiresAt) },
          { db: 'created_at', value: (r) => sqlLiteral(r.createdAt) },
          { db: 'revoked_at', value: (r) => sqlLiteral(r.revokedAt) },
          { db: 'last_used_at', value: (r) => sqlLiteral(r.lastUsedAt) },
        ],
        deleteValue: (_col, row) => sqlLiteral(row.jti),
      },
      {
        currentRows: current.revokedTokenJti.map((jti) => ({ jti })),
        persistedRows: persisted.revokedTokenJti.map((jti) => ({ jti })),
        keyFn: (r) => r.jti,
        table: 'revoked_token_jti',
        keyColumns: ['jti'],
        allColumns: [{ db: 'jti', value: (r) => sqlLiteral(r.jti) }],
        deleteValue: (_col, row) => sqlLiteral(row.jti),
      },
    ];

    for (const plan of plans) {
      const { upserts, deletes } = diffRows(plan.currentRows, plan.persistedRows, plan.keyFn);
      for (const row of upserts) {
        statements.push(mergeSql({ table: plan.table, keyColumns: plan.keyColumns, allColumns: plan.allColumns, row }));
      }
      for (const row of deletes) {
        statements.push(deleteSql({ table: plan.table, keyColumns: plan.keyColumns, row, keyValueMap: plan.deleteValue }));
      }
    }

    const newAudit = current.auditLog.filter((a) => Number(a.id) > this.persistedAuditId);
    for (const a of newAudit) {
      statements.push(`INSERT INTO audit_log (event_time, user_id, username, action, resource, resource_id, secret_name, ip_address, user_agent, detail)
VALUES (${sqlLiteral(a.eventTime)}, ${sqlLiteral(a.userId)}, ${sqlLiteral(a.username)}, ${sqlLiteral(a.action)}, ${sqlLiteral(a.resource)}, ${sqlLiteral(a.resourceId)}, ${sqlLiteral(a.secretName)}, ${sqlLiteral(a.ipAddress)}, ${sqlLiteral(a.userAgent)}, ${jsonLiteral(a.detail)});`);
    }

    if (statements.length === 0) {
      return;
    }

    const query = `
SET XACT_ABORT ON;
BEGIN TRAN;
${statements.join('\n')}
COMMIT TRAN;
`;

    try {
      this.runSql(query);
      if (newAudit.length > 0) {
        this.persistedAuditId = Math.max(...newAudit.map((a) => Number(a.id) || 0), this.persistedAuditId);
      }
      this.persistedState = deepClone(current);
    } catch (err) {
      this.logger.error('sql_store_flush_failed', { error: err.message });
      throw err;
    }
  }
}




