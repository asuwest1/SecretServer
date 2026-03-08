import crypto from 'node:crypto';

function nowIso() {
  return new Date().toISOString();
}

function cloneState(state) {
  return JSON.parse(JSON.stringify(state));
}

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map((x) => stableValue(x));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = stableValue(value[key]);
    }
    return out;
  }
  return value;
}

function auditDigest(payload) {
  const data = JSON.stringify(stableValue(payload));
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sanitizeDetail(detail) {
  if (!detail || typeof detail !== 'object' || Array.isArray(detail)) {
    return {};
  }
  const clone = { ...detail };
  if (clone.integrity) {
    delete clone.integrity;
  }
  return clone;
}

const MAX_REFRESH_SESSIONS = 200000;
const MAX_REVOKED_JTI = 200000;

export class Store {
  constructor() {
    this.users = [];
    this.roles = [];
    this.userRoles = [];
    this.folders = [];
    this.folderAcl = [];
    this.secrets = [];
    this.secretAcl = [];
    this.secretVersions = [];
    this.apiTokens = [];
    this.auditLog = [];

    this.refreshSessions = [];
    this.revokedTokenJti = [];
    this.auditSequence = 0;
  }

  snapshot() {
    return {
      users: this.users,
      roles: this.roles,
      userRoles: this.userRoles,
      folders: this.folders,
      folderAcl: this.folderAcl,
      secrets: this.secrets,
      secretAcl: this.secretAcl,
      secretVersions: this.secretVersions,
      apiTokens: this.apiTokens,
      auditLog: this.auditLog,
      refreshSessions: this.refreshSessions,
      revokedTokenJti: this.revokedTokenJti,
      auditSequence: this.auditSequence,
    };
  }

  restore(snapshot) {
    this.users = snapshot.users || [];
    this.roles = snapshot.roles || [];
    this.userRoles = snapshot.userRoles || [];
    this.folders = snapshot.folders || [];
    this.folderAcl = snapshot.folderAcl || [];
    this.secrets = snapshot.secrets || [];
    this.secretAcl = snapshot.secretAcl || [];
    this.secretVersions = snapshot.secretVersions || [];
    this.apiTokens = snapshot.apiTokens || [];
    this.auditLog = snapshot.auditLog || [];
    this.refreshSessions = snapshot.refreshSessions || [];
    this.revokedTokenJti = snapshot.revokedTokenJti || [];
    this.auditSequence = snapshot.auditSequence || this.auditLog.length;
  }

  async runInTransaction(operation) {
    const backup = cloneState(this.snapshot());
    try {
      const result = await operation();
      await this.flush();
      return result;
    } catch (err) {
      this.restore(backup);
      throw err;
    }
  }

  seedSuperAdmin({ username, passwordHash }) {
    if (this.users.length > 0) {
      return;
    }
    const user = {
      id: crypto.randomUUID(),
      username,
      displayName: 'Super Admin',
      email: 'superadmin@local',
      passwordHash,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaPendingSecretEnc: null,
      isActive: true,
      isSuperAdmin: true,
      failedAttempts: 0,
      lockedUntil: null,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      lastLoginAt: null,
    };
    this.users.push(user);
    this.appendAudit({ action: 'USER_CREATED', userId: user.id, username: user.username, resource: 'user', resourceId: user.id });
  }

  appendAudit(entry) {
    this.auditSequence += 1;

    const previous = this.auditLog[this.auditLog.length - 1] || null;
    const prevHash = previous?.integrityHash || previous?.detail?.integrity?.hash || null;
    const userDetail = sanitizeDetail(entry?.detail);

    const baseRecord = {
      id: this.auditSequence,
      eventTime: nowIso(),
      ...entry,
      detail: userDetail,
    };

    const integrityHash = auditDigest({
      id: baseRecord.id,
      eventTime: baseRecord.eventTime,
      userId: baseRecord.userId || null,
      username: baseRecord.username || null,
      action: baseRecord.action || null,
      resource: baseRecord.resource || null,
      resourceId: baseRecord.resourceId || null,
      secretName: baseRecord.secretName || null,
      ipAddress: baseRecord.ipAddress || null,
      userAgent: baseRecord.userAgent || null,
      detail: userDetail,
      prevHash,
    });

    const record = {
      ...baseRecord,
      integrityHash,
      detail: {
        ...userDetail,
        integrity: {
          algorithm: 'sha256',
          prevHash,
          hash: integrityHash,
        },
      },
    };

    this.auditLog.push(record);
    return record;
  }

  verifyAuditIntegrity(records = this.auditLog) {
    let previousHash = null;

    for (let i = 0; i < records.length; i += 1) {
      const current = records[i];
      const currentDetail = sanitizeDetail(current.detail);
      const actual = current.integrityHash || current.detail?.integrity?.hash || null;
      const expected = auditDigest({
        id: current.id,
        eventTime: current.eventTime,
        userId: current.userId || null,
        username: current.username || null,
        action: current.action || null,
        resource: current.resource || null,
        resourceId: current.resourceId || null,
        secretName: current.secretName || null,
        ipAddress: current.ipAddress || null,
        userAgent: current.userAgent || null,
        detail: currentDetail,
        prevHash: previousHash,
      });

      if (!actual || actual !== expected) {
        return { ok: false, index: i, id: current.id || null, expectedHash: expected, actualHash: actual };
      }

      previousHash = actual;
    }

    return { ok: true, count: records.length, latestHash: previousHash };
  }

  rechainAuditLog() {
    let prevHash = null;
    for (const record of this.auditLog) {
      const userDetail = sanitizeDetail(record.detail);
      const hash = auditDigest({
        id: record.id,
        eventTime: record.eventTime,
        userId: record.userId || null,
        username: record.username || null,
        action: record.action || null,
        resource: record.resource || null,
        resourceId: record.resourceId || null,
        secretName: record.secretName || null,
        ipAddress: record.ipAddress || null,
        userAgent: record.userAgent || null,
        detail: userDetail,
        prevHash,
      });
      record.integrityHash = hash;
      record.detail = {
        ...userDetail,
        integrity: {
          algorithm: 'sha256',
          prevHash,
          hash,
        },
      };
      prevHash = hash;
    }
  }

  enforceAuditRetention({ retentionDays = 90, maxEntries = 200000 } = {}) {
    const now = Date.now();
    const minTime = now - Math.max(1, retentionDays) * 24 * 60 * 60 * 1000;

    this.auditLog = this.auditLog.filter((record) => {
      const ts = new Date(record.eventTime).getTime();
      return Number.isFinite(ts) && ts >= minTime;
    });

    if (this.auditLog.length > maxEntries) {
      this.auditLog = this.auditLog.slice(this.auditLog.length - maxEntries);
    }

    this.rechainAuditLog();
    this.auditSequence = this.auditLog.length > 0 ? Math.max(...this.auditLog.map((a) => Number(a.id) || 0)) : 0;
  }

  enforceSessionRetention() {
    const now = Date.now();
    this.refreshSessions = this.refreshSessions.filter((s) => {
      const expiry = s.expiresAt ? new Date(s.expiresAt).getTime() : null;
      const revoked = s.revokedAt ? new Date(s.revokedAt).getTime() : null;
      if (!Number.isFinite(expiry)) return true;
      if (expiry > now) return true;
      if (revoked && now - revoked < 24 * 60 * 60 * 1000) return true;
      return false;
    });

    if (this.refreshSessions.length > MAX_REFRESH_SESSIONS) {
      this.refreshSessions = this.refreshSessions.slice(this.refreshSessions.length - MAX_REFRESH_SESSIONS);
    }

    if (this.revokedTokenJti.length > MAX_REVOKED_JTI) {
      this.revokedTokenJti = this.revokedTokenJti.slice(this.revokedTokenJti.length - MAX_REVOKED_JTI);
    }
  }

  addRefreshSession(session) {
    this.refreshSessions.push(session);
    this.enforceSessionRetention();
  }

  findRefreshSession(jti) {
    return this.refreshSessions.find((s) => s.jti === jti && !s.revokedAt) || null;
  }

  revokeSession(jti) {
    const session = this.refreshSessions.find((s) => s.jti === jti);
    if (session && !session.revokedAt) {
      session.revokedAt = nowIso();
    }
    if (!this.revokedTokenJti.includes(jti)) {
      this.revokedTokenJti.push(jti);
    }
    this.enforceSessionRetention();
  }

  revokeUserSessions(userId) {
    for (const session of this.refreshSessions) {
      if (session.userId === userId && !session.revokedAt) {
        session.revokedAt = nowIso();
        if (!this.revokedTokenJti.includes(session.jti)) {
          this.revokedTokenJti.push(session.jti);
        }
      }
    }
    this.enforceSessionRetention();
  }

  isRevokedJti(jti) {
    return this.revokedTokenJti.includes(jti);
  }

  findApiTokenByHash(tokenHash) {
    return this.apiTokens.find((t) => t.tokenHash === tokenHash) || null;
  }

  touchApiToken(tokenId) {
    const token = this.apiTokens.find((t) => t.id === tokenId);
    if (token) {
      token.lastUsed = nowIso();
    }
  }

  async load() {
    return;
  }

  async flush() {
    return;
  }
}

