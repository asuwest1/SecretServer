import { spawnSync } from 'node:child_process';
import fs from 'node:fs';

function normalizeUsername(value) {
  return String(value || '').trim();
}

function normalizeGroups(groups, maxGroups) {
  const deduped = new Set();
  for (const group of groups || []) {
    const name = String(group || '').trim();
    if (!name) continue;
    if (name.length > 256) continue;
    deduped.add(name);
    if (deduped.size >= maxGroups) {
      break;
    }
  }
  return [...deduped];
}

export class LdapService {
  constructor(config, logger, runner = spawnSync) {
    this.config = config;
    this.logger = logger;
    this.runner = runner;
  }

  validateConfiguration() {
    if (!this.config.enabled) {
      return { ok: true };
    }

    if (this.config.requireLdaps && this.config.port !== 636) {
      return { ok: false, reason: 'LDAP_LDAPS_REQUIRED' };
    }

    if (!this.config.server && !this.config.domain) {
      return { ok: false, reason: 'LDAP_SERVER_OR_DOMAIN_REQUIRED' };
    }

    if (!this.config.authScriptPath || !fs.existsSync(this.config.authScriptPath)) {
      return { ok: false, reason: 'LDAP_AUTH_SCRIPT_MISSING' };
    }

    return { ok: true };
  }

  async authenticate(username, password) {
    if (!this.config.enabled) {
      return { ok: false, reason: 'LDAP_DISABLED' };
    }

    const configCheck = this.validateConfiguration();
    if (!configCheck.ok) {
      this.logger.warn('ldap_auth_config_invalid', { reason: configCheck.reason });
      return { ok: false, reason: configCheck.reason };
    }

    const safeUsername = normalizeUsername(username);
    if (!safeUsername || !password) {
      return { ok: false, reason: 'INVALID_CREDENTIALS' };
    }

    const payload = JSON.stringify({
      username: safeUsername,
      password,
      domain: this.config.domain,
      server: this.config.server,
      port: this.config.port,
      baseDn: this.config.baseDn,
      serviceAccountDn: this.config.serviceAccountDn,
      serviceAccountPassword: this.config.serviceAccountPassword,
      requireLdaps: this.config.requireLdaps,
    });

    const result = this.runner('powershell', ['-NoProfile', '-File', this.config.authScriptPath, '-Payload', payload], {
      encoding: 'utf8',
      timeout: Math.max(1000, this.config.authTimeoutMs || 8000),
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });

    if (result.error) {
      this.logger.warn('ldap_auth_failed_exec', { code: result.error.code || 'EXEC_ERROR' });
      return { ok: false, reason: 'LDAP_EXEC_FAILED' };
    }

    if (result.status !== 0) {
      this.logger.warn('ldap_auth_failed_exec', {
        status: result.status,
        stderr: String(result.stderr || '').slice(0, 256),
      });
      return { ok: false, reason: 'LDAP_EXEC_FAILED' };
    }

    try {
      const parsed = JSON.parse(String(result.stdout || '').trim() || '{}');
      if (parsed.ok) {
        return {
          ok: true,
          username: normalizeUsername(parsed.username || safeUsername),
          displayName: String(parsed.displayName || safeUsername).trim(),
          email: String(parsed.email || '').trim(),
          groups: normalizeGroups(parsed.groups, Math.max(1, this.config.maxGroups || 256)),
        };
      }
      return { ok: false, reason: parsed.reason || 'LDAP_AUTH_FAILED' };
    } catch (err) {
      this.logger.warn('ldap_auth_failed_parse', { error: err.message });
      return { ok: false, reason: 'LDAP_PARSE_FAILED' };
    }
  }
}
