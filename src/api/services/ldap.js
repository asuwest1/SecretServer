import { spawn } from 'node:child_process';
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

function runProcessAsync(command, args, options = {}) {
  return new Promise((resolve) => {
    try {
      const child = spawn(command, args, {
        windowsHide: true,
        ...options,
      });

      let stdout = '';
      let stderr = '';
      let finished = false;

      const timeoutMs = options.timeout;
      let timeoutHandle = null;
      if (timeoutMs && timeoutMs > 0) {
        timeoutHandle = setTimeout(() => {
          if (!finished) {
            child.kill();
          }
        }, timeoutMs);
      }

      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
      });
      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString('utf8');
      });

      child.on('error', (error) => {
        if (finished) return;
        finished = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        resolve({ status: 1, stdout, stderr, error });
      });

      child.on('close', (code) => {
        if (finished) return;
        finished = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        resolve({ status: code ?? 1, stdout, stderr });
      });

      if (options.input) {
        child.stdin?.write(options.input);
      }
      child.stdin?.end();
    } catch (error) {
      resolve({ status: 1, stdout: '', stderr: '', error });
    }
  });
}

export class LdapService {
  constructor(config, logger, runner = null) {
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

  async execute(command, args, options) {
    if (this.runner) {
      return await this.runner(command, args, options);
    }
    return runProcessAsync(command, args, options);
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

    const serviceAccountPasswordEnv = 'SECRET_SERVER_LDAP_BIND_PASSWORD';
    const payload = JSON.stringify({
      username: safeUsername,
      password,
      domain: this.config.domain,
      server: this.config.server,
      port: this.config.port,
      baseDn: this.config.baseDn,
      serviceAccountDn: this.config.serviceAccountDn,
      serviceAccountPasswordEnv,
      requireLdaps: this.config.requireLdaps,
    });

    const env = { ...process.env };
    if (this.config.serviceAccountPassword) {
      env[serviceAccountPasswordEnv] = this.config.serviceAccountPassword;
    }

    const result = await this.execute('powershell', ['-NoProfile', '-File', this.config.authScriptPath], {
      encoding: 'utf8',
      timeout: Math.max(1000, this.config.authTimeoutMs || 8000),
      windowsHide: true,
      input: payload,
      env,
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
