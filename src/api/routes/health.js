import { spawn } from 'node:child_process';
import { json } from '../lib/http.js';
import { requireAuth, requireSuperAdmin } from '../services/security.js';

function runCommandAsync(command, args, options = {}) {
  return new Promise((resolve) => {
    try {
      const child = spawn(command, args, { windowsHide: true, ...options });
      let stdout = '';
      let stderr = '';
      let done = false;

      const timeoutMs = options.timeout;
      let timeoutHandle = null;
      if (timeoutMs && timeoutMs > 0) {
        timeoutHandle = setTimeout(() => {
          if (!done) child.kill();
        }, timeoutMs);
      }

      child.stdout?.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
      child.stderr?.on('data', (chunk) => { stderr += chunk.toString('utf8'); });

      child.on('error', (error) => {
        if (done) return;
        done = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        resolve({ status: 1, stdout, stderr, error });
      });

      child.on('close', (code) => {
        if (done) return;
        done = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        resolve({ status: code ?? 1, stdout, stderr });
      });

      child.stdin?.end();
    } catch (error) {
      resolve({ status: 1, stdout: '', stderr: '', error });
    }
  });
}

async function sqlDependency(config) {
  if (!config.sql.enabled) {
    return { enabled: false, status: 'skipped' };
  }

  const args = ['-S', config.sql.server, '-d', config.sql.database, '-h', '-1', '-W', '-Q', 'SELECT 1'];
  if (config.sql.username) {
    args.push('-U', config.sql.username);
  } else {
    args.push('-E');
  }

  const env = { ...process.env };
  if (config.sql.username && config.sql.password) {
    env.SQLCMDPASSWORD = config.sql.password;
  }

  const res = await runCommandAsync(config.sql.sqlcmdPath, args, { encoding: 'utf8', timeout: 5000, env });
  return {
    enabled: true,
    status: res.status === 0 ? 'ok' : 'error',
    detail: res.status === 0 ? 'connected' : (res.stderr || res.stdout || 'sqlcmd_failed').trim(),
  };
}

function ldapDependency(config) {
  if (!config.ldap.enabled) {
    return { enabled: false, status: 'skipped' };
  }

  const hasTarget = Boolean(config.ldap.server || config.ldap.domain);
  const requiresLdaps = Boolean(config.ldap.requireLdaps);
  const validLdapsPort = !requiresLdaps || config.ldap.port === 636;
  const scriptConfigured = Boolean(config.ldap.authScriptPath);

  const status = hasTarget && validLdapsPort && scriptConfigured ? 'configured' : 'warning';
  return {
    enabled: true,
    status,
    detail: status === 'configured' ? 'ldap_configured' : 'ldap_hardening_incomplete',
    requireLdaps: requiresLdaps,
    fallbackLocal: Boolean(config.ldap.fallbackLocal),
    authTimeoutMs: config.ldap.authTimeoutMs,
  };
}

export function registerHealthRoutes(router) {
  router.register('GET', /^\/health$/, async (_req, res) => {
    json(res, 200, { data: { status: 'ok', timestamp: new Date().toISOString() } });
  });

  router.register('GET', /^\/health\/deps$/, async (req, res, ctx) => {
    const actor = requireAuth(req, res, ctx, 'read');
    if (!actor) return;
    if (!requireSuperAdmin(res, ctx, actor)) return;

    const sql = await sqlDependency(ctx.config);
    const ldap = ldapDependency(ctx.config);

    const aggregate = [sql, ldap].some((d) => d.enabled && d.status === 'error') ? 'degraded' : 'ok';
    json(res, 200, {
      data: {
        status: aggregate,
        timestamp: new Date().toISOString(),
        dependencies: {
          sql,
          ldap,
        },
      },
    });
  });
}
