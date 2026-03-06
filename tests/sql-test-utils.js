import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export function required(name) {
  const v = process.env[name];
  if (!v) {
    throw new Error(`Missing required env ${name}`);
  }
  return v;
}

export function createSqlConfig() {
  return {
    enabled: true,
    mode: 'sqlcmd',
    server: required('SECRET_SERVER_SQL_SERVER'),
    database: required('SECRET_SERVER_SQL_DATABASE'),
    username: process.env.SECRET_SERVER_SQL_USERNAME || '',
    password: process.env.SECRET_SERVER_SQL_PASSWORD || '',
    sqlcmdPath: process.env.SECRET_SERVER_SQLCMD_PATH || 'sqlcmd',
    trustServerCertificate: (process.env.SECRET_SERVER_SQL_TRUST_SERVER_CERTIFICATE || 'false').toLowerCase() === 'true',
  };
}

export function applyMigrations() {
  const script = path.join(process.cwd(), 'infra', 'scripts', 'apply-migrations.ps1');
  const args = ['-NoProfile', '-File', script];
  if ((process.env.SECRET_SERVER_SQL_TRUST_SERVER_CERTIFICATE || 'false').toLowerCase() === 'true') {
    args.push('-TrustServerCertificate');
  }

  const ps = process.env.SECRET_SERVER_PWSH_PATH || (process.platform === 'win32' ? 'powershell' : 'pwsh');
  const result = spawnSync(ps, args, { stdio: 'inherit', env: process.env });
  assert.equal(result.status, 0, 'migration script should succeed');
}
