import { spawnSync } from 'node:child_process';
import path from 'node:path';

function resolveScriptPath() {
  return path.join(process.cwd(), 'infra', 'scripts', 'read-protected-secret.ps1');
}

function readProtectedSecret(filePath) {
  const scriptPath = resolveScriptPath();
  const result = spawnSync('powershell', ['-NoProfile', '-File', scriptPath, '-FilePath', filePath], {
    encoding: 'utf8',
    timeout: 5000,
    windowsHide: true,
  });

  if (result.status !== 0) {
    throw new Error(String(result.stderr || result.stdout || 'READ_PROTECTED_SECRET_FAILED').trim());
  }

  return String(result.stdout || '').trim();
}

export function loadProtectedSecrets(logger) {
  const secretsDir = String(process.env.SECRET_SERVER_PROTECTED_SECRETS_DIR || '').trim();
  if (!secretsDir) {
    return;
  }

  const mappings = [
    {
      envName: 'SECRET_SERVER_SQL_PASSWORD',
      fileName: process.env.SECRET_SERVER_SQL_PASSWORD_FILE || 'sql_password.bin',
    },
    {
      envName: 'SECRET_SERVER_LDAP_PASSWORD',
      fileName: process.env.SECRET_SERVER_LDAP_PASSWORD_FILE || 'ldap_password.bin',
    },
    {
      envName: 'SECRET_SERVER_BACKUP_PASSPHRASE',
      fileName: process.env.SECRET_SERVER_BACKUP_PASSPHRASE_FILE || 'backup_passphrase.bin',
    },
  ];

  for (const mapping of mappings) {
    if (process.env[mapping.envName]) {
      continue;
    }

    const secretPath = path.join(secretsDir, mapping.fileName);
    try {
      const value = readProtectedSecret(secretPath);
      if (value) {
        process.env[mapping.envName] = value;
      }
    } catch (err) {
      logger?.warn?.('protected_secret_load_failed', {
        envName: mapping.envName,
        fileName: mapping.fileName,
        error: err.message,
      });
    }
  }
}
