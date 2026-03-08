#!/usr/bin/env node
/**
 * rotate-mek.js — Offline master encryption key (MEK) rotation tool.
 *
 * Usage:
 *   node src/api/scripts/rotate-mek.js [--dry-run]
 *
 * Required environment variables (same as the server):
 *   SECRET_SERVER_KEY_FILE      Path to the current master key file.
 *   SECRET_SERVER_SQL_*         SQL Server connection settings (SQL store required;
 *                               the in-memory store has no persistent data).
 *
 * What this script does:
 *   1. Loads all data from SQL (secrets, secret versions, user MFA keys).
 *   2. Generates a new random MEK.
 *   3. Re-wraps every DEK envelope with the new MEK (secret ciphertext unchanged).
 *   4. Writes the new MEK to a staging file (<keyFile>.new).
 *   5. Flushes the re-wrapped records to SQL.
 *   6. On success: renames <keyFile> → <keyFile>.prev, <keyFile>.new → <keyFile>.
 *   7. Prints instructions to restart the server.
 *
 * Failure handling:
 *   - If step 5 (SQL flush) fails, the staging file is removed and SQL is unchanged.
 *     The script is safe to retry.
 *   - If step 6 (rename) fails after a successful SQL flush, the new key is in
 *     <keyFile>.new. Manually rename it to <keyFile> before restarting the server.
 *
 * Add --dry-run to validate config and count objects without writing anything.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { loadConfig } from '../lib/config.js';
import { CryptoService } from '../lib/crypto.js';
import { createStore } from '../data/factory.js';
import { createLogger } from '../lib/logger.js';

const isDryRun = process.argv.includes('--dry-run');
const logger = createLogger('rotate-mek');
const config = loadConfig();

if (!config.sql.enabled) {
  logger.error('rotate_mek_sql_required', {
    message: 'MEK rotation requires the SQL store (SECRET_SERVER_SQL_ENABLED=true). The in-memory store has no persistent data to rotate.',
  });
  process.exit(1);
}

const keyFilePath = config.keyFilePath;
if (!fs.existsSync(keyFilePath)) {
  logger.error('rotate_mek_key_missing', { keyFilePath, message: 'Current master key file not found.' });
  process.exit(1);
}

logger.info('rotate_mek_started', { keyFilePath, dryRun: isDryRun });

// Load the store (reads all data from SQL).
const store = await createStore(config, logger);

const secretCount = store.secrets.length;
const versionCount = store.secretVersions.length;
const mfaCount = store.users.filter((u) => u.mfaSecretEnc || u.mfaPendingSecretEnc).length;

logger.info('rotate_mek_inventory', { secrets: secretCount, secretVersions: versionCount, usersWithMfa: mfaCount });

if (isDryRun) {
  logger.info('rotate_mek_dry_run_complete', { message: 'Dry run — no changes written.' });
  process.exit(0);
}

// Generate the new MEK.
const newMek = crypto.randomBytes(32);
const stagingKeyPath = `${keyFilePath}.new`;
const prevKeyPath = `${keyFilePath}.prev`;

// Write new MEK to staging file first so it is not lost if SQL flush succeeds
// but the rename fails.
try {
  fs.mkdirSync(path.dirname(stagingKeyPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(stagingKeyPath, newMek, { mode: 0o600 });
} catch (err) {
  logger.error('rotate_mek_staging_write_failed', { path: stagingKeyPath, error: err.message });
  process.exit(1);
}

// Re-wrap all DEK envelopes with the new MEK.
const cryptoService = new CryptoService({ keyFilePath });
try {
  cryptoService.rotateMek(newMek, store);
} catch (err) {
  fs.rmSync(stagingKeyPath, { force: true });
  logger.error('rotate_mek_rewrap_failed', { error: err.message });
  process.exit(1);
}

// Flush re-wrapped data to SQL.
try {
  await store.flush();
} catch (err) {
  fs.rmSync(stagingKeyPath, { force: true });
  logger.error('rotate_mek_sql_flush_failed', {
    error: err.message,
    message: 'SQL flush failed — no changes committed. The staging key file has been removed. Safe to retry.',
  });
  process.exit(1);
}

// Atomically promote the new key file.
try {
  if (fs.existsSync(keyFilePath)) {
    fs.renameSync(keyFilePath, prevKeyPath);
  }
  fs.renameSync(stagingKeyPath, keyFilePath);
  try {
    fs.chmodSync(keyFilePath, 0o600);
  } catch {
    // Best effort on platforms that ignore POSIX mode bits.
  }
} catch (err) {
  logger.error('rotate_mek_key_rename_failed', {
    stagingKeyPath,
    keyFilePath,
    error: err.message,
    message: `SQL has been updated with re-wrapped DEKs but the key file rename failed. Manually rename ${stagingKeyPath} to ${keyFilePath} before restarting the server.`,
  });
  process.exit(1);
}

logger.info('rotate_mek_complete', {
  keyFilePath,
  prevKeyPath,
  secrets: secretCount,
  secretVersions: versionCount,
  usersWithMfa: mfaCount,
  message: 'MEK rotation complete. Restart the server to begin using the new key. The previous key is preserved at prevKeyPath for emergency rollback.',
});
