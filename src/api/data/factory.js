import { Store } from './store.js';
import { SqlStore } from './sql-store.js';

function migrationIdToNumber(value) {
  const first = String(value || '').split('_')[0];
  const parsed = Number.parseInt(first, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

export async function createStore(config, logger) {
  if (!config.sql.enabled) {
    const store = new Store();
    await store.load();
    return store;
  }

  try {
    const sqlStore = new SqlStore(config.sql, logger);
    await sqlStore.load();

    const applied = await sqlStore.getAppliedMigrations();
    const appliedMax = applied.reduce((max, m) => Math.max(max, migrationIdToNumber(m.version)), 0);
    const required = Number.parseInt(config.sql.requiredMigration, 10) || 0;

    if (required > 0 && appliedMax < required) {
      throw new Error(`REQUIRED_MIGRATION_${required}_NOT_APPLIED`);
    }

    logger.info('sql_store_enabled', {
      server: config.sql.server,
      database: config.sql.database,
      mode: config.sql.mode,
      appliedMigrations: applied.map((x) => x.version),
    });
    return sqlStore;
  } catch (err) {
    logger.error('sql_store_init_failed_fallback_memory', { error: err.message });
    const store = new Store();
    await store.load();
    return store;
  }
}

