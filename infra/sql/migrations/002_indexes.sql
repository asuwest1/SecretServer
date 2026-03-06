-- 002 hardening/indexes
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_audit_log_event_time' AND object_id = OBJECT_ID('audit_log'))
  CREATE INDEX idx_audit_log_event_time ON audit_log (event_time);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_audit_log_user_id' AND object_id = OBJECT_ID('audit_log'))
  CREATE INDEX idx_audit_log_user_id ON audit_log (user_id);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_api_tokens_user_id' AND object_id = OBJECT_ID('api_tokens'))
  CREATE INDEX idx_api_tokens_user_id ON api_tokens (user_id);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_refresh_sessions_user_id' AND object_id = OBJECT_ID('refresh_sessions'))
  CREATE INDEX idx_refresh_sessions_user_id ON refresh_sessions (user_id);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_refresh_sessions_revoked_at' AND object_id = OBJECT_ID('refresh_sessions'))
  CREATE INDEX idx_refresh_sessions_revoked_at ON refresh_sessions (revoked_at);
