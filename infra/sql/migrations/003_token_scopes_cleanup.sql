-- 003 token scopes and cleanup helpers
IF COL_LENGTH('api_tokens', 'scopes') IS NULL
BEGIN
  EXEC(N'ALTER TABLE api_tokens ADD scopes NVARCHAR(MAX) NOT NULL CONSTRAINT DF_api_tokens_scopes DEFAULT N''[""read""]'';');
END;

IF COL_LENGTH('api_tokens', 'scopes') IS NOT NULL
   AND NOT EXISTS (
     SELECT 1 FROM sys.check_constraints WHERE name = 'CK_api_tokens_scopes_is_json'
   )
BEGIN
  EXEC(N'ALTER TABLE api_tokens ADD CONSTRAINT CK_api_tokens_scopes_is_json CHECK (ISJSON([scopes]) = 1);');
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_api_tokens_expires_at' AND object_id = OBJECT_ID('api_tokens'))
  CREATE INDEX idx_api_tokens_expires_at ON api_tokens (expires_at);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_secrets_purge_after' AND object_id = OBJECT_ID('secrets'))
  CREATE INDEX idx_secrets_purge_after ON secrets (purge_after);
