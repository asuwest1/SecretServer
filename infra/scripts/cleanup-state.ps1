param(
  [string]$Server = $env:SECRET_SERVER_SQL_SERVER,
  [string]$Database = $env:SECRET_SERVER_SQL_DATABASE,
  [string]$Username = $env:SECRET_SERVER_SQL_USERNAME,
  [string]$Password = $env:SECRET_SERVER_SQL_PASSWORD,
  [string]$SqlCmdPath = $(if ($env:SECRET_SERVER_SQLCMD_PATH) { $env:SECRET_SERVER_SQLCMD_PATH } else { 'sqlcmd' }),
  [switch]$TrustServerCertificate
)

if (-not $Server) { $Server = 'localhost' }
if (-not $Database) { $Database = 'secret_server' }

$args = @('-S', $Server, '-d', $Database, '-b', '-Q', @"
SET NOCOUNT ON;
BEGIN TRAN;
DELETE FROM refresh_sessions WHERE expires_at < SYSUTCDATETIME() OR revoked_at IS NOT NULL;
DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < SYSUTCDATETIME();
DELETE FROM secrets WHERE is_deleted = 1 AND purge_after IS NOT NULL AND purge_after < SYSUTCDATETIME();
COMMIT TRAN;
"@)

if ($TrustServerCertificate) { $args += '-C' }
if ($Username) { $args += @('-U', $Username, '-P', $Password) } else { $args += '-E' }

& $SqlCmdPath @args
if ($LASTEXITCODE -ne 0) {
  throw 'Cleanup failed'
}

Write-Host 'Cleanup complete.'
