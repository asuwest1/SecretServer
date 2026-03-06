param(
  [string]$Server = $env:SECRET_SERVER_SQL_SERVER,
  [string]$Database = $env:SECRET_SERVER_SQL_DATABASE,
  [string]$Username = $env:SECRET_SERVER_SQL_USERNAME,
  [string]$Password = $env:SECRET_SERVER_SQL_PASSWORD,
  [string]$SqlCmdPath = $(if ($env:SECRET_SERVER_SQLCMD_PATH) { $env:SECRET_SERVER_SQLCMD_PATH } else { 'sqlcmd' }),
  [string]$MigrationsPath = "$(Join-Path $PSScriptRoot '..\\sql\\migrations')",
  [switch]$TrustServerCertificate
)

if (-not $Server) { $Server = 'localhost' }
if (-not $Database) { $Database = 'secret_server' }

function Invoke-Sql {
  param([string]$Query)
  $args = @('-S', $Server, '-d', $Database, '-b', '-Q', $Query)
  if ($TrustServerCertificate) { $args += '-C' }
  if ($Username) {
    $args += @('-U', $Username, '-P', $Password)
  } else {
    $args += '-E'
  }
  & $SqlCmdPath @args
  if ($LASTEXITCODE -ne 0) {
    throw "sqlcmd failed"
  }
}

Invoke-Sql @"
IF OBJECT_ID('schema_migrations','U') IS NULL
BEGIN
  CREATE TABLE schema_migrations (
    version NVARCHAR(64) NOT NULL PRIMARY KEY,
    applied_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
  );
END;
"@

$files = Get-ChildItem -Path $MigrationsPath -File -Filter '*.sql' | Sort-Object Name
foreach ($file in $files) {
  $version = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
  $existsQuery = "SET NOCOUNT ON; IF EXISTS (SELECT 1 FROM schema_migrations WHERE version = N'$version') SELECT 1 ELSE SELECT 0"

  $args = @('-S', $Server, '-d', $Database, '-h', '-1', '-W', '-Q', $existsQuery)
  if ($TrustServerCertificate) { $args += '-C' }
  if ($Username) { $args += @('-U', $Username, '-P', $Password) } else { $args += '-E' }
  $exists = (& $SqlCmdPath @args | Out-String).Trim()

  if ($exists -eq '1') {
    Write-Host "Skipping migration $version (already applied)"
    continue
  }

  Write-Host "Applying migration $version from $($file.FullName)"
  $applyArgs = @('-S', $Server, '-d', $Database, '-b', '-i', $file.FullName)
  if ($TrustServerCertificate) { $applyArgs += '-C' }
  if ($Username) { $applyArgs += @('-U', $Username, '-P', $Password) } else { $applyArgs += '-E' }
  & $SqlCmdPath @applyArgs
  if ($LASTEXITCODE -ne 0) { throw "Failed applying migration $version" }

  Invoke-Sql "INSERT INTO schema_migrations(version) VALUES (N'$version');"
}

Write-Host 'Migrations complete.'
