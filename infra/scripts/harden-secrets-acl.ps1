param(
  [string]$SecretsPath = 'C:\inetpub\secret-server\secrets',
  [string]$AppPoolName = 'SecretServerPool'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $SecretsPath)) {
  throw "Secrets path not found: $SecretsPath"
}

$poolIdentity = "IIS AppPool\$AppPoolName"

icacls $SecretsPath /inheritance:r | Out-Null
icacls $SecretsPath /grant:r "SYSTEM:(OI)(CI)F" | Out-Null
icacls $SecretsPath /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
icacls $SecretsPath /grant:r "$poolIdentity:(OI)(CI)R" | Out-Null

Write-Host "Secrets ACL hardened for $SecretsPath"
Write-Host "Read granted to: $poolIdentity"
