param(
  [Parameter(Mandatory = $true)][string]$FilePath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $FilePath)) {
  throw "Protected secret file not found: $FilePath"
}

$base64 = (Get-Content -Path $FilePath -Raw).Trim()
if (-not $base64) {
  throw "Protected secret file is empty: $FilePath"
}

$protected = [Convert]::FromBase64String($base64)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
  $protected,
  $null,
  [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

[System.Text.Encoding]::UTF8.GetString($bytes)
