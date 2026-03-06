param(
  [Parameter(Mandatory = $true)][string]$FilePath,
  [Parameter(Mandatory = $true)][string]$Value,
  [switch]$CreateParent
)

$ErrorActionPreference = 'Stop'

if ($CreateParent) {
  $parent = Split-Path -Parent $FilePath
  if ($parent -and -not (Test-Path $parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }
}

$bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
$protected = [System.Security.Cryptography.ProtectedData]::Protect(
  $bytes,
  $null,
  [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

$base64 = [Convert]::ToBase64String($protected)
Set-Content -Path $FilePath -Value $base64 -Encoding ASCII
Write-Host "Protected secret written: $FilePath"
