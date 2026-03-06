param(
  [Parameter(Mandatory = $true)][string]$EnvFile,
  [ValidateSet('Process', 'User', 'Machine')][string]$Target = 'Process',
  [string]$Prefix = 'SECRET_SERVER_'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $EnvFile)) {
  throw "Env file not found: $EnvFile"
}

$lines = Get-Content $EnvFile
$applied = 0

foreach ($line in $lines) {
  $raw = $line.Trim()
  if (-not $raw) { continue }
  if ($raw.StartsWith('#')) { continue }

  $eq = $raw.IndexOf('=')
  if ($eq -lt 1) { continue }

  $name = $raw.Substring(0, $eq).Trim()
  $value = $raw.Substring($eq + 1).Trim()

  if ($name -eq 'NODE_ENV' -or $name.StartsWith($Prefix)) {
    [System.Environment]::SetEnvironmentVariable($name, $value, $Target)
    if ($Target -eq 'Process') {
      Set-Item -Path "Env:$name" -Value $value
    }
    $applied += 1
  }
}

Write-Host "Applied $applied environment values from $EnvFile to $Target scope."
if ($Target -eq 'Machine') {
  Write-Host 'Machine-level environment values usually require service/app-pool recycle to take effect.'
}
