param(
  [Parameter(Mandatory = $true)][string]$PackagePath,
  [string]$SiteName = "SecretServer",
  [string]$PhysicalPath = "C:\inetpub\secret-server",
  [string]$AppPoolName = "SecretServerPool",
  [string]$WorkingDir = (Join-Path $env:TEMP "secret-server-release"),
  [switch]$InstallDependencies,
  [switch]$RunPreflight,
  [string]$EnvFile = '',
  [ValidateSet('Process', 'User', 'Machine')][string]$EnvTarget = 'Process',
  [switch]$SkipChecksumValidation,
  [switch]$ValidateOnly,
  [string]$ChecksumFile = '',
  [string]$ExpectedPackageSha256 = ''
)

$ErrorActionPreference = 'Stop'

function Test-PackageHash {
  param(
    [string]$Path,
    [string]$ChecksumPath,
    [string]$ExpectedHash
  )

  $expected = $ExpectedHash.Trim().ToLowerInvariant()

  if (-not $expected) {
    $candidate = $ChecksumPath
    if (-not $candidate) {
      $candidate = "$Path.sha256"
    }

    if (-not (Test-Path $candidate)) {
      throw "Package checksum file not found: $candidate"
    }

    $line = (Get-Content $candidate | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1).Trim()
    if ($line -notmatch '^([a-fA-F0-9]{64})\s\s(.+)$') {
      throw "Invalid package checksum line in $candidate"
    }

    $expected = $matches[1].ToLowerInvariant()
    $nameInFile = $matches[2]
    $packageName = [System.IO.Path]::GetFileName($Path)
    if ($nameInFile -ne $packageName) {
      throw "Checksum file package name mismatch. Expected '$packageName', got '$nameInFile'"
    }
  }

  $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "Package hash mismatch for $Path"
  }

  Write-Host "Package hash validation passed: $actual"
}

function Test-ReleaseChecksums {
  param([string]$Root)

  $checksumFile = Join-Path $Root 'release-checksums.sha256'
  if (-not (Test-Path $checksumFile)) {
    throw "Checksum file missing: $checksumFile"
  }

  $lines = Get-Content $checksumFile
  $validated = 0

  foreach ($line in $lines) {
    $raw = $line.Trim()
    if (-not $raw) { continue }

    if ($raw -notmatch '^([a-fA-F0-9]{64})\s\s(.+)$') {
      throw "Invalid checksum line: $raw"
    }

    $expected = $matches[1].ToLowerInvariant()
    $rel = $matches[2]
    $target = Join-Path $Root ($rel.Replace('/', '\\'))

    if (-not (Test-Path $target)) {
      throw "Missing file from checksum manifest: $rel"
    }

    $actual = (Get-FileHash -Path $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
      throw "Checksum mismatch for $rel"
    }

    $validated += 1
  }

  Write-Host "Content checksum validation passed for $validated files."
}

if (-not (Test-Path $PackagePath)) {
  throw "Package not found: $PackagePath"
}

if (-not $SkipChecksumValidation) {
  Test-PackageHash -Path $PackagePath -ChecksumPath $ChecksumFile -ExpectedHash $ExpectedPackageSha256
} else {
  Write-Warning 'Package hash validation skipped by request.'
}

if (Test-Path $WorkingDir) {
  Remove-Item -Recurse -Force $WorkingDir
}
New-Item -ItemType Directory -Force -Path $WorkingDir | Out-Null

Expand-Archive -Path $PackagePath -DestinationPath $WorkingDir -Force

if (-not $SkipChecksumValidation) {
  Test-ReleaseChecksums -Root $WorkingDir
} else {
  Write-Warning 'Content checksum validation skipped by request.'
}

if ($ValidateOnly) {
  Write-Host 'ValidateOnly mode enabled. Deployment step skipped.'
  return
}

if ($RunPreflight) {
  $preflight = Join-Path $PSScriptRoot 'preflight-iis.ps1'
  & $preflight
}

if ($EnvFile) {
  $applyEnv = Join-Path $PSScriptRoot 'apply-env-file.ps1'
  & $applyEnv -EnvFile $EnvFile -Target $EnvTarget
}

$deploy = Join-Path $PSScriptRoot 'deploy-iis.ps1'
$args = @(
  '-NoProfile',
  '-File',
  $deploy,
  '-SiteName',
  $SiteName,
  '-PhysicalPath',
  $PhysicalPath,
  '-AppPoolName',
  $AppPoolName,
  '-SourcePath',
  $WorkingDir
)
if ($InstallDependencies) {
  $args += '-InstallDependencies'
}

powershell @args
if ($LASTEXITCODE -ne 0) {
  throw "deploy-iis.ps1 failed with exit code $LASTEXITCODE"
}

Write-Host "Package deployed successfully from $PackagePath"
Write-Host "Expanded package location: $WorkingDir"
