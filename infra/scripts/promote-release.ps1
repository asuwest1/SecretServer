param(
  [Parameter(Mandatory = $true)][string]$PackagePath,
  [string]$SiteName = 'SecretServer',
  [string]$PhysicalPath = 'C:\inetpub\secret-server',
  [string]$AppPoolName = 'SecretServerPool',
  [string]$BaseUrl = 'http://localhost',
  [string]$SnapshotRoot = 'C:\backup\secret-server\deploy-snapshots',
  [switch]$InstallDependencies,
  [switch]$RunPreflight,
  [switch]$RollbackOnFailure,
  [string]$EnvFile = '',
  [ValidateSet('Process', 'User', 'Machine')][string]$EnvTarget = 'Process',
  [string]$ChecksumFile = '',
  [string]$ExpectedPackageSha256 = '',
  [string]$DeployScriptPath = '',
  [string]$SmokeScriptPath = ''
)

$ErrorActionPreference = 'Stop'

function New-Snapshot {
  param([string]$SourcePath, [string]$SnapshotBase)

  if (-not (Test-Path $SourcePath)) {
    return $null
  }

  if (-not (Test-Path $SnapshotBase)) {
    New-Item -ItemType Directory -Force -Path $SnapshotBase | Out-Null
  }

  $name = 'snapshot_' + (Get-Date -Format 'yyyyMMdd_HHmmss_fff')
  $target = Join-Path $SnapshotBase $name
  New-Item -ItemType Directory -Force -Path $target | Out-Null

  Copy-Item -Path (Join-Path $SourcePath '*') -Destination $target -Recurse -Force
  return $target
}

function Restore-Snapshot {
  param([string]$SnapshotPath, [string]$TargetPath)

  if (-not (Test-Path $SnapshotPath)) {
    throw "Snapshot path not found: $SnapshotPath"
  }

  if (-not (Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Force -Path $TargetPath | Out-Null
  }

  Get-ChildItem -Path $TargetPath -Force | Remove-Item -Recurse -Force
  Copy-Item -Path (Join-Path $SnapshotPath '*') -Destination $TargetPath -Recurse -Force
}

if (-not (Test-Path $PackagePath)) {
  throw "Package not found: $PackagePath"
}

$snapshot = New-Snapshot -SourcePath $PhysicalPath -SnapshotBase $SnapshotRoot
if ($snapshot) {
  Write-Host "Snapshot created: $snapshot"
} else {
  Write-Host 'No existing deployment found; snapshot skipped.'
}

$deployScript = if ($DeployScriptPath) { $DeployScriptPath } else { Join-Path $PSScriptRoot 'deploy-from-package.ps1' }
$smokeScript = if ($SmokeScriptPath) { $SmokeScriptPath } else { Join-Path $PSScriptRoot 'smoke-test.ps1' }

try {
  $deployParams = @{
    PackagePath = $PackagePath
    SiteName = $SiteName
    PhysicalPath = $PhysicalPath
    AppPoolName = $AppPoolName
  }
  if ($InstallDependencies) { $deployParams.InstallDependencies = $true }
  if ($RunPreflight) { $deployParams.RunPreflight = $true }
  if ($EnvFile) {
    $deployParams.EnvFile = $EnvFile
    $deployParams.EnvTarget = $EnvTarget
  }
  if ($ChecksumFile) {
    $deployParams.ChecksumFile = $ChecksumFile
  }
  if ($ExpectedPackageSha256) {
    $deployParams.ExpectedPackageSha256 = $ExpectedPackageSha256
  }

  & $deployScript @deployParams

  & $smokeScript -BaseUrl $BaseUrl

  Write-Host 'Promotion completed successfully.'
} catch {
  Write-Warning "Promotion failed: $($_.Exception.Message)"

  if ($RollbackOnFailure -and $snapshot) {
    Write-Warning 'Rollback enabled. Restoring snapshot...'
    Restore-Snapshot -SnapshotPath $snapshot -TargetPath $PhysicalPath

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-Command Restart-WebAppPool -ErrorAction SilentlyContinue) {
      Restart-WebAppPool -Name $AppPoolName
    }

    Write-Warning 'Rollback completed.'
  }

  throw
}


