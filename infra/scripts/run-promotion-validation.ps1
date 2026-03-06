param(
  [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')),
  [string]$ArtifactsDir = ''
)

$ErrorActionPreference = 'Stop'

if (-not $ArtifactsDir) {
  $ArtifactsDir = Join-Path $WorkspaceRoot 'artifacts\promotion-validation'
}

$logsDir = Join-Path $ArtifactsDir 'logs'
$mockDir = Join-Path $ArtifactsDir 'mock'
$physicalPath = Join-Path $ArtifactsDir 'staging-site'
$snapshotRoot = Join-Path $ArtifactsDir 'snapshots'

New-Item -ItemType Directory -Force -Path $ArtifactsDir, $logsDir, $mockDir, $physicalPath, $snapshotRoot | Out-Null
Set-Content -Path (Join-Path $physicalPath 'version.txt') -Value 'old'

$version = Get-Date -Format 'yyyyMMdd_HHmmss'
& (Join-Path $PSScriptRoot 'package-release.ps1') -SourcePath $WorkspaceRoot -OutputDir $ArtifactsDir -Version $version | Out-Null

$package = Join-Path $ArtifactsDir ("secret_server_release_{0}.zip" -f $version)
$checksum = "$package.sha256"

& (Join-Path $PSScriptRoot 'deploy-from-package.ps1') -PackagePath $package -ChecksumFile $checksum -ValidateOnly | Out-Null

$mockDeploy = Join-Path $mockDir 'mock-deploy.ps1'
$mockSmokePass = Join-Path $mockDir 'mock-smoke-pass.ps1'
$mockSmokeFail = Join-Path $mockDir 'mock-smoke-fail.ps1'

@"
param(
  [Parameter(Mandatory = `$true)][string]`$PackagePath,
  [string]`$SiteName = 'SecretServer',
  [string]`$PhysicalPath = '',
  [string]`$AppPoolName = '',
  [switch]`$InstallDependencies,
  [switch]`$RunPreflight,
  [string]`$EnvFile = '',
  [string]`$EnvTarget = 'Process',
  [string]`$ChecksumFile = '',
  [string]`$ExpectedPackageSha256 = ''
)

if (-not `$PhysicalPath) { throw 'PhysicalPath is required for mock deploy' }
New-Item -ItemType Directory -Force -Path `$PhysicalPath | Out-Null
Set-Content -Path (Join-Path `$PhysicalPath 'version.txt') -Value 'new'
"@ | Set-Content $mockDeploy

@"
param([string]`$BaseUrl = 'http://localhost')
Write-Host "Mock smoke pass for `$BaseUrl"
"@ | Set-Content $mockSmokePass

@"
param([string]`$BaseUrl = 'http://localhost')
throw "Mock smoke failure for `$BaseUrl"
"@ | Set-Content $mockSmokeFail

$results = @()

$successStart = Get-Date
& (Join-Path $PSScriptRoot 'promote-release.ps1') `
  -PackagePath $package `
  -ChecksumFile $checksum `
  -PhysicalPath $physicalPath `
  -SnapshotRoot $snapshotRoot `
  -RollbackOnFailure `
  -DeployScriptPath $mockDeploy `
  -SmokeScriptPath $mockSmokePass | Out-Null
$successEnd = Get-Date

$successVersion = Get-Content (Join-Path $physicalPath 'version.txt') -Raw
$results += [pscustomobject]@{
  scenario = 'success'
  startedAt = $successStart.ToString('o')
  completedAt = $successEnd.ToString('o')
  deployedVersion = $successVersion.Trim()
  passed = ($successVersion.Trim() -eq 'new')
}

Set-Content -Path (Join-Path $physicalPath 'version.txt') -Value 'old'

$failureStart = Get-Date
$failureThrown = $false
try {
  & (Join-Path $PSScriptRoot 'promote-release.ps1') `
    -PackagePath $package `
    -ChecksumFile $checksum `
    -PhysicalPath $physicalPath `
    -SnapshotRoot $snapshotRoot `
    -RollbackOnFailure `
    -DeployScriptPath $mockDeploy `
    -SmokeScriptPath $mockSmokeFail | Out-Null
} catch {
  $failureThrown = $true
}
$failureEnd = Get-Date

$failureVersion = Get-Content (Join-Path $physicalPath 'version.txt') -Raw
$results += [pscustomobject]@{
  scenario = 'forced-failure-rollback'
  startedAt = $failureStart.ToString('o')
  completedAt = $failureEnd.ToString('o')
  failureObserved = $failureThrown
  restoredVersion = $failureVersion.Trim()
  rollbackPassed = ($failureThrown -and $failureVersion.Trim() -eq 'old')
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath = Join-Path $logsDir ("promotion_validation_{0}.json" -f $stamp)
$results | ConvertTo-Json -Depth 5 | Set-Content $logPath

[pscustomobject]@{
  packagePath = $package
  checksumPath = $checksum
  logPath = $logPath
  successPassed = ($results | Where-Object { $_.scenario -eq 'success' }).passed
  rollbackPassed = ($results | Where-Object { $_.scenario -eq 'forced-failure-rollback' }).rollbackPassed
} | ConvertTo-Json -Depth 4 | Write-Output
