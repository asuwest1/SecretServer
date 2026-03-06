param(
  [string]$SiteName = "SecretServer",
  [string]$PhysicalPath = "C:\inetpub\secret-server",
  [string]$AppPoolName = "SecretServerPool",
  [string]$SourcePath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")),
  [switch]$InstallDependencies
)

$ErrorActionPreference = 'Stop'
Import-Module WebAdministration

$sourceRoot = (Resolve-Path $SourcePath).Path
$apiSource = Join-Path $sourceRoot 'src\api'
$webDistSource = Join-Path $sourceRoot 'src\web\dist'
$packagedWebRoot = Join-Path $sourceRoot 'wwwroot'
$webConfigSource = Join-Path $sourceRoot 'infra\iis\web.config'
$packageJsonSource = Join-Path $sourceRoot 'package.json'

if (-not (Test-Path $apiSource)) { throw "Missing API source at $apiSource" }
if (-not (Test-Path $webConfigSource)) { throw "Missing IIS config at $webConfigSource" }
if (-not (Test-Path $packageJsonSource)) { throw "Missing package.json at $packageJsonSource" }

$webSource = $null
if (Test-Path $webDistSource) {
  $webSource = $webDistSource
} elseif (Test-Path $packagedWebRoot) {
  $webSource = $packagedWebRoot
} else {
  throw "Missing web artifact at '$webDistSource' or '$packagedWebRoot'. Build web UI first or deploy from a release package."
}

if (-not (Test-Path $PhysicalPath)) {
  New-Item -ItemType Directory -Force -Path $PhysicalPath | Out-Null
}

$targetApi = Join-Path $PhysicalPath 'src\api'
$targetWeb = Join-Path $PhysicalPath 'wwwroot'
$targetSecrets = Join-Path $PhysicalPath 'secrets'
$targetData = Join-Path $PhysicalPath 'data'

New-Item -ItemType Directory -Force -Path $targetApi, $targetWeb, $targetSecrets, $targetData | Out-Null

Copy-Item -Path $apiSource -Destination (Join-Path $PhysicalPath 'src') -Recurse -Force
Copy-Item -Path (Join-Path $webSource '*') -Destination $targetWeb -Recurse -Force
Copy-Item -Path $webConfigSource -Destination (Join-Path $PhysicalPath 'web.config') -Force
Copy-Item -Path $packageJsonSource -Destination (Join-Path $PhysicalPath 'package.json') -Force

$rootLock = Join-Path $sourceRoot 'package-lock.json'
if (Test-Path $rootLock) {
  Copy-Item -Path $rootLock -Destination (Join-Path $PhysicalPath 'package-lock.json') -Force
}

if ($InstallDependencies) {
  Push-Location $PhysicalPath
  try {
    npm install --omit=dev
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path "IIS:\AppPools\$AppPoolName")) {
  New-WebAppPool -Name $AppPoolName | Out-Null
}

Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value ""
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value ApplicationPoolIdentity

if (-not (Get-Website -Name $SiteName -ErrorAction SilentlyContinue)) {
  New-Website -Name $SiteName -Port 80 -PhysicalPath $PhysicalPath -ApplicationPool $AppPoolName | Out-Null
} else {
  Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $PhysicalPath
  Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName
}

Restart-WebAppPool -Name $AppPoolName
Write-Host "Deployment complete: $SiteName at $PhysicalPath"
Write-Host "API entrypoint: src/api/server.js"
Write-Host "Web root: wwwroot"
Write-Host "Web source used: $webSource"
