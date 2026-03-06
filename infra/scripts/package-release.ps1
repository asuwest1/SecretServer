param(
  [string]$SourcePath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')),
  [string]$OutputDir = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) 'artifacts'),
  [string]$Version = (Get-Date -Format 'yyyyMMdd_HHmmss'),
  [switch]$BuildWeb
)

$ErrorActionPreference = 'Stop'

$sourceRoot = (Resolve-Path $SourcePath).Path
$outputRoot = $OutputDir
if (-not (Test-Path $outputRoot)) {
  New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
}

if ($BuildWeb) {
  Push-Location $sourceRoot
  try {
    npm run web:build
  } finally {
    Pop-Location
  }
}

$webDist = Join-Path $sourceRoot 'src\web\dist'
if (-not (Test-Path $webDist)) {
  throw "Missing frontend build at $webDist. Run 'npm run web:build' or use -BuildWeb."
}

$stage = Join-Path $outputRoot "release_$Version"
if (Test-Path $stage) {
  Remove-Item -Recurse -Force $stage
}

$stageSrcApi = Join-Path $stage 'src\api'
$stageWwwroot = Join-Path $stage 'wwwroot'
$stageScripts = Join-Path $stage 'infra\scripts'
$stageIis = Join-Path $stage 'infra\iis'
$stageEnv = Join-Path $stage 'infra\env'
$stageDocs = Join-Path $stage 'docs'

New-Item -ItemType Directory -Force -Path $stageSrcApi, $stageWwwroot, $stageScripts, $stageIis, $stageEnv, $stageDocs | Out-Null

Copy-Item -Path (Join-Path $sourceRoot 'src\api\*') -Destination $stageSrcApi -Recurse -Force
Copy-Item -Path (Join-Path $webDist '*') -Destination $stageWwwroot -Recurse -Force
Copy-Item -Path (Join-Path $sourceRoot 'infra\scripts\*.ps1') -Destination $stageScripts -Force
Copy-Item -Path (Join-Path $sourceRoot 'infra\iis\web.config') -Destination (Join-Path $stageIis 'web.config') -Force
if (Test-Path (Join-Path $sourceRoot 'infra\env\*')) {
  Copy-Item -Path (Join-Path $sourceRoot 'infra\env\*') -Destination $stageEnv -Force
}
Copy-Item -Path (Join-Path $sourceRoot 'docs\operations-runbook.md') -Destination (Join-Path $stageDocs 'operations-runbook.md') -Force
Copy-Item -Path (Join-Path $sourceRoot 'README.md') -Destination (Join-Path $stage 'README.md') -Force
Copy-Item -Path (Join-Path $sourceRoot 'package.json') -Destination (Join-Path $stage 'package.json') -Force

$rootLock = Join-Path $sourceRoot 'package-lock.json'
if (Test-Path $rootLock) {
  Copy-Item -Path $rootLock -Destination (Join-Path $stage 'package-lock.json') -Force
}

$manifest = [ordered]@{
  version = $Version
  createdAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  files = @(
    'src/api',
    'wwwroot',
    'infra/scripts',
    'infra/iis/web.config',
    'infra/env',
    'docs/operations-runbook.md',
    'README.md',
    'package.json'
  )
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $stage 'release-manifest.json')

$checksumPath = Join-Path $stage 'release-checksums.sha256'
$checksumLines = @()
$files = Get-ChildItem -Path $stage -Recurse -File | Sort-Object FullName
foreach ($f in $files) {
  if ($f.FullName -eq $checksumPath) { continue }
  $rel = $f.FullName.Substring($stage.Length + 1).Replace('\\', '/')
  $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  $checksumLines += "$hash  $rel"
}
$checksumLines | Set-Content $checksumPath

$zipPath = Join-Path $outputRoot "secret_server_release_$Version.zip"
if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force

$zipHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$zipName = [System.IO.Path]::GetFileName($zipPath)
$zipChecksumPath = "$zipPath.sha256"
"$zipHash  $zipName" | Set-Content $zipChecksumPath

Write-Host "Release package created: $zipPath"
Write-Host "Package checksum: $zipChecksumPath"
Write-Host "Staging directory: $stage"
Write-Host "Content checksum file: $checksumPath"
