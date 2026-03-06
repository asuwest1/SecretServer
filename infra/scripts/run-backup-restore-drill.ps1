param(
  [int]$Runs = 3,
  [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')),
  [string]$ArtifactsDir = '',
  [string]$PassphraseEnv = 'SECRET_SERVER_BACKUP_PASSPHRASE'
)

$ErrorActionPreference = 'Stop'

if (-not $ArtifactsDir) {
  $ArtifactsDir = Join-Path $WorkspaceRoot 'artifacts\drills'
}
$backupDir = Join-Path $ArtifactsDir 'backups'
$logsDir = Join-Path $ArtifactsDir 'logs'
$sourceDir = Join-Path $ArtifactsDir 'source-seed'
$restoreRoot = Join-Path $ArtifactsDir 'restore-runs'

New-Item -ItemType Directory -Force -Path $backupDir, $logsDir, $sourceDir, $restoreRoot | Out-Null

if (-not [Environment]::GetEnvironmentVariable($PassphraseEnv)) {
  [Environment]::SetEnvironmentVariable($PassphraseEnv, 'local-drill-passphrase', 'Process')
}

function Get-DirFingerprint {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return '' }

  $rows = @()
  foreach ($f in (Get-ChildItem -Path $Path -Recurse -File | Sort-Object FullName)) {
    $rel = $f.FullName.Substring($Path.Length).TrimStart('\\')
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $rows += "$rel|$hash"
  }

  $joined = ($rows -join "`n")
  if (-not $joined) { return '' }

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
  $sha = New-Object System.Security.Cryptography.SHA256Managed
  $hashBytes = $sha.ComputeHash($bytes)
  return (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Seed-Source {
  param([string]$Path)

  if (Test-Path $Path) {
    Remove-Item -Recurse -Force $Path
  }

  New-Item -ItemType Directory -Force -Path (Join-Path $Path 'secrets'), (Join-Path $Path 'data') | Out-Null
  Set-Content -Path (Join-Path $Path 'secrets\master.key') -Value "master-$(Get-Date -Format o)"
  Set-Content -Path (Join-Path $Path 'secrets\jwt.key') -Value "jwt-$(Get-Date -Format o)"
  $state = @{ ts = (Get-Date -Format o) } | ConvertTo-Json -Compress
  Set-Content -Path (Join-Path $Path 'data\app-state.json') -Value $state
}

$results = @()

for ($i = 1; $i -le $Runs; $i++) {
  Seed-Source -Path $sourceDir

  $preHash = Get-DirFingerprint -Path $sourceDir
  $backupStart = Get-Date

  & (Join-Path $PSScriptRoot 'backup.ps1') -BackupDir $backupDir -SourceDir $sourceDir -PassphraseEnv $PassphraseEnv | Out-Null

  $backupEnd = Get-Date
  $backupFile = Get-ChildItem -Path $backupDir -Filter '*.enc' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $backupFile) {
    throw 'Backup file not found after backup run.'
  }

  $restoreDir = Join-Path $restoreRoot ("run_{0}" -f $i)
  if (Test-Path $restoreDir) {
    Remove-Item -Recurse -Force $restoreDir
  }

  $restoreStart = Get-Date
  & (Join-Path $PSScriptRoot 'restore.ps1') -EncryptedBackup $backupFile.FullName -TargetDir $restoreDir -PassphraseEnv $PassphraseEnv | Out-Null
  $restoreEnd = Get-Date

  $postHash = Get-DirFingerprint -Path $restoreDir
  $integrityOk = ($preHash -eq $postHash)

  $rtoSec = [math]::Round((New-TimeSpan -Start $restoreStart -End $restoreEnd).TotalSeconds, 2)
  $rpoSec = [math]::Round((New-TimeSpan -Start $backupStart -End $restoreEnd).TotalSeconds, 2)

  $results += [pscustomobject]@{
    run = $i
    startedAt = $backupStart.ToString('o')
    backupCompletedAt = $backupEnd.ToString('o')
    restoreCompletedAt = $restoreEnd.ToString('o')
    backupFile = $backupFile.FullName
    sourceFingerprint = $preHash
    restoredFingerprint = $postHash
    integrityOk = $integrityOk
    rtoSeconds = $rtoSec
    rpoSeconds = $rpoSec
  }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath = Join-Path $logsDir ("backup_restore_drill_{0}.json" -f $stamp)
$results | ConvertTo-Json -Depth 5 | Set-Content $logPath

$summary = @{
  runs = $Runs
  successCount = ($results | Where-Object { $_.integrityOk }).Count
  maxRtoSeconds = ($results | Measure-Object -Property rtoSeconds -Maximum).Maximum
  maxRpoSeconds = ($results | Measure-Object -Property rpoSeconds -Maximum).Maximum
  logPath = $logPath
}

$summary | ConvertTo-Json -Depth 3 | Write-Output
