param(
  [string]$BackupDir = "C:\\backup\\secret-server",
  [string]$SourceDir = "C:\\inetpub\\secret-server",
  [string]$PassphraseEnv = "SECRET_SERVER_BACKUP_PASSPHRASE"
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$temp = Join-Path $env:TEMP "secret-server-$timestamp"
$archive = Join-Path $BackupDir "secret_server_$timestamp.zip"
$encrypted = "$archive.enc"

New-Item -ItemType Directory -Force -Path $temp, $BackupDir | Out-Null
Copy-Item -Path (Join-Path $SourceDir "secrets") -Destination $temp -Recurse -Force -ErrorAction Stop
Copy-Item -Path (Join-Path $SourceDir "data") -Destination $temp -Recurse -Force -ErrorAction SilentlyContinue

Compress-Archive -Path (Join-Path $temp "*") -DestinationPath $archive -Force

$passphrase = [Environment]::GetEnvironmentVariable($PassphraseEnv)
if (-not $passphrase) {
  throw "Missing env var $PassphraseEnv"
}

$bytes = [System.IO.File]::ReadAllBytes($archive)
$aes = [System.Security.Cryptography.Aes]::Create()
 $sha = New-Object System.Security.Cryptography.SHA256Managed
 $aes.Key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($passphrase))
$aes.GenerateIV()
$encryptor = $aes.CreateEncryptor()
$cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

[System.IO.File]::WriteAllBytes($encrypted, $aes.IV + $cipher)
Remove-Item $archive -Force
Remove-Item $temp -Recurse -Force

Get-ChildItem $BackupDir -Filter '*.enc' | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
Write-Host "Backup written: $encrypted"

