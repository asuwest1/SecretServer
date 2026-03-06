param(
  [Parameter(Mandatory=$true)][string]$EncryptedBackup,
  [string]$TargetDir = "C:\inetpub\secret-server",
  [string]$PassphraseEnv = "SECRET_SERVER_BACKUP_PASSPHRASE"
)

$passphrase = [Environment]::GetEnvironmentVariable($PassphraseEnv)
if (-not $passphrase) {
  throw "Missing env var $PassphraseEnv"
}

$data = [System.IO.File]::ReadAllBytes($EncryptedBackup)
$iv = $data[0..15]
$cipher = $data[16..($data.Length-1)]

$aes = [System.Security.Cryptography.Aes]::Create()
$sha = New-Object System.Security.Cryptography.SHA256Managed
$aes.Key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($passphrase))
$aes.IV = $iv
$decryptor = $aes.CreateDecryptor()
$plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)

$tempZip = Join-Path $env:TEMP 'secret-server-restore.zip'
$tempDir = Join-Path $env:TEMP 'secret-server-restore'
[System.IO.File]::WriteAllBytes($tempZip, $plain)

if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force

if (-not (Test-Path $TargetDir)) {
  New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
}

Get-ChildItem -Path $tempDir -Force | ForEach-Object {
  Copy-Item -Path $_.FullName -Destination $TargetDir -Recurse -Force
}

Remove-Item $tempZip -Force
Remove-Item $tempDir -Recurse -Force
Write-Host "Restore completed to $TargetDir"
