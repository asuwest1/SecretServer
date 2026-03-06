param(
  [string]$JwtKeyPath = "C:\\inetpub\\secret-server\\secrets\\jwt.key"
)

$jwt = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($jwt)
[System.IO.File]::WriteAllBytes($JwtKeyPath, $jwt)
Write-Host "Rotated JWT key at $JwtKeyPath"
