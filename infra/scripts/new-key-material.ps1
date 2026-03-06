param(
  [string]$OutputDir = "C:\\inetpub\\secret-server\\secrets"
)

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$masterPath = Join-Path $OutputDir 'master.key'
$jwtPath = Join-Path $OutputDir 'jwt.key'

$master = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($master)
[System.IO.File]::WriteAllBytes($masterPath, $master)

$jwt = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($jwt)
[System.IO.File]::WriteAllBytes($jwtPath, $jwt)

$acl = Get-Acl $OutputDir
$acl.SetAccessRuleProtection($true, $false)
Set-Acl -Path $OutputDir -AclObject $acl

Write-Host "Generated key material in $OutputDir"
