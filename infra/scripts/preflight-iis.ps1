param(
  [switch]$AllowWarnings
)

$ErrorActionPreference = 'Stop'

function Add-Result {
  param([string]$Check, [bool]$Ok, [string]$Detail)
  [pscustomobject]@{ Check = $Check; Ok = $Ok; Detail = $Detail }
}

$results = @()

# IIS role/module
try {
  Import-Module WebAdministration -ErrorAction Stop
  $results += Add-Result -Check 'IIS WebAdministration module' -Ok $true -Detail 'available'
} catch {
  $results += Add-Result -Check 'IIS WebAdministration module' -Ok $false -Detail $_.Exception.Message
}

# URL Rewrite detection
$urlRewritePaths = @(
  'HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\IIS Extensions\URL Rewrite'
)
$urlRewriteFound = $false
foreach ($p in $urlRewritePaths) {
  if (Test-Path $p) { $urlRewriteFound = $true; break }
}
$results += Add-Result -Check 'IIS URL Rewrite' -Ok $urlRewriteFound -Detail ($(if ($urlRewriteFound) { 'installed' } else { 'registry key not found' }))

# iisnode detection
$iisnodeDll = Join-Path ${env:ProgramFiles} 'iisnode\iisnode.dll'
$iisnodeFound = Test-Path $iisnodeDll
$results += Add-Result -Check 'iisnode' -Ok $iisnodeFound -Detail ($(if ($iisnodeFound) { $iisnodeDll } else { 'iisnode.dll not found' }))

# Node and npm
try {
  $nodeVersion = (& node -v 2>$null)
  $results += Add-Result -Check 'node' -Ok $true -Detail $nodeVersion
} catch {
  $results += Add-Result -Check 'node' -Ok $false -Detail 'node not found in PATH'
}

try {
  $npmVersion = (& npm -v 2>$null)
  $results += Add-Result -Check 'npm' -Ok $true -Detail $npmVersion
} catch {
  $results += Add-Result -Check 'npm' -Ok $false -Detail 'npm not found in PATH'
}

Write-Host 'Preflight results:'
$results | Format-Table -AutoSize

$failed = $results | Where-Object { -not $_.Ok }
if ($failed.Count -gt 0 -and -not $AllowWarnings) {
  throw 'IIS preflight failed. Resolve required checks or rerun with -AllowWarnings.'
}

if ($failed.Count -gt 0) {
  Write-Warning 'Preflight completed with warnings.'
} else {
  Write-Host 'Preflight passed.'
}
