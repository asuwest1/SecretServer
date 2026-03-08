param(
  [string]$Payload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
  if ([string]::IsNullOrWhiteSpace($Payload)) {
    $Payload = [Console]::In.ReadToEnd()
  }

  $input = $Payload | ConvertFrom-Json
  $username = [string]$input.username
  $password = [string]$input.password
  $domain = [string]$input.domain
  $server = [string]$input.server
  $baseDn = [string]$input.baseDn
  $serviceAccountDn = [string]$input.serviceAccountDn
  $serviceAccountPasswordEnv = [string]$input.serviceAccountPasswordEnv
  $serviceAccountPassword = ''
  if (-not [string]::IsNullOrWhiteSpace($serviceAccountPasswordEnv)) {
    $servicePasswordVar = Get-Item -Path "Env:$serviceAccountPasswordEnv" -ErrorAction SilentlyContinue
    if ($null -ne $servicePasswordVar) {
      $serviceAccountPassword = [string]$servicePasswordVar.Value
    }
  }
  $port = [int]$input.port
  $requireLdaps = [bool]$input.requireLdaps

  if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
    @{ ok = $false; reason = 'INVALID_CREDENTIALS' } | ConvertTo-Json -Compress
    exit 0
  }

  if ($requireLdaps -and $port -ne 636) {
    @{ ok = $false; reason = 'LDAP_LDAPS_REQUIRED' } | ConvertTo-Json -Compress
    exit 0
  }

  Add-Type -AssemblyName System.DirectoryServices.AccountManagement

  if ([string]::IsNullOrWhiteSpace($domain)) {
    $domain = $env:USERDOMAIN
  }

  if ([string]::IsNullOrWhiteSpace($domain) -and [string]::IsNullOrWhiteSpace($server)) {
    @{ ok = $false; reason = 'LDAP_SERVER_OR_DOMAIN_REQUIRED' } | ConvertTo-Json -Compress
    exit 0
  }

  $target = if (-not [string]::IsNullOrWhiteSpace($server)) { $server } else { $domain }

  $contextOptions = [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate -bor
    [System.DirectoryServices.AccountManagement.ContextOptions]::Signing -bor
    [System.DirectoryServices.AccountManagement.ContextOptions]::Sealing

  if ($requireLdaps) {
    $contextOptions = $contextOptions -bor [System.DirectoryServices.AccountManagement.ContextOptions]::SecureSocketLayer
  }

  $context = $null
  if (-not [string]::IsNullOrWhiteSpace($serviceAccountDn) -and -not [string]::IsNullOrWhiteSpace($serviceAccountPassword)) {
    if (-not [string]::IsNullOrWhiteSpace($baseDn)) {
      $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain,
        $target,
        $baseDn,
        $contextOptions,
        $serviceAccountDn,
        $serviceAccountPassword
      )
    }
    else {
      $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain,
        $target,
        $null,
        $contextOptions,
        $serviceAccountDn,
        $serviceAccountPassword
      )
    }
  }
  else {
    if (-not [string]::IsNullOrWhiteSpace($baseDn)) {
      $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain,
        $target,
        $baseDn,
        $contextOptions
      )
    }
    else {
      $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain,
        $target
      )
    }
  }

  $valid = $context.ValidateCredentials($username, $password, $contextOptions)
  if (-not $valid) {
    @{ ok = $false; reason = 'INVALID_CREDENTIALS' } | ConvertTo-Json -Compress
    exit 0
  }

  $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
    $context,
    [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,
    $username
  )
  if ($null -eq $userPrincipal) {
    $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $username)
  }

  $groups = @()
  if ($userPrincipal -ne $null) {
    try {
      foreach ($group in $userPrincipal.GetAuthorizationGroups()) {
        if ($group.Name) {
          $groups += [string]$group.Name
        }
      }
    }
    catch {
      # Group lookup can fail for nested/trust edge cases; auth success still stands.
      $groups = @()
    }
  }

  @{
    ok = $true
    username = $username
    displayName = if ($userPrincipal -and $userPrincipal.DisplayName) { $userPrincipal.DisplayName } else { $username }
    email = if ($userPrincipal -and $userPrincipal.EmailAddress) { $userPrincipal.EmailAddress } else { '' }
    groups = $groups
  } | ConvertTo-Json -Compress
}
catch {
  @{ ok = $false; reason = 'LDAP_EXCEPTION'; detail = $_.Exception.Message } | ConvertTo-Json -Compress
}
