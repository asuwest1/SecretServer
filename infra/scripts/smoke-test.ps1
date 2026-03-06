param(
  [string]$BaseUrl = 'http://localhost',
  [string]$HealthPath = '/health',
  [string]$AppPath = '/',
  [string]$LoginPath = '/api/v1/auth/login',
  [string]$DocsPath = '/api/docs',
  [switch]$CheckDocsRestriction,
  [string]$AdminUsername = '',
  [string]$AdminPassword = '',
  [string]$ExternalProbeIp = '8.8.8.8',
  [switch]$SkipTlsValidation,
  [int]$TimeoutSec = 15
)

$ErrorActionPreference = 'Stop'

if ($SkipTlsValidation) {
  add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Join-Url([string]$base, [string]$path) {
  if ($base.EndsWith('/') -and $path.StartsWith('/')) {
    return "$($base.TrimEnd('/'))$path"
  }
  if (-not $base.EndsWith('/') -and -not $path.StartsWith('/')) {
    return "$base/$path"
  }
  return "$base$path"
}

$results = @()

try {
  $appUrl = Join-Url $BaseUrl $AppPath
  $app = Invoke-WebRequest -Uri $appUrl -Method GET -TimeoutSec $TimeoutSec
  $appOk = $app.StatusCode -ge 200 -and $app.StatusCode -lt 400
  $results += [pscustomobject]@{ Check='Web UI'; Url=$appUrl; Ok=$appOk; Detail="status=$($app.StatusCode)" }
} catch {
  $results += [pscustomobject]@{ Check='Web UI'; Url=(Join-Url $BaseUrl $AppPath); Ok=$false; Detail=$_.Exception.Message }
}

try {
  $healthUrl = Join-Url $BaseUrl $HealthPath
  $health = Invoke-RestMethod -Uri $healthUrl -Method GET -TimeoutSec $TimeoutSec
  $healthOk = $health.data.status -eq 'ok'
  $results += [pscustomobject]@{ Check='Health'; Url=$healthUrl; Ok=$healthOk; Detail="status=$($health.data.status)" }
} catch {
  $results += [pscustomobject]@{ Check='Health'; Url=(Join-Url $BaseUrl $HealthPath); Ok=$false; Detail=$_.Exception.Message }
}

try {
  $loginUrl = Join-Url $BaseUrl $LoginPath
  $body = @{ username='nonexistent-user'; password='wrong-password' } | ConvertTo-Json
  $loginOk = $false
  $loginDetail = ''

  try {
    Invoke-RestMethod -Uri $loginUrl -Method POST -ContentType 'application/json' -Body $body -TimeoutSec $TimeoutSec | Out-Null
    $loginDetail = 'unexpected success response'
  } catch {
    if ($_.Exception.Response) {
      $resp = $_.Exception.Response
      $status = [int]$resp.StatusCode
      $stream = $resp.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($stream)
      $raw = $reader.ReadToEnd()
      $code = ''
      try {
        $parsed = $raw | ConvertFrom-Json
        $code = $parsed.error.code
      } catch { }
      $loginOk = ($status -eq 401) -or ($status -eq 429)
      $loginDetail = "status=$status code=$code"
    } else {
      $loginDetail = $_.Exception.Message
    }
  }

  $results += [pscustomobject]@{ Check='Login Endpoint'; Url=$loginUrl; Ok=$loginOk; Detail=$loginDetail }
} catch {
  $results += [pscustomobject]@{ Check='Login Endpoint'; Url=(Join-Url $BaseUrl $LoginPath); Ok=$false; Detail=$_.Exception.Message }
}

if ($CheckDocsRestriction) {
  $docsUrl = Join-Url $BaseUrl $DocsPath

  if ([string]::IsNullOrWhiteSpace($AdminUsername) -or [string]::IsNullOrWhiteSpace($AdminPassword)) {
    $results += [pscustomobject]@{ Check='Docs Internal Restriction'; Url=$docsUrl; Ok=$false; Detail='AdminUsername/AdminPassword required when CheckDocsRestriction is set.' }
  }
  else {
    try {
      $loginBody = @{ username = $AdminUsername; password = $AdminPassword } | ConvertTo-Json
      $loginResp = Invoke-RestMethod -Uri (Join-Url $BaseUrl $LoginPath) -Method POST -ContentType 'application/json' -Body $loginBody -TimeoutSec $TimeoutSec
      $token = $loginResp.data.accessToken

      if ([string]::IsNullOrWhiteSpace($token)) {
        $results += [pscustomobject]@{ Check='Docs Internal Restriction'; Url=$docsUrl; Ok=$false; Detail='Admin login succeeded but no access token was returned.' }
      }
      else {
        $ok = $false
        $detail = ''

        try {
          Invoke-WebRequest -Uri $docsUrl -Method GET -TimeoutSec $TimeoutSec -Headers @{
            Authorization = "Bearer $token"
            'x-forwarded-for' = $ExternalProbeIp
          } | Out-Null
          $detail = 'unexpected success response'
        } catch {
          if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            $ok = $status -eq 403
            $detail = "status=$status"
          } else {
            $detail = $_.Exception.Message
          }
        }

        $results += [pscustomobject]@{ Check='Docs Internal Restriction'; Url=$docsUrl; Ok=$ok; Detail=$detail }
      }
    } catch {
      $results += [pscustomobject]@{ Check='Docs Internal Restriction'; Url=$docsUrl; Ok=$false; Detail=$_.Exception.Message }
    }
  }
}

Write-Host 'Smoke test results:'
$results | Format-Table -AutoSize

if ($results.Where({ -not $_.Ok }).Count -gt 0) {
  throw 'Smoke validation failed.'
}

Write-Host 'Smoke validation passed.'
