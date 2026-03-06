# LDAP/AD Troubleshooting Guide

This guide covers common LDAP/AD operational failures for Secret Server.

## Required Configuration Baseline

- `SECRET_SERVER_LDAP_ENABLED=true`
- `SECRET_SERVER_LDAP_REQUIRE_LDAPS=true`
- `SECRET_SERVER_LDAP_PORT=636`
- One of:
  - `SECRET_SERVER_LDAP_SERVER=<dc-hostname>`
  - `SECRET_SERVER_LDAP_DOMAIN=<ad-domain>`
- `SECRET_SERVER_LDAP_AUTH_SCRIPT` points to an existing script path.
- In production, keep:
  - `SECRET_SERVER_LDAP_FALLBACK_LOCAL=false`
  - `SECRET_SERVER_LDAP_ALLOW_LOCAL_FALLBACK_IN_PRODUCTION=false`

## Fast Diagnostics

1. Check dependency health:
   - `GET /health/deps`
   - Confirm LDAP dependency is `configured`.
2. Verify startup logs do not include `ldap_config_invalid`.
3. Validate LDAP auth script execution manually:
   - `powershell -NoProfile -File infra/scripts/ldap-auth.ps1 -Payload '<json>'`
4. Confirm role-group map is valid JSON:
   - `SECRET_SERVER_LDAP_ROLE_GROUP_MAP={"AD-Group":"RoleName"}`

## Failure Modes

### 1. LDAPS Required Error

Symptoms:
- Login fails with LDAP auth rejection.
- Logs show `LDAP_LDAPS_REQUIRED`.

Causes:
- `SECRET_SERVER_LDAP_REQUIRE_LDAPS=true` but port is not 636.

Fix:
- Set `SECRET_SERVER_LDAP_PORT=636`.
- Confirm DC accepts LDAPS and certificate chain is trusted.

### 2. Auth Script Missing

Symptoms:
- Service exits at startup or LDAP auth always fails.
- Logs show `LDAP_AUTH_SCRIPT_MISSING`.

Fix:
- Set `SECRET_SERVER_LDAP_AUTH_SCRIPT` to a valid absolute path.
- Ensure app pool/service identity can read and execute script.

### 3. Timeout / Execution Failures

Symptoms:
- Logs include `ldap_auth_failed_exec`.
- Auth requests are slow and fail.

Causes:
- Domain controller latency/network path issues.
- Script blocked by policy or execution restrictions.

Fix:
- Increase `SECRET_SERVER_LDAP_AUTH_TIMEOUT_MS` carefully (for example 12000).
- Verify network route to DC and firewall rules.
- Validate PowerShell execution policy for the service account.

### 4. Group Mapping Not Applying

Symptoms:
- LDAP login succeeds but expected roles are missing.

Causes:
- Group names in `SECRET_SERVER_LDAP_ROLE_GROUP_MAP` do not match AD group display names.
- Mapped role names do not exist in app.

Fix:
- Confirm group names exactly as returned by AD.
- Confirm mapped role names exist in Secret Server.
- Re-login user to trigger sync.

### 5. Unexpected Role Drops on Login

Behavior:
- LDAP-managed role bindings (rows with `assignedBy=null`) are synchronized to current mapped groups on each LDAP login.
- Stale LDAP-managed role assignments are removed.

Guidance:
- Keep manual assignments separate (non-null `assignedBy`) when you want persistence outside LDAP sync.

## Certificate and TLS Notes

- Use domain certificates trusted by the server host.
- Avoid disabling LDAPS requirements in production.
- If certificate trust fails, fix trust chain on host rather than lowering TLS requirements.

## Recommended Production Defaults

- `SECRET_SERVER_LDAP_REQUIRE_LDAPS=true`
- `SECRET_SERVER_LDAP_FALLBACK_LOCAL=false`
- `SECRET_SERVER_LDAP_ALLOW_LOCAL_FALLBACK_IN_PRODUCTION=false`
- `SECRET_SERVER_LDAP_AUTH_TIMEOUT_MS=8000`
- `SECRET_SERVER_LDAP_MAX_GROUPS=256`
