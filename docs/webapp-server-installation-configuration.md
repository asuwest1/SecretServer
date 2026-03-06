# Web Application Server Installation and Configuration (Windows + IIS)

This guide sets up a Secret Server web application host on Windows Server with IIS.

Scope:
- Host prerequisites
- IIS + Node runtime configuration
- Environment and key material setup
- SQL migration/bootstrap
- Deployment + validation
- Rollback path

## 1. Host Prerequisites

Required software/components:
- Windows Server with IIS installed
- IIS URL Rewrite module
- iisnode
- Node.js + npm
- SQL Server reachable from this host
- `sqlcmd` available (or configured via `SECRET_SERVER_SQLCMD_PATH`)

Run preflight check:

```powershell
powershell -NoProfile -File infra/scripts/preflight-iis.ps1
```

If preflight reports failures, install missing dependencies and rerun.

## 2. Prepare Environment File

Start from template:

- `infra/env/secret-server.env.template`

Create a secure copy (example):

```powershell
Copy-Item infra/env/secret-server.env.template C:\secure\secret-server.env
```

Set production values in `C:\secure\secret-server.env`:
- `NODE_ENV=production`
- SQL connectivity values (`SECRET_SERVER_SQL_*`)
- LDAP values if enabled (`SECRET_SERVER_LDAP_*`)
- `SECRET_SERVER_BOOTSTRAP_PASSWORD`
- `SECRET_SERVER_BACKUP_PASSPHRASE`

Apply env vars to machine scope:

```powershell
powershell -NoProfile -File infra/scripts/apply-env-file.ps1 -EnvFile C:\secure\secret-server.env -Target Machine
```

## 3. Generate Key Material

Create encryption/JWT keys for server runtime:

```powershell
powershell -NoProfile -File infra/scripts/new-key-material.ps1 -OutputDir C:\inetpub\secret-server\secrets
```

Verify expected files:
- `C:\inetpub\secret-server\secrets\master.key`
- `C:\inetpub\secret-server\secrets\jwt.key`

## 4. SQL Database Initialization

If this is a greenfield DB, follow:
- `docs/sql-server-fresh-setup.md`

At minimum, run migrations:

```powershell
powershell -NoProfile -File infra/scripts/apply-migrations.ps1
```

## 5. Build and Package Release (recommended)

From repo root:

```powershell
npm run web:build
powershell -NoProfile -File infra/scripts/package-release.ps1
```

This creates a versioned zip and checksum files under `artifacts/`.

## 6. Deploy to IIS

### Option A: Deploy from release package (recommended)

```powershell
powershell -NoProfile -File infra/scripts/deploy-from-package.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -RunPreflight -InstallDependencies
```

### Option B: Deploy directly from source tree

```powershell
powershell -NoProfile -File infra/scripts/deploy-iis.ps1 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -InstallDependencies
```

## 7. Configure HTTPS Binding in IIS

`infra/iis/web.config` enforces HTTP->HTTPS redirect. Ensure IIS site has a valid HTTPS binding and certificate.

In IIS Manager:
1. Open Site `SecretServer`.
2. Bindings...
3. Add `https` binding (port 443) with correct server certificate.

Without a valid HTTPS binding, clients will be redirected to TLS but fail to connect.

## 8. Post-Deploy Validation

Run smoke checks:

```powershell
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -SkipTlsValidation
```

Optional docs-restriction check:

```powershell
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -CheckDocsRestriction -AdminUsername superadmin -AdminPassword '<password>' -ExternalProbeIp 8.8.8.8 -SkipTlsValidation
```

## 9. Promotion Workflow (with rollback)

Use promotion script for staged release validation:

```powershell
powershell -NoProfile -File infra/scripts/promote-release.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -BaseUrl https://your-secret-server-host -RunPreflight -InstallDependencies -RollbackOnFailure
```

## 10. Operations and Recovery

- Backup: `infra/scripts/backup.ps1`
- Restore: `infra/scripts/restore.ps1`
- Drill automation/evidence: `infra/scripts/run-backup-restore-drill.ps1`
- Promotion validation evidence: `infra/scripts/run-promotion-validation.ps1`

Reference docs:
- `docs/operations-runbook.md`
- `docs/backup-restore-evidence.md`
- `docs/staging-promotion-evidence.md`


