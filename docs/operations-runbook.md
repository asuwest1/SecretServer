# Operations Runbook (Scaffold)

## Migrations
Run before deployment:
```powershell
powershell -NoProfile -File infra/scripts/apply-migrations.ps1
```

## Build frontend artifact
Run before IIS deploy:
```powershell
npm run web:build
```

## Create release package
Create a deployable zip with API, frontend artifacts, IIS config, ops scripts, env templates, plus both internal and detached SHA-256 checksums:
```powershell
powershell -NoProfile -File infra/scripts/package-release.ps1
```

Optional flags:
- `-BuildWeb` to build frontend during packaging.
- `-OutputDir <path>` to override artifact location.
- `-Version <label>` to control artifact naming.

## IIS preflight
Validate host prerequisites:
```powershell
powershell -NoProfile -File infra/scripts/preflight-iis.ps1
```

Checks:
- IIS WebAdministration PowerShell module
- URL Rewrite installation
- iisnode installation
- `node` and `npm` availability

## Environment values
Template file:
- `infra/env/secret-server.env.template`

Apply values from env file:
```powershell
powershell -NoProfile -File infra/scripts/apply-env-file.ps1 -EnvFile C:\secure\secret-server.env -Target Machine
```

## IIS deploy (API + UI)
Deploy from source tree:
```powershell
powershell -NoProfile -File infra/scripts/deploy-iis.ps1 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -InstallDependencies
```

Deploy from release package:
```powershell
powershell -NoProfile -File infra/scripts/deploy-from-package.ps1 -PackagePath C:\\path\\to\\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\\path\\to\\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -RunPreflight -InstallDependencies
```

Integrity options for package deployment:
- default behavior validates detached package hash (`.zip.sha256`) and internal content checksums (`release-checksums.sha256`)
- `-SkipChecksumValidation` bypasses checksum verification (not recommended)
- `-ValidateOnly` performs extract + checksum validation only

Notes:
- `-InstallDependencies` runs `npm install --omit=dev` in deploy directory.
- Requires IIS + URL Rewrite + iisnode installed on target host.
- Serves React app from `wwwroot` and rewrites `/api/*` and `/health*` to Node API.

## One-command promotion (deploy + smoke + rollback)
Run:
```powershell
powershell -NoProfile -File infra/scripts/promote-release.ps1 -PackagePath C:\\path\\to\\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\\path\\to\\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -BaseUrl https://your-secret-server-host -RunPreflight -InstallDependencies -RollbackOnFailure
```

Behavior:
- Creates a deployment snapshot before release apply.
- Deploys from package and runs smoke checks.
- Restores snapshot automatically when smoke checks fail.

## Post-deploy smoke validation
Run:
```powershell
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -SkipTlsValidation
```

Checks:
- `GET /`
- `GET /health`
- `POST /api/v1/auth/login` returns expected auth rejection semantics.

## Backup
Run:
```powershell
powershell -NoProfile -File infra/scripts/backup.ps1
```

Required env var:
- `SECRET_SERVER_BACKUP_PASSPHRASE`

Default backup location:
- `C:\backup\secret-server`

## Restore
Run:
```powershell
powershell -NoProfile -File infra/scripts/restore.ps1 -EncryptedBackup C:\backup\secret-server\secret_server_YYYYMMDD_HHMMSS.zip.enc
```

## Dependency health
Check dependency status:
- `GET /health/deps`

## Incident triage
1. Verify API health on `GET /health`.
2. Query audit events from `GET /api/v1/audit` with a Super Admin token.
3. Export audit stream from `GET /api/v1/audit/export?format=csv` for SIEM cross-check.
4. If key corruption is suspected, restore `secrets` directory and latest encrypted backup.

## Cleanup task
Run daily:
```powershell
powershell -NoProfile -File infra/scripts/cleanup-state.ps1 -TrustServerCertificate
```

## Recovery targets
- RTO target: < 2 hours (scripted restore + service validation)
- RPO target: < 24 hours (nightly backup cadence)


## Backup/restore drill automation
Run repeatable backup/restore drills with integrity + timing logs:
```powershell
powershell -NoProfile -File infra/scripts/run-backup-restore-drill.ps1 -Runs 3
```

Outputs:
- JSON run logs in `artifacts/drills/logs`
- encrypted backups in `artifacts/drills/backups`

## Promotion validation automation
Run staged promotion validation with package checksum verification and forced-failure rollback test:
```powershell
powershell -NoProfile -File infra/scripts/run-promotion-validation.ps1
```

Outputs:
- package + checksum artifacts in `artifacts/promotion-validation`
- validation logs in `artifacts/promotion-validation/logs`
