# Secret Server Scaffold

This repository contains an executable Secret Server MVP scaffold with security-focused APIs, SQL Server support, and Windows/IIS operations artifacts.

## Documentation index
- Start here: `docs/documentation-index.md`

## Implemented capabilities
- Versioned API under `/api/v1`
- Auth/session flows:
  - login + lockout policy
  - MFA challenge + TOTP verification
  - refresh token rotation + replay detection + session revocation
  - logout + logout-all
  - API token auth (`X-API-Token`) for protected endpoints
- Admin APIs: users, roles, role membership, API token issuance, MFA setup/verify
- Vault APIs: folders + ACL, secrets CRUD/reveal, soft-delete/restore, version history
- Security controls: request throttling, secure headers, structured log redaction
- Crypto: AES-256-GCM secret encryption with MEK/DEK model
- Audit: append-only audit stream, query/export, optional syslog forwarding
- SQL mode: diff-based per-entity upsert/delete sync + append-only audit inserts

## Persistence modes
- Default: in-memory store
- SQL: `SECRET_SERVER_SQL_ENABLED=true` with `sqlcmd` available

## SQL migrations
- Fresh setup checklist: `docs/sql-server-fresh-setup.md`
- Migration files: `infra/sql/migrations`
- Apply script: `powershell -NoProfile -File infra/scripts/apply-migrations.ps1`
- Startup requires migration version in `SECRET_SERVER_SQL_REQUIRED_MIGRATION` (default `3`) when SQL mode is enabled.

## Health and observability
- `GET /health`
- `GET /health/deps` (SQL + LDAP dependency status)
- Request completion/failure timing logs emitted in structured JSON

## Key environment variables
- Core: `SECRET_SERVER_HOST`, `SECRET_SERVER_PORT`, `SECRET_SERVER_ISSUER`
- Keys: `SECRET_SERVER_KEY_FILE`, `SECRET_SERVER_JWT_KEY_FILE`
- LDAP: `SECRET_SERVER_LDAP_ENABLED`, `SECRET_SERVER_LDAP_FALLBACK_LOCAL`, `SECRET_SERVER_LDAP_ALLOW_LOCAL_FALLBACK_IN_PRODUCTION`, `SECRET_SERVER_LDAP_REQUIRE_LDAPS`, `SECRET_SERVER_LDAP_ROLE_GROUP_MAP`, `SECRET_SERVER_LDAP_AUTH_TIMEOUT_MS`, `SECRET_SERVER_LDAP_MAX_GROUPS`, `SECRET_SERVER_LDAP_DOMAIN`, `SECRET_SERVER_LDAP_SERVER`, `SECRET_SERVER_LDAP_AUTH_SCRIPT`
- SQL: `SECRET_SERVER_SQL_ENABLED`, `SECRET_SERVER_SQL_SERVER`, `SECRET_SERVER_SQL_DATABASE`, `SECRET_SERVER_SQL_USERNAME`, `SECRET_SERVER_SQL_PASSWORD`, `SECRET_SERVER_SQLCMD_PATH`, `SECRET_SERVER_SQL_REQUIRED_MIGRATION`
- OpenAPI: `SECRET_SERVER_OPENAPI_INTERNAL_ONLY`, `SECRET_SERVER_OPENAPI_TRUST_PROXY`

## Operations scripts
- `infra/scripts/apply-migrations.ps1`
- `infra/scripts/package-release.ps1`
- `infra/scripts/deploy-iis.ps1`
- `infra/scripts/deploy-from-package.ps1`
- `infra/scripts/preflight-iis.ps1`
- `infra/scripts/apply-env-file.ps1`
- `infra/scripts/smoke-test.ps1`
- `infra/scripts/promote-release.ps1`
- `infra/scripts/backup.ps1`
- `infra/scripts/restore.ps1`
- `infra/scripts/cleanup-state.ps1`
- `infra/scripts/new-key-material.ps1`
- `infra/scripts/rotate-jwt-key.ps1`

## Runtime decision
- See [docs/adr/0001-runtime-target-node-v1.md](docs/adr/0001-runtime-target-node-v1.md)

## Tests
- Unit: `npm test`
- API integration: `npm run test:integration:api`
- SQL integration: `npm run test:integration:sql`
- Frontend tests: `npm run web:test`

## API token scopes
- Supported scopes: `read`, `write`, `admin`
- Create token scopes via `POST /api/v1/users/{id}/api-tokens` body `{ "scopes": ["read"] }`
- `admin` implies all access; `write` implies `read`

## Maintenance cleanup
Run cleanup job (expired sessions/tokens and purgeable secrets):
```powershell
powershell -NoProfile -File infra/scripts/cleanup-state.ps1 -TrustServerCertificate
```

## Web console (React)
- Install frontend deps: `cd src/web && npm install`
- Start UI dev server: `npm run web:dev`
- API proxy is configured to `http://localhost:8080`
- Run UI tests: `npm run web:test`
- Build UI: `npm run web:build`

## Release + IIS deployment
1. Build frontend artifact: `npm run web:build`
2. Create release zip (includes `release-checksums.sha256` and detached zip hash `.zip.sha256`):
```powershell
powershell -NoProfile -File infra/scripts/package-release.ps1
```
3. (Optional) preflight target host:
```powershell
powershell -NoProfile -File infra/scripts/preflight-iis.ps1
```
4. Deploy from source tree:
```powershell
powershell -NoProfile -File infra/scripts/deploy-iis.ps1 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -InstallDependencies
```
5. Deploy from release package (checksum verification enabled by default):
```powershell
powershell -NoProfile -File infra/scripts/deploy-from-package.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -RunPreflight -InstallDependencies
```
6. Validate package integrity only:
```powershell
powershell -NoProfile -File infra/scripts/deploy-from-package.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -ValidateOnly
```
7. Apply environment file (optional):
```powershell
powershell -NoProfile -File infra/scripts/apply-env-file.ps1 -EnvFile C:\secure\secret-server.env -Target Machine
```
8. Validate:
```powershell
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -SkipTlsValidation
```
9. Validate OpenAPI internal restriction (authenticated superadmin from external forwarded IP should be denied):
```powershell
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -CheckDocsRestriction -AdminUsername superadmin -AdminPassword '<password>' -ExternalProbeIp 8.8.8.8 -SkipTlsValidation
```

## One-command promotion (with rollback)
```powershell
powershell -NoProfile -File infra/scripts/promote-release.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -SiteName SecretServer -PhysicalPath C:\inetpub\secret-server -AppPoolName SecretServerPool -BaseUrl https://your-secret-server-host -RunPreflight -InstallDependencies -RollbackOnFailure
```

## Release governance artifacts
- Risk register: `docs/risk-register.md`
- Go-live checklist: `docs/go-live-checklist.md`
- Release decision + rollback criteria: `docs/release-decision-and-rollback-criteria.md`
- Backup/restore evidence: `docs/backup-restore-evidence.md`
- Staging promotion evidence: `docs/staging-promotion-evidence.md`

## Server installation guide
- Web application server install/config: `docs/webapp-server-installation-configuration.md`

## User documentation
- End-user guide: `docs/user-guide.md`
- Administrator guide: `docs/administrator-guide.md`
