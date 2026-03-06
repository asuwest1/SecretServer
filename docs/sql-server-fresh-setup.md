# SQL Server Fresh Setup Checklist (Windows)

Use this for a clean local/staging SQL setup for Secret Server.

## 1. Prerequisites

- SQL Server is installed and running.
- PowerShell available.
- Repo root is your current directory:
  - `C:\Users\wthor\OneDrive\Documents\GitHub\SecretServer`

## 2. Install `sqlcmd`

If `sqlcmd` is not installed, install from Microsoft package source:

```powershell
winget install Microsoft.Sqlcmd
```

Verify:

```powershell
sqlcmd -?
```

If needed, set explicit path for this project:

```powershell
$env:SECRET_SERVER_SQLCMD_PATH = 'C:\Program Files\sqlcmd\sqlcmd.exe'
```

## 3. Create the Database

### Option A: Windows Integrated Auth

```powershell
sqlcmd -S localhost -E -Q "IF DB_ID('secret_server') IS NULL CREATE DATABASE secret_server;"
```

### Option B: SQL Username/Password Auth

```powershell
sqlcmd -S localhost -U sa -P "<YourStrongPassword>" -Q "IF DB_ID('secret_server') IS NULL CREATE DATABASE secret_server;"
```

## 4. Configure Environment Variables

### Option A: Integrated Auth

```powershell
$env:SECRET_SERVER_SQL_ENABLED = 'true'
$env:SECRET_SERVER_SQL_SERVER = 'localhost'
$env:SECRET_SERVER_SQL_DATABASE = 'secret_server'
$env:SECRET_SERVER_SQL_REQUIRED_MIGRATION = '3'
```

### Option B: SQL Auth

```powershell
$env:SECRET_SERVER_SQL_ENABLED = 'true'
$env:SECRET_SERVER_SQL_SERVER = 'localhost'
$env:SECRET_SERVER_SQL_DATABASE = 'secret_server'
$env:SECRET_SERVER_SQL_USERNAME = 'sa'
$env:SECRET_SERVER_SQL_PASSWORD = '<YourStrongPassword>'
$env:SECRET_SERVER_SQL_REQUIRED_MIGRATION = '3'
```

Optional TLS trust flag for local dev SQL certs:

```powershell
$env:SECRET_SERVER_SQL_TRUST_SERVER_CERTIFICATE = 'true'
```

## 5. Apply Migrations (Creates Tables/Indexes)

```powershell
powershell -NoProfile -File infra/scripts/apply-migrations.ps1
```

If using SQL auth explicitly:

```powershell
powershell -NoProfile -File infra/scripts/apply-migrations.ps1 -Server localhost -Database secret_server -Username sa -Password "<YourStrongPassword>"
```

## 6. Verify Migration State and Tables

### Check applied migrations

Integrated auth:

```powershell
sqlcmd -S localhost -E -d secret_server -Q "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
```

SQL auth:

```powershell
sqlcmd -S localhost -U sa -P "<YourStrongPassword>" -d secret_server -Q "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
```

Expected versions:
- `001_initial_schema`
- `002_indexes`
- `003_token_scopes_cleanup`

### Check core tables exist

```powershell
sqlcmd -S localhost -E -d secret_server -Q "SELECT name FROM sys.tables WHERE name IN ('users','roles','user_roles','folders','secrets','secret_versions','secret_acl','folder_acl','api_tokens','audit_log','refresh_sessions','revoked_token_jti','schema_migrations') ORDER BY name;"
```

## 7. Run API in SQL Mode

```powershell
npm start
```

Optional SQL integration validation:

```powershell
npm run test:integration:sql
npm run test:integration:api:sql
```

## 8. Troubleshooting

- `sqlcmd failed` during migrations:
  - verify SQL Server name/port and auth mode
  - verify `SECRET_SERVER_SQLCMD_PATH` if `sqlcmd` is not on PATH
- login/certificate errors in local dev:
  - set `SECRET_SERVER_SQL_TRUST_SERVER_CERTIFICATE=true`
  - or run script with `-TrustServerCertificate`
- database exists but app still fails at startup:
  - ensure `SECRET_SERVER_SQL_REQUIRED_MIGRATION` matches latest migration (`3` currently)

## 9. Related Files

- Migration runner: `infra/scripts/apply-migrations.ps1`
- Migration SQL: `infra/sql/migrations/`
- Runbook: `docs/operations-runbook.md`
- Main readme: `README.md`
