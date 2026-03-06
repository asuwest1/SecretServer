# Secret Server Administrator Guide

This guide is for platform/application administrators responsible for operating Secret Server.

## 1. Admin Scope and Responsibilities

Administrators are responsible for:
- User and role lifecycle
- Access control policy (folder/secret ACL)
- Authentication settings (local, LDAP/AD, MFA policy)
- Audit review/export and incident triage
- Backup/restore readiness and recovery drills
- Release promotion and rollback validation

## 2. Access Model

### Super Admin

Super Admin can:
- Manage users, roles, role membership
- Manage all folders/secrets and ACLs
- Access audit query/export and integrity verification
- Access OpenAPI docs (subject to internal network restriction)

### Role/ACL Behavior

- Access is additive by role grants.
- Secret-level ACL entries override folder inheritance for that secret.
- Permission types:
  - `View`
  - `Add`
  - `Change`
  - `Delete`

Reference:
- `docs/acl-precedence.md`

## 3. Initial Bootstrap

1. Deploy app and apply DB migrations.
2. Ensure key files exist:
   - `SECRET_SERVER_KEY_FILE`
   - `SECRET_SERVER_JWT_KEY_FILE`
3. Set secure bootstrap password (`SECRET_SERVER_BOOTSTRAP_PASSWORD`).
4. Start app and confirm Super Admin access.
5. Create named admin accounts; avoid long-term use of bootstrap identity.

## 4. User and Role Administration

### Create role

- Create least-privilege roles for teams/functions.
- Avoid broad `Change/Delete` where not required.

### Create user

- Provide strong password policy and enforce MFA.
- Assign role membership through role APIs/UI.

### Deactivate user

- Deactivate immediately for offboarding.
- Revoke active sessions/tokens as part of offboarding procedure.

## 5. LDAP/AD Administration

Key settings:
- `SECRET_SERVER_LDAP_ENABLED`
- `SECRET_SERVER_LDAP_REQUIRE_LDAPS`
- `SECRET_SERVER_LDAP_FALLBACK_LOCAL`
- `SECRET_SERVER_LDAP_ALLOW_LOCAL_FALLBACK_IN_PRODUCTION`
- `SECRET_SERVER_LDAP_ROLE_GROUP_MAP`

Recommended production posture:
- LDAPS required
- Local fallback disabled in production unless formally approved
- Explicit group-to-role mapping

Reference:
- `docs/ldap-troubleshooting.md`

## 6. API Token Governance

- Issue tokens with minimum required scopes (`read`, `write`, `admin`).
- Prefer short expirations for automation tokens.
- Rotate/revoke on personnel or integration changes.
- Treat raw token display as one-time secret.

## 7. Audit Operations

Admin endpoints:
- `GET /api/v1/audit`
- `GET /api/v1/audit/export?format=json|csv`
- `GET /api/v1/audit/verify`

Routine checks:
1. Review authentication failures and permission-denied spikes.
2. Review high-risk actions (secret reveal/update/delete, role changes).
3. Validate audit chain integrity periodically.
4. Export and archive audit artifacts per policy.

## 8. Security Operations Checklist

Daily/weekly checks:
- Review failed logins/lockouts.
- Review admin role changes.
- Confirm backup completion status.
- Verify SIEM forwarding health.
- Review dependency vulnerability scan outputs.

References:
- `docs/browser-security-review.md`
- `docs/dependency-vulnerability-process.md`
- `docs/siem-validation.md`

## 9. Backup and Recovery Administration

Backup:

```powershell
powershell -NoProfile -File infra/scripts/backup.ps1
```

Restore:

```powershell
powershell -NoProfile -File infra/scripts/restore.ps1 -EncryptedBackup C:\backup\secret-server\secret_server_YYYYMMDD_HHMMSS.zip.enc
```

Drill automation:

```powershell
powershell -NoProfile -File infra/scripts/run-backup-restore-drill.ps1 -Runs 3
```

Evidence reference:
- `docs/backup-restore-evidence.md`

## 10. Release Promotion and Rollback

Promotion with rollback enabled:

```powershell
powershell -NoProfile -File infra/scripts/promote-release.ps1 -PackagePath C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip -ChecksumFile C:\path\to\secret_server_release_YYYYMMDD_HHMMSS.zip.sha256 -BaseUrl https://your-secret-server-host -RollbackOnFailure
```

Validation harness:

```powershell
powershell -NoProfile -File infra/scripts/run-promotion-validation.ps1
```

Evidence reference:
- `docs/staging-promotion-evidence.md`

## 11. Incident Response (Admin Playbook)

1. Confirm service health (`/health`, `/health/deps`).
2. Check auth and permission failure trends in audit logs.
3. Verify audit integrity (`/api/v1/audit/verify`).
4. Isolate high-risk tokens/users (deactivate/revoke/rotate).
5. Restore from latest known-good backup if integrity is in doubt.
6. Document timeline, impact, and remediation.

## 12. Governance and Sign-Off Artifacts

- Risk register: `docs/risk-register.md`
- Go-live checklist: `docs/go-live-checklist.md`
- Release decision criteria: `docs/release-decision-and-rollback-criteria.md`

## 13. Related Documents

- End-user guide: `docs/user-guide.md`
- Operations runbook: `docs/operations-runbook.md`
- Web application server setup: `docs/webapp-server-installation-configuration.md`
- SQL setup: `docs/sql-server-fresh-setup.md`

