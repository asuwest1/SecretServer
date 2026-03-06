# Windows Secret Protection (DPAPI + IIS)

This guide implements production secret handling without plaintext secrets in checked-in files.

## 1. Design

- Secret values are stored as DPAPI-protected files (LocalMachine scope).
- API process loads protected values at startup when `SECRET_SERVER_PROTECTED_SECRETS_DIR` is configured.
- Secret/key directories are ACL-hardened for `SYSTEM`, `Administrators`, and IIS App Pool identity.

## 2. Configure Environment

Set these machine-level values:

```powershell
SECRET_SERVER_PROTECTED_SECRETS_DIR=C:\inetpub\secret-server\secrets\protected
SECRET_SERVER_SQL_PASSWORD_FILE=sql_password.bin
SECRET_SERVER_LDAP_PASSWORD_FILE=ldap_password.bin
SECRET_SERVER_BACKUP_PASSPHRASE_FILE=backup_passphrase.bin
```

Apply via env file:

```powershell
powershell -NoProfile -File infra/scripts/apply-env-file.ps1 -EnvFile C:\secure\secret-server.env -Target Machine
```

## 3. Create Protected Secret Files

Write SQL password:

```powershell
powershell -NoProfile -File infra/scripts/write-protected-secret.ps1 -FilePath C:\inetpub\secret-server\secrets\protected\sql_password.bin -Value '<SQL_PASSWORD>' -CreateParent
```

Write LDAP bind password:

```powershell
powershell -NoProfile -File infra/scripts/write-protected-secret.ps1 -FilePath C:\inetpub\secret-server\secrets\protected\ldap_password.bin -Value '<LDAP_PASSWORD>' -CreateParent
```

Write backup passphrase:

```powershell
powershell -NoProfile -File infra/scripts/write-protected-secret.ps1 -FilePath C:\inetpub\secret-server\secrets\protected\backup_passphrase.bin -Value '<BACKUP_PASSPHRASE>' -CreateParent
```

## 4. Harden ACLs

Harden key/secrets directory ACL for app pool read-only access:

```powershell
powershell -NoProfile -File infra/scripts/harden-secrets-acl.ps1 -SecretsPath C:\inetpub\secret-server\secrets -AppPoolName SecretServerPool
```

## 5. Runtime Behavior

At API startup, if an env var is missing, the server attempts to load it from DPAPI-protected files:

- `SECRET_SERVER_SQL_PASSWORD`
- `SECRET_SERVER_LDAP_PASSWORD`
- `SECRET_SERVER_BACKUP_PASSPHRASE`

Loader implementation:
- `src/api/lib/protected-secrets.js`
- invoked from `src/api/server.js`

## 6. Validation

Optional read test for each file:

```powershell
powershell -NoProfile -File infra/scripts/read-protected-secret.ps1 -FilePath C:\inetpub\secret-server\secrets\protected\sql_password.bin
```

Then recycle app pool and validate app health:

```powershell
Restart-WebAppPool -Name SecretServerPool
powershell -NoProfile -File infra/scripts/smoke-test.ps1 -BaseUrl https://your-secret-server-host -SkipTlsValidation
```

## 7. Rotation Procedure

1. Generate new secret value.
2. Rewrite protected file with `write-protected-secret.ps1`.
3. Recycle app pool.
4. Validate health and auth/data paths.
5. Record change in operational change log.

For JWT signing key rotation also run:

```powershell
powershell -NoProfile -File infra/scripts/rotate-jwt-key.ps1 -KeyFile C:\inetpub\secret-server\secrets\jwt.key
```

## 8. Notes and Constraints

- DPAPI LocalMachine scope means secrets are decryptable only on the same Windows machine context.
- For multi-node deployments, create protected secrets independently on each node.
- Do not store plaintext secret values in repository, release artifacts, or deployment logs.
