# Staging Promotion Validation Evidence

Date executed: 2026-03-06

Command used:

```powershell
powershell -NoProfile -File infra/scripts/run-promotion-validation.ps1
```

Primary outputs:

- Package: `artifacts/promotion-validation/secret_server_release_20260306_080110.zip`
- Detached checksum: `artifacts/promotion-validation/secret_server_release_20260306_080110.zip.sha256`
- Validation log: `artifacts/promotion-validation/logs/promotion_validation_20260306_080123.json`

Validated scenarios:

1. Successful promotion path
- Package checksum and internal content checksum verified.
- Promotion completed with smoke pass.
- Result: `passed = true`.

2. Forced-failure rollback path
- Smoke script intentionally failed post-deploy.
- Promotion triggered rollback to pre-deploy snapshot.
- Result: `failureObserved = true`, `rollbackPassed = true`, `restoredVersion = old`.

Conclusion:

- Staged promotion flow is repeatable with checksum verification.
- Automatic rollback behavior under forced failure is validated.
