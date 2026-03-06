# PRD Acceptance Trace Matrix

This matrix maps each PRD production acceptance criterion to concrete implementation and evidence.

Legend:
- `Pass`: implemented with automated evidence in current CI/tests.
- `Partial`: implemented, but missing one or more explicit automated checks or measurable proof.
- `Fail`: not implemented.

## Acceptance Criteria Matrix

| PRD Criterion | Implementation Files | Automated Test Coverage | Evidence / CI Link | Status | Owner | Target Date |
|---|---|---|---|---|---|---|
| 1. View-only user can reveal but cannot edit/delete | `src/api/routes/secrets.js`, `src/api/services/permissions.js` | `tests/integration-api.js` (view success, write/delete denial patterns), `npm run test:integration:api` | GitHub Actions workflow: `.github/workflows/ci.yml` job `test` step `Run backend API integration tests` | Pass | Backend | March 6, 2026 |
| 2. User with no role gets denied and cannot discover secret | `src/api/routes/secrets.js`, `src/api/services/permissions.js` | `tests/integration-api.js` (bob list empty + reveal 403) | `.github/workflows/ci.yml` job `test` | Pass | Backend | March 6, 2026 |
| 3. Secret reveal action appears in audit log with correct user/timestamp quickly | `src/api/routes/secrets.js`, `src/api/routes/audit.js`, `src/api/data/store.js`, `src/api/data/sql-store.js` | `tests/integration-api.js` (audit action presence) | `.github/workflows/ci.yml` job `test` | Partial | Backend | March 14, 2026 |
| 4. DB inspection shows no plaintext credentials in secrets table | `src/api/lib/crypto.js`, `src/api/data/sql-store.js` | `tests/integration-sql.js`, `tests/integration-api-sql.js` validate encrypted object persistence and SQL round-trip | `.github/workflows/ci.yml` job `integration-sql` | Partial | Security + Backend | March 20, 2026 |
| 5. Removing key file makes secrets unreadable after restart | `src/api/lib/crypto.js`, `src/api/server.js` | Unit-level crypto tests exist (`tests/run-tests.js`) but no explicit restart-without-key integration test | `npm test` currently covers crypto round-trip only | Partial | Backend | March 20, 2026 |
| 6. Account lockout after 5 failed attempts and unlock flow/cooldown | `src/api/routes/auth.js`, `src/api/lib/config.js` | Auth tests cover baseline login flows; no dedicated lockout abuse-path test sequence yet | `npm test`, `npm run test:integration:api` | Partial | Security + Backend | March 14, 2026 |
| 7. TLS enforced and HTTP redirected to HTTPS with valid cert | `infra/iis/web.config`, `src/api/server.js` (HSTS/security headers) | Smoke currently checks app/health/login behavior; no explicit HTTP->HTTPS redirect assertion in CI | `infra/scripts/smoke-test.ps1` exists; add redirect assertion next | Partial | Infra/Ops | March 14, 2026 |
| 8. Backup+restore cycle under 2h with post-restore accessibility | `infra/scripts/backup.ps1`, `infra/scripts/restore.ps1`, `infra/scripts/run-backup-restore-drill.ps1`, `docs/backup-restore-evidence.md` | `infra/scripts/run-backup-restore-drill.ps1` with 3 successful runs and fingerprint parity | `artifacts/drills/logs/backup_restore_drill_20260306_075614.json` | Pass | Ops | March 6, 2026 |

## Criterion-Level Notes

- Criterion 3: action logging is present; explicit `<=1 second` SLO assertion is not yet codified as a timed test.
- Criterion 4: encryption at rest behavior is implemented, but a dedicated SQL plaintext scan assertion should be added for stronger proof.
- Criterion 8: backup/restore tooling is implemented, but measured RTO/RPO evidence logs are still pending.

## Current Evidence Sources

- CI workflow: `.github/workflows/ci.yml`
  - Job `test`: unit + in-memory integration + web tests/build.
  - Job `integration-sql`: migrations + SQL integration + SQL API integration.
- Local test entry points:
  - `npm test`
  - `npm run test:integration:api`
  - `npm run test:integration:sql`
  - `npm run test:integration:api:sql`
  - `npm run web:test`

## Ownership Convention

- `Backend`: API/auth/permissions/data-layer implementation and tests.
- `Infra/Ops`: IIS, TLS, deployment, backup/restore, production validation.
- `Security`: abuse-path, crypto-at-rest evidence, risk sign-off.

