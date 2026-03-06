# Release Decision and Rollback Criteria

Date: 2026-03-06
Scope: Production-candidate release governance for Secret Server MVP.

## Go/No-Go Decision Criteria

Release is approved only if all are true:

1. No open critical security issues.
2. All PRD acceptance criteria are either `Pass` or explicitly accepted in risk register.
3. Required test suites pass:
   - `npm test`
   - `npm run test:integration:api`
   - `npm run test:integration:ldap`
4. Backup/restore drill evidence exists with successful integrity checks.
5. Promotion validation evidence exists with successful forced-failure rollback.
6. Security and operations sign-offs are documented in `docs/go-live-checklist.md`.

## Immediate Rollback Triggers

Rollback must be initiated if any occur after deployment:

1. `/health` fails for more than 5 consecutive minutes.
2. Authentication failure rate exceeds 20% for 10 minutes without external dependency outage explanation.
3. Any confirmed privilege escalation or unauthorized secret access event.
4. Audit log integrity verification (`/api/v1/audit/verify`) reports failure.
5. Data corruption or unrecoverable errors in secret reveal/update core workflows.

## Rollback Procedure

1. Stop promotion and capture incident timestamp.
2. Run rollback-capable promotion flow using last known good package/snapshot.
3. Re-run smoke validation (`infra/scripts/smoke-test.ps1`).
4. Validate backup restore readiness if data integrity concern persists.
5. Record incident and rollback outcome in release notes and risk register.

## Post-Rollback Exit Criteria

1. Service health stable for 30 minutes.
2. Auth and secret workflows validated by smoke checks.
3. Root cause owner assigned with remediation ETA.
4. Updated release decision documented before re-attempt.
