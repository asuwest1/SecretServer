# Go-Live Checklist

Date: 2026-03-06
Release: Secret Server production-candidate (MVP)

## Security Sign-off

- [x] No open critical security defects in current tracked backlog.
- [x] Authz abuse-path regression tests passing.
- [x] JWT rotation/replay protections validated.
- [x] LDAP/AD hardening controls validated (LDAPS/config checks).
- [x] Browser security posture review completed and documented.
- [ ] Production TLS certificate chain validated in target environment.

## Operations Sign-off

- [x] Backup/restore drill evidence captured with multiple successful runs.
- [x] RTO/RPO measured and below runbook targets.
- [x] Promotion validation completed with checksum verification.
- [x] Forced-failure rollback path validated.
- [x] Smoke test script and runbook available.
- [ ] Production monitoring/alert routing confirmed in target environment.

## Quality Gates

- [x] `npm test` passing.
- [x] `npm run test:integration:api` passing.
- [x] `npm run test:integration:ldap` passing.
- [x] `npm run test:perf:api` passing and within documented thresholds.
- [x] PRD traceability matrix updated.

## Release Readiness Decision

- [ ] Security sign-off complete.
- [ ] Operations sign-off complete.
- [ ] Engineering sign-off complete.
- [ ] Final go/no-go meeting recorded.

## Sign-off Record

- Security Lead: Pending
- Operations Lead: Pending
- Engineering Lead: Pending
- Product Owner: Pending
- Decision Timestamp: Pending
