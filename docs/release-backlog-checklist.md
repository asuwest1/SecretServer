# Release Backlog Checklist

This checklist tracks remaining work to reach production-candidate readiness against the PRD plan.

## 1. Stack Compliance
- [x] Confirm final backend runtime decision (`ASP.NET Core 8` required vs accepted Node runtime deviation).
- [x] If required, complete backend migration plan and implementation milestones.
- [x] Update all architecture docs to match actual runtime and deployment model.

Done when:
- Runtime/hosting stack is formally approved and reflected in implementation + docs.

Status note:
- Approved runtime decision: Node.js backend + React frontend + SQL Server persistence.

References:
- `Secret Server_TechSpec.md`
- `README.md`

## 2. PRD Acceptance Traceability
- [x] Create criterion-by-criterion trace matrix mapping `PRD requirement -> implementation file -> automated test -> evidence`.
- [x] Mark each criterion as `Pass`, `Partial`, or `Fail` with owner and target date.
- [x] Add CI/test evidence links for all `Pass` criteria.

Done when:
- Every PRD acceptance criterion has explicit evidence and no ambiguous status.

References:
- `Secret server_PRD.md`
- `docs/prd-traceability-matrix.md`
- `docs/operations-runbook.md`

## 3. Frontend Feature Completion
- [x] Implement full ACL management UX (folder + secret ACL editing).
- [x] Implement secret version UX (view history, compare metadata, safe revert flow if in scope).
- [x] Implement audit query/export UI with filters and download options.
- [x] Add robust empty/error/loading states for all major screens.
- [x] Expand frontend tests for all completed flows.

Done when:
- All in-scope PRD UI workflows are available and tested.

References:
- `src/web/src/App.jsx`
- `src/web/src/App.test.jsx`

## 4. LDAP/AD Hardening
- [x] Add robust LDAPS validation and explicit configuration validation errors.
- [x] Add integration tests for LDAP success/failure/fallback and group mapping behavior.
- [x] Document LDAP operational troubleshooting (timeouts, auth failures, cert errors).

Done when:
- LDAP flows are deterministic, test-covered, and operationally supportable.

References:
- `src/api/services/ldap.js`
- `src/api/routes/auth.js`
- `infra/scripts/ldap-auth.ps1`

## 5. ACL and Inheritance Edge Cases
- [x] Define explicit precedence rules (inheritance + direct ACL conflict handling).
- [x] Add tests for deep folder hierarchies and mixed ACL grants.
- [x] Validate list/search/reveal/update/delete permission consistency under edge conditions.

Done when:
- ACL resolution behavior is spec-defined and comprehensively regression-tested.

References:
- `src/api/services/permissions.js`
- `src/api/routes/folders.js`
- `src/api/routes/secrets.js`

## 6. API Contract Hardening
- [x] Add/complete strict request validation across endpoints.
- [x] Finalize standardized error code catalog and ensure consistent responses.
- [x] Ensure OpenAPI coverage matches live API behavior exactly.
- [x] Add contract tests for representative success/failure paths.

Done when:
- API behavior, docs, and tests are aligned with no undocumented responses.

References:
- `docs/openapi.yaml`
- `src/api/lib/http.js`
- `src/api/routes/`

## 7. Audit and SIEM Integrity
- [x] Validate immutability controls and retention behavior under operational load.
- [x] Add syslog integration tests for configured protocols and failure modes.
- [x] Document SIEM forwarding expectations and validation procedure.

Done when:
- Audit and SIEM paths are verifiably complete and resilient.

References:
- `src/api/services/syslog.js`
- `src/api/routes/audit.js`

## 8. Security Verification Expansion
- [x] Add deeper authz abuse-path tests (horizontal and vertical escalation attempts).
- [x] Add JWT misuse/rotation edge-case tests and replay scenarios.
- [x] Review browser security posture for CSRF/XSS and document residual risk.
- [x] Add dependency vulnerability monitoring and response process.

Done when:
- Security regression suite covers top risks and gates CI.

References:
- `tests/integration-api.js`
- `.github/workflows/security-checks.yml`

## 9. Performance Qualification
- [x] Define target workload profile and acceptance thresholds (p95/p99).
- [x] Add repeatable perf scripts for reveal/search/list/auth flows.
- [x] Execute and record baseline + near-capacity results.

Done when:
- Performance targets are measured and passing with reproducible evidence.

References:
- `tests/perf-api.js`
- `README.md`

## 10. Backup/Restore Evidence
- [x] Run recurring backup/restore drills and capture run logs.
- [x] Measure and record RTO/RPO outcomes over multiple runs.
- [x] Validate post-restore integrity (health, auth, sample data access).

Done when:
- Recovery objectives are demonstrably achieved with historical evidence.

References:
- `infra/scripts/backup.ps1`
- `infra/scripts/restore.ps1`
- `docs/operations-runbook.md`

## 11. Staging Promotion Validation
- [x] Execute full staged promotion using package + checksum verification.
- [x] Execute forced-failure scenario and confirm automatic rollback behavior.
- [x] Record promotion and rollback evidence with timestamps.

Done when:
- Promotion path is proven safe and repeatable in staging.

References:
- `infra/scripts/promote-release.ps1`
- `infra/scripts/deploy-from-package.ps1`
- `infra/scripts/smoke-test.ps1`

## 12. Final Release Governance
- [x] Create risk register with open/accepted/mitigated statuses.
- [x] Create go-live checklist with security and ops sign-offs.
- [x] Document release decision and rollback criteria.

Done when:
- Release approval artifacts are complete, reviewed, and linked from repo docs.

References:
- `docs/` (add release artifacts)
- `README.md`








