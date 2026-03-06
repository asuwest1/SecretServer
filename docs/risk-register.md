# Release Risk Register

Date: 2026-03-06
Scope: Secret Server production-candidate release governance.

Status legend:
- Open: unresolved and not accepted.
- Mitigated: control implemented and verified.
- Accepted: known residual risk approved for this release.

| ID | Risk | Category | Likelihood | Impact | Status | Mitigation / Decision | Owner | Target Date |
|---|---|---|---|---|---|---|---|---|
| R-001 | Unauthorized access due to authz edge-case regression | Security | Medium | High | Mitigated | Added abuse-path integration coverage and ACL precedence tests in `tests/integration-api.js`. | Security + Backend | 2026-03-06 |
| R-002 | Refresh token replay or rotation misuse | Security | Medium | High | Mitigated | Added refresh replay and misuse tests; invalid token type rejected in auth flow. | Security + Backend | 2026-03-06 |
| R-003 | LDAP misconfiguration causing auth outage | Reliability | Medium | Medium | Mitigated | Added LDAP config validation + troubleshooting runbook + integration tests. | Backend + Ops | 2026-03-06 |
| R-004 | Audit tampering or integrity loss | Security/Compliance | Low | High | Mitigated | Implemented audit hash-chain verification endpoint and tests. | Security + Backend | 2026-03-06 |
| R-005 | Syslog forwarding silent failure | Operations | Medium | Medium | Mitigated | Added protocol/failure-mode tests and SIEM validation procedure. | Ops | 2026-03-06 |
| R-006 | Backup/restore failure under incident pressure | Resilience | Medium | High | Mitigated | Automated backup/restore drills with logged fingerprint parity and RTO/RPO evidence. | Ops | 2026-03-06 |
| R-007 | Staging promotion failure without rollback | Deployment | Medium | High | Mitigated | Added promotion validation harness with forced-failure rollback proof. | Ops | 2026-03-06 |
| R-008 | TLS certificate or trust chain issues in production | Security/Infra | Low | High | Open | Operational cert lifecycle and external trust validation still environment-dependent; verify at go-live change window. | Infra/Ops | 2026-03-10 |
| R-009 | SQL plaintext-at-rest verification gap for all data paths | Security | Low | Medium | Accepted | Core crypto validated and SQL integration present; full database-wide plaintext scan deferred to next hardening cycle. | Security | 2026-03-15 |
| R-010 | Performance degradation under production-scale dataset | Performance | Medium | Medium | Accepted | Baseline and near-capacity local harness results are within thresholds; production-like load test deferred to post-MVP phase. | Backend + Ops | 2026-03-20 |

## Acceptance Notes

- R-009 accepted for this release candidate with explicit follow-up action in next cycle.
- R-010 accepted with monitoring requirement during initial production rollout.

## Sign-off

- Security Lead: Pending
- Operations Lead: Pending
- Engineering Lead: Pending
