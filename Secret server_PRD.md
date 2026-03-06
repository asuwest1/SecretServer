# Secret Server
## Shared Password & Secrets Management Application
### Product Requirements Document

| Field | Value |
|---|---|
| Document Version | 1.0 |
| Status | Draft – Pending Review |
| Date | February 2026 |
| Classification | Internal / Confidential |
| Audience | IT Management, Security, Development Team |

---

## 1. Executive Summary

Secret Server is an on-premises, server-based web application that provides network and systems administrators with a centralized, role-based platform for storing, sharing, and managing passwords and other sensitive secrets. All data at rest is protected with AES-256 encryption. Access to every secret is governed by a granular permission model tied to user-assigned roles, enabling least-privilege access and comprehensive audit logging.

This document defines the functional requirements, security architecture, user roles, data model, and non-functional requirements necessary to design, build, test, and deploy Secret Server.

---

## 2. Goals & Objectives

### 2.1 Business Goals

- Eliminate the use of insecure shared spreadsheets, sticky notes, and unencrypted text files for credential storage.
- Enforce least-privilege access through role-based permissions on individual secrets.
- Provide a full audit trail for all secret access and modification events.
- Operate entirely on-premises with no dependency on third-party cloud services.

### 2.2 Success Metrics

| Metric | Target |
|---|---|
| Time to onboard a new admin | < 10 minutes |
| Secrets retrievable per role per audit period | 100% traceable |
| Data-at-rest encryption strength | AES-256 minimum |
| System availability | ≥ 99.5% (scheduled maintenance excluded) |
| Authentication failure lockout | After 5 consecutive failures |

---

## 3. Scope

### 3.1 In Scope

- Web application accessible via modern browsers (Chrome, Firefox, Edge).
- User and role management by administrators.
- Secrets vault with CRUD operations and role-based permission enforcement.
- AES-256 encryption of all secrets and sensitive metadata at rest.
- Comprehensive audit logging.
- LDAP / Active Directory integration (optional, configurable) — included in v1.0.
- RESTful API for automation and scripting.

### 3.2 Out of Scope (Version 1.0)

- Mobile native applications (iOS / Android).
- Cloud-hosted SaaS deployment model.
- Hardware Security Module (HSM) integration (planned for v2.0).
- Password health scoring / breach monitoring.

---

## 4. Stakeholders

| Stakeholder | Role | Interest |
|---|---|---|
| IT / Systems Administrators | Primary Users | Secure credential sharing, role management |
| IT Manager / Security Officer | Administrator | Policy enforcement, audit oversight |
| Development / DevOps Team | Builders / API Consumers | Automation, CI/CD secret injection |
| Compliance / Auditors | Reviewers | Access logs, encryption attestation |

---

## 5. User Roles & Permissions

### 5.1 System-Level Roles

Secret Server defines two system-level roles that apply globally across the application:

| System Role | Capabilities |
|---|---|
| **Super Admin** | Full system access: manage users, assign roles, manage all secrets, configure system settings, view all audit logs, define custom roles. |
| **User** | Access to secrets is determined entirely by role-based secret permissions (see §5.2). |

### 5.2 Custom Roles

Super Admins may create any number of named custom roles (e.g., Network-Admins, Database-Admins, NOC-Team). A user may be assigned multiple roles simultaneously. Effective permissions are the union of all assigned roles.

### 5.3 Secret-Level Permissions

Each secret has an Access Control List (ACL). Roles are added to the ACL and assigned one or more of the following permissions independently:

| Permission | Description |
|---|---|
| **Add** | User may create new secrets within a folder/category to which this role has Add permission. |
| **View** | User may reveal and copy the secret value. Triggers an audit log entry. |
| **Change** | User may edit the secret name, value, metadata, and notes. |
| **Delete** | User may soft-delete a secret (moved to Trash, recoverable for 30 days). |

Permissions are additive across roles. A user holding Role A (View only) and Role B (Change only) on the same secret effectively has both View and Change permissions.

### 5.4 Role Assignment Example

| Role Name | Add | View | Change | Delete |
|---|:---:|:---:|:---:|:---:|
| Network-Admins | ✓ | ✓ | ✓ | ✓ |
| Database-Admins | ✓ | ✓ | ✓ | ✓ |
| NOC-Team (read-only) | | ✓ | | |
| Help-Desk | ✓ | ✓ | ✓ | |

---

## 6. Functional Requirements

### 6.1 Authentication & Session Management

- **FR-AUTH-01:** Users must authenticate with a username and strong password before accessing the application.
- **FR-AUTH-02:** Multi-Factor Authentication (MFA) must be supported (TOTP/RFC 6238). Enforced at Super Admin discretion.
- **FR-AUTH-03:** LDAP / Active Directory authentication integration must be configurable.
- **FR-AUTH-04:** Sessions must expire after a configurable idle period (default: 15 minutes).
- **FR-AUTH-05:** Accounts must lock after 5 consecutive failed login attempts. Unlock via Super Admin or configurable cool-down timer.
- **FR-AUTH-06:** All authentication events (success, failure, lockout, MFA bypass) must be recorded in the audit log.

### 6.2 User Management

- **FR-USER-01:** Super Admins can create, edit, deactivate, and delete user accounts.
- **FR-USER-02:** Users can be assigned multiple roles simultaneously.
- **FR-USER-03:** Deactivated users cannot log in; their audit history is preserved.
- **FR-USER-04:** Super Admins can force a password reset on any account.
- **FR-USER-05:** User profile includes: username, display name, email, assigned roles, MFA status, account status.

### 6.3 Role Management

- **FR-ROLE-01:** Super Admins can create, rename, and delete custom roles.
- **FR-ROLE-02:** Deleting a role does not delete secrets; it removes the role from all secret ACLs.
- **FR-ROLE-03:** The system must display which users and which secrets are associated with a role before deletion is confirmed.

### 6.4 Secrets Vault

- **FR-VAULT-01:** Secrets are stored in a hierarchical folder / category structure.
- **FR-VAULT-02:** Secret types include: Password, SSH Key, API Key, Certificate, Secure Note, Connection String, and Custom (user-defined fields).
- **FR-VAULT-03:** Each secret stores: Name, Type, Secret Value, URL (optional), Username (optional), Notes, Tags, Created By, Created Date, Last Modified By, Last Modified Date.
- **FR-VAULT-04:** Secret values are never displayed in plain text in list views; they are masked by default.
- **FR-VAULT-05:** A "Reveal" action requires the user to have View permission and is logged in the audit trail.
- **FR-VAULT-06:** Copy-to-clipboard clears automatically after a configurable interval (default: 30 seconds).
- **FR-VAULT-07:** Secret version history is maintained for a minimum of 20 prior versions per secret.
- **FR-VAULT-08:** Deleted secrets are soft-deleted to a Trash area, recoverable for 30 days, then permanently purged.
- **FR-VAULT-09:** Bulk import via CSV / KeePass XML export must be supported by Super Admins.

### 6.5 Access Control

- **FR-ACL-01:** Each secret has an ACL listing roles and their granted permissions (Add, View, Change, Delete).
- **FR-ACL-02:** A secret with no ACL entries is accessible only by Super Admins.
- **FR-ACL-03:** ACL management (adding/removing roles and permissions on a secret) requires the user to hold Change permission on that secret, or to be a Super Admin.
- **FR-ACL-04:** Folder-level permissions may be set and are inherited by contained secrets unless overridden at the secret level.

### 6.6 Search & Discovery

- **FR-SEARCH-01:** Full-text search across secret names, usernames, URLs, tags, and notes (excluding secret values).
- **FR-SEARCH-02:** Search results are automatically filtered to only show secrets the current user has at least View permission for.
- **FR-SEARCH-03:** Advanced filter by: folder, type, tag, last-modified date range, created-by user.

### 6.7 Audit & Logging

- **FR-AUDIT-01:** All actions against secrets (view, create, edit, delete, restore) are recorded with: timestamp, user, action type, secret name/ID.
- **FR-AUDIT-02:** Authentication events, role assignments, and system configuration changes are logged.
- **FR-AUDIT-03:** Audit logs are immutable from within the application; only database-level backup/restore can affect them.
- **FR-AUDIT-04:** Super Admins may export audit logs as CSV or JSON for a specified date range.
- **FR-AUDIT-05:** Syslog forwarding (UDP/TCP) must be configurable for SIEM integration.

### 6.8 API

- **FR-API-01:** A RESTful API must be provided supporting all secret CRUD operations and user/role management.
- **FR-API-02:** API authentication via API tokens (per user) with configurable expiry.
- **FR-API-03:** API tokens are treated as secrets themselves; they are displayed only at creation time and stored hashed.
- **FR-API-04:** API access is governed by the same role-based permissions as the UI.
- **FR-API-05:** OpenAPI (Swagger) documentation must be generated and hosted at `/api/docs`.

---

## 7. Security Requirements

### 7.1 Encryption at Rest

- **SR-ENC-01:** All secret values must be encrypted at rest using AES-256-GCM.
- **SR-ENC-02:** The encryption key must be derived using PBKDF2 or Argon2id with a per-installation salt, or managed via an external key file/vault.
- **SR-ENC-03:** The database must not store plaintext secret values under any circumstance, including in logs, backups, or temporary files.
- **SR-ENC-04:** Encryption keys must not be stored in the same location as the encrypted database.
- **SR-ENC-05:** The full disk/volume hosting the database must additionally support OS-level encryption (BitLocker, LUKS) as a defense-in-depth layer. Configuration guidance is provided; enforcement is outside the application's scope.

### 7.2 Encryption in Transit

- **SR-TLS-01:** All web traffic must be served over HTTPS (TLS 1.2 minimum; TLS 1.3 recommended).
- **SR-TLS-02:** HTTP access must be permanently redirected to HTTPS.
- **SR-TLS-03:** HSTS headers must be set with a minimum `max-age` of 31,536,000 seconds.

### 7.3 Password & Authentication Security

- **SR-PWD-01:** User passwords must be hashed with Argon2id (or bcrypt with cost ≥ 12) before storage.
- **SR-PWD-02:** Minimum password policy: 12 characters, mixed case, digit, special character (configurable by Super Admin).
- **SR-PWD-03:** The application must detect and reject passwords found in common breach lists (HaveIBeenPwned API or local offline list).

### 7.4 Application Security

- **SR-APP-01:** Input validation and output encoding must prevent SQL injection, XSS, and CSRF.
- **SR-APP-02:** CSRF tokens must be included on all state-changing requests.
- **SR-APP-03:** Rate limiting must be applied to login and API endpoints.
- **SR-APP-04:** Security headers must be set: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
- **SR-APP-05:** Dependency scanning must be integrated into the build pipeline; no known critical CVEs in production dependencies.

---

## 8. Non-Functional Requirements

| Category | Requirement ID | Requirement |
|---|---|---|
| Performance | NFR-PERF-01 | Page load time < 2 seconds for up to 50 concurrent users on recommended hardware. |
| Performance | NFR-PERF-02 | Secret retrieval (decrypt + return) < 500 ms. |
| Availability | NFR-AVAIL-01 | 99.5% uptime excluding planned maintenance windows. |
| Scalability | NFR-SCALE-01 | Support up to 200 users and 50,000 secrets without architecture changes. |
| Backup | NFR-BAK-01 | Automated encrypted daily backups with configurable retention (default: 30 days). |
| Backup | NFR-BAK-02 | Backup restoration must be documented and tested quarterly. |
| Usability | NFR-UX-01 | Web UI must be responsive and functional at 1280px minimum screen width. |
| Maintainability | NFR-MNT-01 | Application must support rolling updates with < 5 minutes downtime. |
| Logging | NFR-LOG-01 | Application and error logs retained for 90 days; audit logs retained for 1 year (configurable). |

---

## 9. Technical Architecture

### 9.1 Recommended Stack

| Layer | Technology Options |
|---|---|
| Web / App Server | ASP.NET Core 8 *(selected — see §13)* |
| Frontend | React or Vue.js (SPA) served by the app server |
| Database | SQL Server 2019+ or PostgreSQL 15+ |
| Encryption Library | BouncyCastle (.NET) / libsodium (Node/Python) |
| Reverse Proxy / TLS | Nginx or IIS with internal CA or Let's Encrypt cert |
| Authentication (optional) | LDAP / Active Directory via LDAPS |
| Containerization | Docker + Docker Compose (optional but recommended) |

### 9.2 Data Model Overview

The core entity relationships are summarized below:

- **Users ↔ Roles:** Many-to-many (`user_roles` junction table).
- **Roles ↔ Secrets:** Many-to-many via ACL table (`role_id`, `secret_id`, `can_add`, `can_view`, `can_change`, `can_delete`).
- **Secrets ↔ Folders:** Many-to-one (secrets belong to a folder).
- **Folders:** Self-referencing hierarchy (`parent_folder_id`).
- **SecretVersions:** One-to-many child of Secrets (stores encrypted prior values).
- **AuditLog:** Append-only table (`user_id`, `action`, `secret_id`, `timestamp`, `ip_address`, `user_agent`).

### 9.3 Encryption Key Management

Secret Server uses a two-tier key model:

- **Master Encryption Key (MEK):** A 256-bit key stored in a separate key file outside the database directory, or optionally in an environment variable / secrets manager on the host OS. The MEK is loaded into memory at application startup and never written to disk in plain form.
- **Data Encryption Keys (DEK):** Per-secret AES-256-GCM keys generated at secret creation. Each DEK is encrypted with the MEK and stored alongside the ciphertext in the database.

This approach ensures that database file theft without the key file does not expose secrets.

---

## 10. Deployment Requirements

### 10.1 Server Prerequisites

| Resource | Minimum | Recommended |
|---|---|---|
| Operating System | Windows Server 2019+ or RHEL/Ubuntu LTS | Same |
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Storage | 100 GB SSD (OS + app + DB) | 200 GB SSD + separate backup volume |
| Network | Static IP or DNS hostname; port 443 firewall-restricted to admin workstations | Same |

### 10.2 Installation

- Installer package or Docker Compose file provided.
- First-run wizard creates the Super Admin account and generates the Master Encryption Key.
- Key file path and all configuration stored in a single `.env` / `appsettings.json` file.

### 10.3 Backup & Recovery

- Automated nightly backup of encrypted database + key file (to a separate path/volume).
- Backup files are themselves AES-256 encrypted with a backup passphrase configured during setup.
- Recovery procedure documented in the Operations Guide; RTO target: < 2 hours.

---

## 11. Compliance & Standards Alignment

| Standard / Framework | Alignment Notes |
|---|---|
| NIST SP 800-63B | MFA support, password strength requirements, breach detection. |
| NIST SP 800-57 | AES-256 key management, key separation, key lifecycle. |
| ISO/IEC 27001 (A.9) | Access control, least privilege, audit trails. |
| CIS Controls v8 – #5 | Account management, privileged access management. |
| CMMC Level 2 (AC.2.006) | Least privilege principle enforced at secret level. |
| AS9100 Rev D | Controlled document environment for credential records. |

---

## 12. Acceptance Criteria

The following conditions must be validated before the application is approved for production use:

1. A user with View-only permission can reveal a secret value but cannot edit or delete it.
2. A user with no role assigned to a secret receives a permission-denied response and sees no indication the secret exists.
3. Every secret reveal action appears in the audit log with correct user and timestamp within 1 second.
4. Database file inspection (hex editor / strings tool) reveals no plaintext credentials in the secrets table.
5. Removing the key file and restarting the application renders all secrets unreadable (application reports encryption key unavailable).
6. An account is locked after 5 failed login attempts and remains locked until an admin unlocks it or the cool-down expires.
7. TLS is enforced; HTTP requests are redirected to HTTPS with a valid certificate.
8. A full backup and restore cycle completes in < 2 hours and all secrets are accessible post-restore.

---

## 13. Architecture Decisions

All open issues from the initial draft have been resolved. Decisions are recorded below for traceability.

| # | Issue | **Decision** | Rationale | Owner |
|---|---|---|---|---|
| 1 | Technology stack finalization | **ASP.NET Core 8 / C#** | Strong crypto ecosystem support (AES-256-GCM in BCL; Argon2id via vetted .NET libraries), type safety, LTS, and strong performance for CPU-bound encryption vs. Node.js. Node.js deferred for potential future API-only microservice use only. | IT Manager |
| 2 | LDAP / AD integration priority | **v1.0 — included** | LDAP/AD is a primary deployment requirement for enterprise environments; deferral would block initial rollout for most target sites. | IT Manager |
| 3 | Key management strategy | **Local key file** | Simplest operational model for on-premises deployments with no additional infrastructure dependency. Key file stored on a separate volume with `chmod 400`. HashiCorp Vault support planned for v2.0. | Security Officer |
| 4 | MFA enforcement policy | **Optional** (Super Admin configurable) | MFA is supported (TOTP/RFC 6238) and can be enforced per-user or globally by a Super Admin. Mandatory enforcement deferred to allow phased rollout. | IT Manager |
| 5 | Audit log retention period | **1 year** | Aligns with ISO/IEC 27001 and CIS Controls guidance. Configurable via `Logging:AuditRetentionDays` for sites with stricter regulatory requirements. | Compliance |

---

## 14. Revision History

| Version | Date | Author | Summary |
|---|---|---|---|
| 1.0 | February 2026 | IT Team | Initial draft. |
| 1.1 | February 2026 | IT Team | Resolved all open architecture decisions: ASP.NET Core 8 selected; LDAP included in v1.0; local key file for MEK; MFA optional; audit log retention set to 1 year. |
