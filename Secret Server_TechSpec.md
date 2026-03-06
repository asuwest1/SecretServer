# Secret Server
## Shared Password & Secrets Management Application
### Technical Specification

| Field | Value |
|---|---|
| Document Version | 1.0 |
| Status | Draft |
| Date | February 2026 |
| Based On | Secret Server PRD v1.0 |
| Classification | Internal / Confidential |
| Audience | Development Team, DevOps, Security Officer |

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Database Design](#4-database-design)
5. [Encryption Architecture](#5-encryption-architecture)
6. [Authentication & Session Management](#6-authentication--session-management)
7. [Authorization & Access Control](#7-authorization--access-control)
8. [API Specification](#8-api-specification)
9. [Frontend Architecture](#9-frontend-architecture)
10. [Audit Logging](#10-audit-logging)
11. [Configuration & Environment](#11-configuration--environment)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Backup & Recovery](#13-backup--recovery)
14. [Security Hardening Checklist](#14-security-hardening-checklist)
15. [Testing Strategy](#15-testing-strategy)
16. [Error Handling & Logging](#16-error-handling--logging)
17. [Build & CI/CD Pipeline](#17-build--cicd-pipeline)
18. [Revision History](#18-revision-history)

---

## 1. Overview

This Technical Specification translates the Secret Server PRD into implementable engineering decisions. It defines the system architecture, database schema, encryption design, API contracts, and deployment pipeline that developers and DevOps engineers will use to build and operate the application.

### 1.1 Design Principles

- **Security first.** Every design decision is evaluated against the threat model before convenience.
- **Least privilege.** No component, user, or process receives more access than it needs.
- **Defense in depth.** Encryption at rest, TLS in transit, application-layer access control, and OS-level disk encryption are all independent layers.
- **Auditability.** Every state-changing operation produces an immutable, timestamped audit record.
- **Air-gap readiness.** The application runs fully offline; no outbound internet dependency is required at runtime.

### 1.2 Threat Model Summary

| Threat | Mitigation |
|---|---|
| Database file stolen from disk | AES-256-GCM encryption; key stored separately |
| Insider threat (over-privileged user) | Secret-level ACL; least-privilege role model |
| Credential stuffing / brute force | Account lockout; rate limiting; MFA |
| Man-in-the-middle | TLS 1.3; HSTS; certificate pinning option |
| XSS / injection attacks | Input validation; CSP headers; parameterized queries |
| Backup theft | Backups independently AES-256 encrypted |
| Session hijacking | Short-lived JWTs; idle timeout; secure cookie flags |

---

## 2. System Architecture

### 2.1 High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Admin Workstations                      │
│              Chrome / Firefox / Edge (HTTPS)                 │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS / TLS 1.3
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Reverse Proxy (Nginx / IIS)                  │
│         TLS termination · HSTS · Security headers            │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP (loopback only)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               Application Server (ASP.NET Core 8)            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Auth Module │  │ Vault Module │  │  Admin Module    │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               Encryption Service                     │    │
│  │   MEK loader · DEK generator · AES-256-GCM wrap/     │    │
│  │   unwrap · Argon2id hashing                          │    │
│  └──────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               Audit Service                          │    │
│  │   Append-only writes · Syslog forwarder              │    │
│  └──────────────────────────────────────────────────────┘    │
└────────┬───────────────────────────┬────────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐       ┌──────────────────────┐
│  SQL Server /   │       │   Key File Store      │
│  PostgreSQL DB  │       │  (separate volume /   │
│  (encrypted     │       │   env variable /      │
│   DEKs + data)  │       │   OS keystore)        │
└─────────────────┘       └──────────────────────┘
         │
         ▼
┌─────────────────┐
│  Backup Volume  │
│ (AES-256 enc.)  │
└─────────────────┘
```

### 2.2 Network Segmentation

- The application server **must not** be internet-facing. Restrict port 443 at the perimeter firewall to admin workstation subnets only.
- Database port (1433 for SQL Server; 5432 for PostgreSQL) must be bound to `127.0.0.1` (loopback) or an isolated VLAN — never exposed to the broader network.
- The key file store must reside on a volume or path not accessible to the database service account.

### 2.3 Process Architecture

| Process | User Account | Privileges |
|---|---|---|
| Nginx / IIS | `www-data` / `IIS_IUSRS` | Read config, bind port 443 |
| Application Server | `Secret Server-app` (dedicated service account) | Read key file, read/write DB |
| Database (SQL Server / PG) | `mssql` / `postgres` | Own DB files only |
| Backup Agent | `Secret Server-backup` | Read DB + key file; write backup volume |

---

## 3. Technology Stack

### 3.1 Selected Stack *(Finalized — February 2026)*

| Layer | Technology | Version | Rationale |
|---|---|---|---|
| Backend Framework | ASP.NET Core | 8.0 LTS | Long-term support; strong crypto libraries; Windows + Linux |
| Language | C# | 12 | Type safety; mature ecosystem |
| Frontend Framework | React | 18.x | Component model; large ecosystem |
| Frontend Build | Vite | 5.x | Fast HMR; tree shaking |
| UI Component Library | shadcn/ui + Tailwind CSS | Latest | Accessible; unstyled base |
| Database | PostgreSQL | 16.x | Open source; strong JSON support; cross-platform |
| ORM | Entity Framework Core | 8.x | Code-first migrations; LINQ |
| Encryption | libsodium-net / BouncyCastle | Latest | AES-256-GCM; Argon2id |
| Authentication | ASP.NET Core Identity + JWT Bearer | Built-in | Integrated with EF Core |
| Reverse Proxy | Nginx | 1.26 stable | TLS termination; headers |
| Containerization | Docker + Docker Compose | 25.x / 2.x | Reproducible environments |
| API Docs | Swashbuckle (Swagger) | 6.x | Auto-generated from attributes |

### 3.2 Node / Browser Requirements

- **Node.js:** 20 LTS (build tooling only; not runtime)
- **Browsers:** Chrome 120+, Firefox 121+, Edge 120+
- **Minimum screen width:** 1280px

### 3.3 Package Management

- Backend: NuGet (`.csproj` / `packages.lock.json` — lock file committed)
- Frontend: npm with `package-lock.json` committed
- Dependency audit: `dotnet list package --vulnerable` + `npm audit` run in CI on every build

---

## 4. Database Design

### 4.1 Schema

#### `users`
```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(64)  NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    email           VARCHAR(256) NOT NULL UNIQUE,
    password_hash   VARCHAR(256) NOT NULL,          -- Argon2id output
    mfa_secret_enc  BYTEA,                           -- TOTP secret, encrypted with MEK
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    is_super_admin  BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    pwd_reset_req   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `roles`
```sql
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(256),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `user_roles`
```sql
CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

#### `folders`
```sql
CREATE TABLE folders (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(128) NOT NULL,
    parent_folder_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    created_by       UUID NOT NULL REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, parent_folder_id)
);
```

#### `secrets`
```sql
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id       UUID NOT NULL REFERENCES folders(id),
    name            VARCHAR(256) NOT NULL,
    secret_type     VARCHAR(32) NOT NULL,            -- password|ssh_key|api_key|certificate|note|connection_string|custom
    username        VARCHAR(256),
    url             VARCHAR(2048),
    notes_enc       BYTEA,                           -- encrypted with DEK
    tags            VARCHAR(64)[],
    value_enc       BYTEA NOT NULL,                  -- AES-256-GCM ciphertext
    dek_enc         BYTEA NOT NULL,                  -- DEK wrapped with MEK
    nonce           BYTEA NOT NULL,                  -- 12-byte GCM nonce
    is_deleted      BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMPTZ,
    purge_after     TIMESTAMPTZ,                     -- deleted_at + 30 days
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      UUID NOT NULL REFERENCES users(id),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_secrets_folder ON secrets(folder_id) WHERE NOT is_deleted;
CREATE INDEX idx_secrets_tags   ON secrets USING GIN(tags);
```

#### `secret_versions`
```sql
CREATE TABLE secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id   UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version_num SMALLINT NOT NULL,
    value_enc   BYTEA NOT NULL,
    dek_enc     BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    notes_enc   BYTEA,
    changed_by  UUID NOT NULL REFERENCES users(id),
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_id, version_num)
);
-- Retain max 20 versions; enforce via application logic + nightly cleanup job
```

#### `secret_acl`
```sql
CREATE TABLE secret_acl (
    secret_id  UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    can_add    BOOLEAN NOT NULL DEFAULT FALSE,
    can_view   BOOLEAN NOT NULL DEFAULT FALSE,
    can_change BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete BOOLEAN NOT NULL DEFAULT FALSE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    PRIMARY KEY (secret_id, role_id)
);
```

#### `folder_acl`
```sql
CREATE TABLE folder_acl (
    folder_id  UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    can_add    BOOLEAN NOT NULL DEFAULT FALSE,
    can_view   BOOLEAN NOT NULL DEFAULT FALSE,
    can_change BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (folder_id, role_id)
);
```

#### `api_tokens`
```sql
CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(64) NOT NULL,
    token_hash  VARCHAR(256) NOT NULL UNIQUE,        -- SHA-256 of raw token
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `audit_log`
```sql
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     UUID REFERENCES users(id),
    username    VARCHAR(64),                         -- denormalized snapshot
    action      VARCHAR(64) NOT NULL,                -- see §10.1 for action codes
    resource    VARCHAR(32),                         -- user|role|secret|folder|token|system
    resource_id UUID,
    secret_name VARCHAR(256),                        -- denormalized snapshot
    ip_address  INET,
    user_agent  TEXT,
    detail      JSONB                                -- action-specific extra fields
);
-- Append-only: revoke DELETE/UPDATE on audit_log from application DB user
CREATE INDEX idx_audit_time      ON audit_log(event_time DESC);
CREATE INDEX idx_audit_user      ON audit_log(user_id);
CREATE INDEX idx_audit_resource  ON audit_log(resource, resource_id);
```

### 4.2 Database User Permissions

```sql
-- Application runtime user
CREATE ROLE Secret Server_app LOGIN PASSWORD '...';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO Secret Server_app;
REVOKE DELETE, UPDATE ON audit_log FROM Secret Server_app;  -- audit_log is append-only

-- Backup/read-only user
CREATE ROLE Secret Server_backup LOGIN PASSWORD '...';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO Secret Server_backup;
```

### 4.3 Full-Text Search

PostgreSQL `tsvector` column on `secrets` covering `name`, `username`, `url`, and `tags`. Notes are **excluded** from search index (they may contain sensitive context). Search queries are scoped by the effective permission set of the requesting user using a CTE-based permission check before the text match.

---

## 5. Encryption Architecture

### 5.1 Two-Tier Key Model

```
Master Encryption Key (MEK)
  256-bit · loaded from key file at startup · held in memory only
      │
      ▼ wraps/unwraps
Data Encryption Keys (DEK) — one per secret
  256-bit · generated fresh at secret creation
  stored as: AES-256-GCM( DEK, MEK, nonce_dek ) → dek_enc column
      │
      ▼ encrypts
Secret Value
  stored as: AES-256-GCM( plaintext, DEK, nonce_val ) → value_enc column
```

### 5.2 MEK Lifecycle

| Event | Action |
|---|---|
| First install | Wizard generates 32 random bytes via `RandomNumberGenerator.GetBytes(32)`; writes to key file with `chmod 400` |
| Application startup | Key file read into `IMemoryEncryptionService` singleton; file handle closed |
| Key rotation (manual) | Re-encrypt all DEKs with new MEK; atomic swap of key file |
| Key file missing at startup | Application refuses to start; returns HTTP 503 to reverse proxy |

**Selected strategy: Local key file** (see PRD §13, Decision #3). The key file is stored on a volume separate from the database, with permissions `chmod 400`. HashiCorp Vault support is planned for v2.0.

Key file location options (in priority order):
1. **Path specified in `Secret Server_KEY_FILE` environment variable** *(recommended — selected for v1.0)*
2. OS-level secrets manager (Windows DPAPI / Linux kernel keyring) via optional plugin *(v2.0)*
3. `appsettings.json` → `Encryption:KeyFilePath` (not recommended for production)

### 5.3 Encryption Implementation

```csharp
// AES-256-GCM encrypt
public static (byte[] ciphertext, byte[] nonce) Encrypt(byte[] plaintext, byte[] key)
{
    var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // 12 bytes
    RandomNumberGenerator.Fill(nonce);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[AesGcm.TagByteSizes.MaxSize];     // 16 bytes
    using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
    aes.Encrypt(nonce, plaintext, ciphertext, tag);
    // Store tag appended to ciphertext
    return (ciphertext.Concat(tag).ToArray(), nonce);
}

// AES-256-GCM decrypt
public static byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce, byte[] key)
{
    var tag        = ciphertextWithTag[^16..];
    var ciphertext = ciphertextWithTag[..^16];
    var plaintext  = new byte[ciphertext.Length];
    using var aes  = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
    aes.Decrypt(nonce, ciphertext, tag, plaintext);
    return plaintext;
}
```

### 5.4 Password Hashing

```csharp
// Argon2id parameters (OWASP recommended minimums for interactive login)
var config = new Argon2Config
{
    Type         = Argon2Type.HybridAddressing,  // id
    TimeCost     = 3,
    MemoryCost   = 65536,  // 64 MB
    Lanes        = 4,
    Threads      = 4,
    HashLength   = 32,
    Salt         = RandomNumberGenerator.GetBytes(16)
};
```

### 5.5 Secrets Never in Plaintext Outside RAM

- Values are decrypted **in the request handler** and returned directly to the HTTP response body.
- They are **never** written to: EF Core change tracker state (use raw SQL for value column), application logs, temp files, or EF migrations.
- Response for "view secret" returns only the plaintext value — not the DEK, nonce, or any key material.

---

## 6. Authentication & Session Management

### 6.1 Local Authentication Flow

```
1. POST /api/auth/login { username, password }
2. Load user record; check is_active and locked_until
3. Verify Argon2id hash; on failure increment failed_attempts
4. If failed_attempts >= 5 → set locked_until = NOW() + lockout_duration; return 401
5. If MFA enabled → return { mfa_required: true, mfa_token: <short-lived JWT> }
6. POST /api/auth/mfa { mfa_token, totp_code }
7. Verify TOTP against decrypted mfa_secret; on success issue access + refresh tokens
8. Reset failed_attempts = 0; update last_login
```

**MFA Policy (v1.0):** MFA is **optional** and configurable by Super Admins (see PRD §13, Decision #4). It can be enforced globally or per-user via the Admin Module. The default configuration ships with MFA disabled; Super Admins are prompted to review this setting during first-run setup.

### 6.2 Token Design

| Token | Type | Lifetime | Storage |
|---|---|---|---|
| Access Token | JWT (RS256) | 15 minutes | Memory (JS variable) — never localStorage |
| Refresh Token | Opaque UUID | 8 hours (configurable) | HttpOnly Secure SameSite=Strict cookie |
| MFA Challenge Token | JWT (HS256) | 5 minutes | Memory only |
| API Token | SHA-256 hash stored | Configurable / no expiry | Caller stores raw value at creation |

**JWT Claims (Access Token):**
```json
{
  "sub": "<user_uuid>",
  "name": "<display_name>",
  "is_super_admin": false,
  "role_ids": ["<uuid>", "<uuid>"],
  "iat": 1700000000,
  "exp": 1700000900,
  "jti": "<unique_token_id>"
}
```

### 6.3 LDAP / AD Integration *(Included in v1.0 — see PRD §13, Decision #2)*

When `Auth:Mode = "LDAP"` in configuration:
- Bind to LDAP server using service account credentials over LDAPS (port 636).
- Authenticate user via LDAP bind with provided credentials.
- Group membership (configurable `Auth:LdapGroupBase`) maps to Secret Server roles via a configurable mapping table in the database.
- Local password hashing is skipped; the `password_hash` column stores a sentinel value.
- MFA still applies if enabled.

### 6.4 Session Security

```
Set-Cookie: refresh_token=<value>;
            HttpOnly;
            Secure;
            SameSite=Strict;
            Path=/api/auth/refresh;
            Max-Age=28800
```

- Idle timeout enforced on the frontend (15-minute timer reset on any API activity).
- Backend validates `exp` claim on every request; a sliding window is **not** used for access tokens.
- Logout explicitly revokes the refresh token by deleting it from a `refresh_tokens` table.

---

## 7. Authorization & Access Control

### 7.1 Permission Resolution Algorithm

```
function canAccess(userId, secretId, permission):
  if user.is_super_admin → return ALLOW

  userRoleIds = SELECT role_id FROM user_roles WHERE user_id = userId

  -- Check secret-level ACL first
  aclEntry = SELECT * FROM secret_acl
             WHERE secret_id = secretId
               AND role_id = ANY(userRoleIds)

  if aclEntry exists:
    return ANY(aclEntry.{permission}) ? ALLOW : DENY

  -- Fall back to folder-level ACL (inherited)
  folderId = secret.folder_id
  while folderId is not null:
    folderAcl = SELECT * FROM folder_acl
                WHERE folder_id = folderId
                  AND role_id = ANY(userRoleIds)
    if folderAcl exists:
      return ANY(folderAcl.{permission}) ? ALLOW : DENY
    folderId = folder.parent_folder_id

  return DENY  -- no ACL entry found at any level
```

### 7.2 Middleware Pipeline Order

```
Request
  → TLS (Nginx)
  → Rate Limiter
  → CORS Policy
  → Authentication (JWT Bearer / API Token)
  → Authorization (Role/Permission check)
  → Request Body Size Limit (10 MB)
  → Controller Action
  → Audit Logger (post-action)
Response
```

### 7.3 Search Result Scoping

All secret search and list queries are pre-filtered with a permission CTE before returning results:

```sql
WITH user_roles AS (
  SELECT role_id FROM user_roles WHERE user_id = @userId
),
permitted_secrets AS (
  SELECT DISTINCT s.id
  FROM secrets s
  LEFT JOIN secret_acl sa ON sa.secret_id = s.id AND sa.role_id IN (SELECT role_id FROM user_roles)
  LEFT JOIN folder_acl fa ON fa.folder_id = s.folder_id AND fa.role_id IN (SELECT role_id FROM user_roles)
  WHERE (sa.can_view = TRUE OR fa.can_view = TRUE)
    AND s.is_deleted = FALSE
)
SELECT s.id, s.name, s.secret_type, s.username, s.url, s.tags, s.updated_at
FROM secrets s
JOIN permitted_secrets ps ON ps.id = s.id
WHERE to_tsvector('english', s.name || ' ' || COALESCE(s.username,'') || ' ' || COALESCE(s.url,''))
      @@ plainto_tsquery('english', @query);
```

---

## 8. API Specification

### 8.1 Base URL & Versioning

```
Base:     https://<host>/api/v1
Docs:     https://<host>/api/docs
Auth:     Bearer <access_token>  OR  X-API-Token: <raw_token>
Format:   application/json
```

### 8.2 Endpoint Reference

#### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login` | Username + password login |
| `POST` | `/auth/mfa` | Submit TOTP code after MFA challenge |
| `POST` | `/auth/refresh` | Exchange refresh token for new access token |
| `POST` | `/auth/logout` | Revoke refresh token |

#### Users

| Method | Path | Auth Required | Description |
|---|---|---|---|
| `GET` | `/users` | Super Admin | List all users |
| `POST` | `/users` | Super Admin | Create user |
| `GET` | `/users/{id}` | Super Admin or self | Get user detail |
| `PUT` | `/users/{id}` | Super Admin | Update user |
| `DELETE` | `/users/{id}` | Super Admin | Deactivate user |
| `POST` | `/users/{id}/reset-password` | Super Admin | Force password reset |
| `GET` | `/users/{id}/api-tokens` | Self | List API tokens |
| `POST` | `/users/{id}/api-tokens` | Self | Create API token |
| `DELETE` | `/users/{id}/api-tokens/{tokenId}` | Self or Super Admin | Revoke API token |

#### Roles

| Method | Path | Auth Required | Description |
|---|---|---|---|
| `GET` | `/roles` | Super Admin | List roles |
| `POST` | `/roles` | Super Admin | Create role |
| `PUT` | `/roles/{id}` | Super Admin | Update role |
| `DELETE` | `/roles/{id}` | Super Admin | Delete role (with impact preview) |
| `GET` | `/roles/{id}/members` | Super Admin | List users in role |

#### Folders

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/folders` | Any | List accessible folders |
| `POST` | `/folders` | Super Admin | Create folder |
| `PUT` | `/folders/{id}` | Super Admin | Rename / move folder |
| `DELETE` | `/folders/{id}` | Super Admin | Delete folder (must be empty) |
| `GET` | `/folders/{id}/acl` | Super Admin | Get folder ACL |
| `PUT` | `/folders/{id}/acl` | Super Admin | Set folder ACL |

#### Secrets

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/secrets` | View (scoped) | Search/list accessible secrets |
| `POST` | `/secrets` | Add (on folder) | Create secret |
| `GET` | `/secrets/{id}` | View | Get secret metadata (no value) |
| `GET` | `/secrets/{id}/value` | View | Decrypt and return secret value — **audited** |
| `PUT` | `/secrets/{id}` | Change | Update secret |
| `DELETE` | `/secrets/{id}` | Delete | Soft-delete secret |
| `POST` | `/secrets/{id}/restore` | Change | Restore from Trash |
| `GET` | `/secrets/{id}/versions` | Change | List version history |
| `GET` | `/secrets/{id}/versions/{ver}` | Change | Get historical version value — **audited** |
| `GET` | `/secrets/{id}/acl` | Change | Get secret ACL |
| `PUT` | `/secrets/{id}/acl` | Change | Update secret ACL |
| `POST` | `/secrets/import` | Super Admin | Bulk import (CSV / KeePass XML) |

#### Audit

| Method | Path | Auth Required | Description |
|---|---|---|---|
| `GET` | `/audit` | Super Admin | Query audit log (filterable) |
| `GET` | `/audit/export` | Super Admin | Export as CSV or JSON |

### 8.3 Standard Response Envelopes

**Success:**
```json
{
  "data": { ... },
  "meta": { "page": 1, "pageSize": 50, "total": 243 }
}
```

**Error:**
```json
{
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "You do not have permission to view this secret.",
    "traceId": "00-abc123-def456-00"
  }
}
```

### 8.4 Error Codes

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Request body failed validation |
| 401 | `UNAUTHENTICATED` | Missing or expired token |
| 401 | `MFA_REQUIRED` | MFA challenge needed |
| 403 | `PERMISSION_DENIED` | Authenticated but not authorized |
| 404 | `NOT_FOUND` | Resource does not exist or is not visible to caller |
| 409 | `CONFLICT` | Duplicate name / unique constraint |
| 422 | `IMPORT_ERROR` | Import file parse failure |
| 429 | `RATE_LIMITED` | Too many requests |
| 503 | `KEY_UNAVAILABLE` | MEK could not be loaded at startup |

### 8.5 Rate Limits

| Endpoint Group | Limit |
|---|---|
| `POST /auth/login` | 10 requests / minute / IP |
| `POST /auth/mfa` | 5 requests / minute / IP |
| All other API endpoints | 300 requests / minute / user |
| `GET /secrets/{id}/value` | 60 requests / minute / user |

---

## 9. Frontend Architecture

### 9.1 Application Structure

```
src/
├── api/            # Typed API client (fetch wrappers)
├── components/
│   ├── ui/         # shadcn/ui base components
│   ├── vault/      # Secret list, detail, reveal button
│   ├── admin/      # User, role, folder management
│   └── audit/      # Audit log viewer
├── hooks/          # useAuth, useSecrets, usePermissions
├── pages/          # Route-level components
├── stores/         # Zustand stores (auth state only)
├── utils/
│   ├── clipboard.ts  # Auto-clearing clipboard helper
│   └── crypto.ts     # Client-side none (all crypto server-side)
└── main.tsx
```

### 9.2 Key Frontend Behaviors

**Secret value display:**
- Value is fetched on explicit user action ("Reveal" button click).
- Displayed in a masked `<input type="password">` that toggles to text on secondary click.
- A countdown timer starts at reveal; value is cleared from DOM and memory after 30 seconds (configurable).
- Access token stored in module-scope JS variable only — never `localStorage` or `sessionStorage`.

**Clipboard:**
```typescript
export async function copyWithAutoClear(value: string, seconds = 30) {
  await navigator.clipboard.writeText(value);
  setTimeout(() => navigator.clipboard.writeText(''), seconds * 1000);
}
```

**Idle session timeout:**
- 15-minute inactivity timer reset on `mousemove`, `keydown`, `click`, `scroll`.
- At timeout: clear access token from memory, display modal, redirect to `/login`.

### 9.3 Content Security Policy

```
Content-Security-Policy:
  default-src 'self';
  script-src  'self';
  style-src   'self' 'unsafe-inline';
  img-src     'self' data:;
  font-src    'self';
  connect-src 'self';
  frame-ancestors 'none';
```

---

## 10. Audit Logging

### 10.1 Action Code Registry

| Action Code | Resource | Trigger |
|---|---|---|
| `AUTH_LOGIN_SUCCESS` | user | Successful login |
| `AUTH_LOGIN_FAILURE` | user | Failed login attempt |
| `AUTH_LOCKOUT` | user | Account locked |
| `AUTH_MFA_SUCCESS` | user | MFA verified |
| `AUTH_MFA_FAILURE` | user | MFA failed |
| `AUTH_LOGOUT` | user | User logged out |
| `AUTH_TOKEN_REFRESH` | user | Refresh token used |
| `SECRET_VIEWED` | secret | Value decrypted and returned |
| `SECRET_CREATED` | secret | New secret created |
| `SECRET_UPDATED` | secret | Secret metadata or value changed |
| `SECRET_DELETED` | secret | Soft-delete |
| `SECRET_RESTORED` | secret | Restored from Trash |
| `SECRET_PURGED` | secret | Permanently deleted |
| `SECRET_VERSION_VIEWED` | secret | Historical version decrypted |
| `SECRET_ACL_CHANGED` | secret | ACL entries modified |
| `FOLDER_CREATED` | folder | New folder |
| `FOLDER_DELETED` | folder | Folder removed |
| `FOLDER_ACL_CHANGED` | folder | Folder ACL modified |
| `USER_CREATED` | user | New user account |
| `USER_UPDATED` | user | User profile changed |
| `USER_DEACTIVATED` | user | User deactivated |
| `USER_ROLE_ASSIGNED` | user | Role added to user |
| `USER_ROLE_REMOVED` | user | Role removed from user |
| `ROLE_CREATED` | role | New role |
| `ROLE_UPDATED` | role | Role renamed |
| `ROLE_DELETED` | role | Role deleted |
| `API_TOKEN_CREATED` | token | API token issued |
| `API_TOKEN_REVOKED` | token | API token revoked |
| `SYSTEM_KEY_LOADED` | system | MEK loaded at startup |
| `SYSTEM_BACKUP_STARTED` | system | Backup job started |
| `SYSTEM_BACKUP_COMPLETED` | system | Backup job completed |
| `SYSTEM_CONFIG_CHANGED` | system | Configuration updated |

### 10.2 Syslog Format

When syslog forwarding is enabled (`Syslog:Enabled = true`):

```
<134>1 2026-02-15T14:32:01Z Secret Server - SECRET_VIEWED - [meta user="wsmith" secret_id="a1b2c3" ip="10.1.2.3"] Secret viewed
```

- Facility: Local0 (16); Severity: Informational (6) = PRI 134
- Transport: TCP preferred; UDP fallback
- TLS syslog (RFC 5425) supported when `Syslog:UseTls = true`

---

## 11. Configuration & Environment

### 11.1 `appsettings.json` Structure

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=Secret Server;Username=Secret Server_app;Password=..."
  },
  "Encryption": {
    "KeyFilePath": "/etc/Secret Server/master.key",
    "KeySource": "file"
  },
  "Auth": {
    "Mode": "local",
    "JwtSigningKeyPath": "/etc/Secret Server/jwt.key",
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeHours": 8,
    "LockoutThreshold": 5,
    "LockoutDurationMinutes": 30,
    "LdapServer": "",
    "LdapPort": 636,
    "LdapBaseDn": "",
    "LdapServiceAccountDn": "",
    "LdapServiceAccountPasswordEnv": "Secret Server_LDAP_PASSWORD"
  },
  "Session": {
    "IdleTimeoutMinutes": 15,
    "ClipboardClearSeconds": 30
  },
  "Vault": {
    "TrashRetentionDays": 30,
    "MaxVersionsPerSecret": 20
  },
  "RateLimit": {
    "LoginPerMinutePerIp": 10,
    "MfaPerMinutePerIp": 5,
    "ApiPerMinutePerUser": 300,
    "SecretViewPerMinutePerUser": 60
  },
  "Syslog": {
    "Enabled": false,
    "Server": "",
    "Port": 514,
    "UseTls": false
  },
  "Backup": {
    "Enabled": true,
    "CronSchedule": "0 2 * * *",
    "DestinationPath": "/var/backup/Secret Server",
    "RetentionDays": 30
  },
  "Logging": {
    "RetentionDays": 90
  }
}
```

### 11.2 Environment Variables (override `appsettings.json`)

| Variable | Purpose |
|---|---|
| `Secret Server_KEY_FILE` | Path to MEK key file |
| `Secret Server_DB_PASSWORD` | Database password |
| `Secret Server_LDAP_PASSWORD` | LDAP service account password |
| `Secret Server_JWT_KEY_FILE` | Path to JWT signing key |
| `ASPNETCORE_ENVIRONMENT` | `Production` / `Development` |

---

## 12. Deployment Architecture

### 12.1 Docker Compose (Recommended)

```yaml
version: "3.9"

services:
  app:
    image: Secret Server-app:1.0
    restart: unless-stopped
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - Secret Server_DB_PASSWORD_FILE=/run/secrets/db_password
      - Secret Server_KEY_FILE=/run/secrets/master_key
    volumes:
      - ./config/appsettings.Production.json:/app/appsettings.Production.json:ro
      - key_store:/run/secrets:ro
    depends_on:
      db:
        condition: service_healthy
    networks:
      - internal

  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: Secret Server
      POSTGRES_USER: Secret Server_app
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - pg_data:/var/lib/postgresql/data
    secrets:
      - db_password
    networks:
      - internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U Secret Server_app"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:1.26-alpine
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - app
    networks:
      - internal
      - external

volumes:
  pg_data:
  key_store:

networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### 12.2 Nginx Configuration

```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;

    ssl_certificate     /etc/nginx/certs/Secret Server.crt;
    ssl_certificate_key /etc/nginx/certs/Secret Server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options            DENY always;
    add_header X-Content-Type-Options     nosniff always;
    add_header Referrer-Policy            strict-origin-when-cross-origin always;
    add_header Content-Security-Policy    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';" always;

    client_max_body_size 10m;

    location / {
        proxy_pass         http://app:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }
}
```

### 12.3 File System Layout (Linux)

```
/opt/Secret Server/          # Application binaries (owned: root, readable: Secret Server-app)
/etc/Secret Server/
    appsettings.Production.json   # chmod 640; owner: root:Secret Server-app
    master.key                    # chmod 400; owner: root (read by app via sudo or CAP)
    jwt.key                       # chmod 400; owner: root
/var/lib/Secret Server/      # PostgreSQL data (if not containerized)
/var/log/Secret Server/      # Application logs (chmod 750)
/var/backup/Secret Server/   # Backup output (separate mount recommended)
```

---

## 13. Backup & Recovery

### 13.1 Backup Procedure

The nightly backup job (run by `Secret Server-backup` service account via cron / systemd timer) performs the following steps atomically:

```bash
#!/bin/bash
set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backup/Secret Server"
TMP_DIR=$(mktemp -d)
PASSPHRASE_FILE="/etc/Secret Server/backup.passphrase"  # chmod 400

# 1. Dump PostgreSQL
pg_dump -U Secret Server_backup -F c Secret Server > "$TMP_DIR/db_${TIMESTAMP}.dump"

# 2. Copy key file
cp /etc/Secret Server/master.key "$TMP_DIR/master_${TIMESTAMP}.key"

# 3. Encrypt the bundle
tar -czf - -C "$TMP_DIR" . \
  | openssl enc -aes-256-gcm -pbkdf2 -iter 600000 \
      -pass file:"$PASSPHRASE_FILE" \
  > "$BACKUP_DIR/Secret Server_${TIMESTAMP}.enc"

# 4. Cleanup temp
rm -rf "$TMP_DIR"

# 5. Purge old backups
find "$BACKUP_DIR" -name "*.enc" -mtime +30 -delete

echo "Backup completed: Secret Server_${TIMESTAMP}.enc"
```

### 13.2 Restore Procedure

```bash
# 1. Decrypt backup
openssl enc -d -aes-256-gcm -pbkdf2 -iter 600000 \
    -pass file:/etc/Secret Server/backup.passphrase \
    -in Secret Server_20260215_020001.enc \
  | tar -xzf - -C /tmp/restore/

# 2. Stop application
systemctl stop Secret Server

# 3. Restore key file
cp /tmp/restore/master_*.key /etc/Secret Server/master.key
chmod 400 /etc/Secret Server/master.key

# 4. Restore database
pg_restore -U postgres -d Secret Server --clean /tmp/restore/db_*.dump

# 5. Start application
systemctl start Secret Server
```

**RTO target:** < 2 hours from incident declaration to service restored.
**RPO target:** < 24 hours (last successful nightly backup).

---

## 14. Security Hardening Checklist

Use this checklist during pre-production review and quarterly security audits.

### 14.1 Infrastructure

- [ ] OS-level disk encryption enabled (BitLocker / LUKS) on database volume
- [ ] Key file stored on a separate volume from the database
- [ ] Database port not exposed beyond loopback / private VLAN
- [ ] Port 443 firewall-restricted to admin workstation subnets
- [ ] SSH access to server via key pair only; password auth disabled
- [ ] Automatic OS security patching enabled
- [ ] Server time synchronized via NTP (audit log accuracy depends on this)

### 14.2 TLS / Network

- [ ] TLS 1.2 minimum enforced; TLS 1.0 and 1.1 disabled
- [ ] TLS 1.3 preferred in Nginx cipher list
- [ ] HSTS header present with `max-age=31536000`
- [ ] HTTP → HTTPS redirect returning 301
- [ ] Certificate issued by trusted internal CA or public CA
- [ ] Certificate expiry monitoring alert configured (30-day warning)

### 14.3 Application

- [ ] `ASPNETCORE_ENVIRONMENT=Production` set (disables developer error pages)
- [ ] Swagger / OpenAPI UI disabled in production (docs endpoint behind auth)
- [ ] Detailed error messages suppressed in API responses
- [ ] CSP header validated against target browsers
- [ ] Rate limiting active on login and MFA endpoints
- [ ] Account lockout tested (5 failures → locked)
- [ ] MFA enforcement decision documented and applied

### 14.4 Encryption

- [ ] MEK key file permissions: `chmod 400`
- [ ] Key file NOT co-located with database files
- [ ] Application startup fails gracefully when key file is missing
- [ ] No plaintext credentials visible in database via `SELECT value_enc` inspection
- [ ] Backup files independently encrypted and verified restorable
- [ ] JWT signing key is RSA-2048 minimum or ECDSA P-256+

### 14.5 Audit & Monitoring

- [ ] Audit log `DELETE` and `UPDATE` privileges revoked from app DB user
- [ ] Syslog forwarding configured and tested (if SIEM in use)
- [ ] Alert configured on repeated `AUTH_LOGIN_FAILURE` events (e.g., > 20/hour)
- [ ] Audit log export tested for correct date-range filtering
- [ ] Log retention policy confirmed (90-day app logs; **1-year audit logs** — see PRD §13, Decision #5; configurable via `Logging:AuditRetentionDays` for sites with stricter requirements)

### 14.6 Dependencies & Build

- [ ] `dotnet list package --vulnerable` returns no critical CVEs
- [ ] `npm audit --audit-level=high` passes
- [ ] All dependencies pinned to specific versions in lock files
- [ ] Docker base images pinned to digest hash (not `latest`)
- [ ] CI pipeline fails build on any critical CVE

---

## 15. Testing Strategy

### 15.1 Unit Tests

- Encryption service: encrypt → decrypt round-trip with known vectors
- Permission resolution algorithm: all combinations of role/ACL/folder inheritance
- Password hashing: verify Argon2id output format and round-trip
- Token generation and validation: expiry, claims, revocation

### 15.2 Integration Tests

- Full auth flow: login → MFA → token refresh → logout
- Secret CRUD with permission enforcement at each permission level
- ACL inheritance: folder ACL grants access to child secret
- Audit log: verify every tested action produces expected log entry
- Import: valid CSV, valid KeePass XML, malformed input rejection

### 15.3 Security Tests

| Test | Method | Pass Criteria |
|---|---|---|
| SQL injection | sqlmap against all endpoints | Zero successful injections |
| XSS | OWASP ZAP active scan | No reflected or stored XSS |
| CSRF | Manual + ZAP | All state-changing endpoints reject requests without valid CSRF token |
| Brute force lockout | Scripted 6 rapid login attempts | Account locked on 5th failure |
| Privilege escalation | Request secret with wrong role | 403 / 404 returned; no data leaked |
| Plaintext in DB | Hex dump of secrets table | No recognizable credentials in plaintext |
| TLS downgrade | SSLscan / testssl.sh | TLS 1.0/1.1 refused; no weak ciphers |
| JWT tampering | Modified `sub` or `role_ids` claim | 401 returned |

### 15.4 Performance Baseline

Measured on recommended hardware (8-core, 16 GB RAM):

| Scenario | Target | Method |
|---|---|---|
| Page load (50 concurrent users) | < 2 seconds (p95) | k6 load test |
| Secret decrypt + return | < 500 ms (p99) | k6 targeted test |
| Search across 50,000 secrets | < 1 second (p95) | k6 with seeded data |

---

## 16. Error Handling & Logging

### 16.1 Application Log Levels

| Level | Usage |
|---|---|
| `Critical` | Application cannot start (missing MEK, DB unavailable) |
| `Error` | Unhandled exception; failed backup; decryption error |
| `Warning` | Auth failure; rate limit triggered; deprecated config |
| `Information` | Request lifecycle; startup/shutdown; scheduled job results |
| `Debug` | SQL queries (disabled in Production); permission checks |

### 16.2 Log Format (Structured JSON)

```json
{
  "timestamp": "2026-02-15T14:32:01.123Z",
  "level": "Information",
  "message": "Secret value accessed",
  "traceId": "00-abc123-def456-00",
  "userId": "a1b2c3d4-...",
  "secretId": "e5f6g7h8-...",
  "ip": "10.1.2.3"
}
```

- Log sink: Rolling file (`/var/log/Secret Server/app-YYYYMMDD.log`) + optional Syslog
- Secret values, password hashes, and key material **must never appear in any log at any level**
- Log scrubbing middleware strips any field matching `/password|secret|key|token|hash/i` before writing

---

## 17. Build & CI/CD Pipeline

### 17.1 Pipeline Stages

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Checkout   │→  │    Build    │→  │    Test     │→  │  Security   │→  │   Package   │
│             │   │  dotnet     │   │  Unit +     │   │  Scan       │   │  Docker     │
│             │   │  build      │   │  Integration│   │  CVE audit  │   │  image      │
│             │   │  npm build  │   │  Tests      │   │  SAST       │   │  + sign     │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
                                                                                │
                                                               ┌────────────────┘
                                                               ▼
                                                    ┌─────────────────────┐
                                                    │  Deploy (manual     │
                                                    │  approval gate for  │
                                                    │  production)        │
                                                    └─────────────────────┘
```

### 17.2 Branch Strategy

| Branch | Purpose | Deploy Target |
|---|---|---|
| `main` | Production-ready code | Production (manual gate) |
| `develop` | Integration branch | Staging (automatic) |
| `feature/*` | Feature work | None (PR only) |
| `hotfix/*` | Critical production fixes | Production (manual gate) |

### 17.3 Definition of Done

A story or task is complete when:

- [ ] Unit tests written and passing (minimum 80% line coverage on new code)
- [ ] Integration test covers the happy path and at least one error case
- [ ] Security test for any auth/permission/crypto change
- [ ] `dotnet list package --vulnerable` passes with no critical/high
- [ ] `npm audit --audit-level=high` passes
- [ ] PR reviewed and approved by at least one other developer
- [ ] Audit log entry verified for any user-facing action

---

## 18. Revision History

| Version | Date | Author | Summary |
|---|---|---|---|
| 1.0 | February 2026 | IT Team | Initial draft derived from Secret Server PRD v1.0 |
| 1.1 | February 2026 | IT Team | Applied architecture decisions: ASP.NET Core 8 stack finalized; LDAP included in v1.0; local key file (MEK) confirmed; MFA policy set to optional/configurable; audit log retention confirmed at 1 year. Updated §3.1, §5.2, §6, §6.3, §14.5. |
