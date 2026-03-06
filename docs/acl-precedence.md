# ACL Precedence and Inheritance Rules

This document defines effective permission resolution for secrets.

## Core Rules

1. Super Admin bypass
- Super Admin always has full access regardless of ACL entries.

2. Secret-level ACL override
- If any ACL entries exist for a secret, only secret-level ACL entries are used for permission checks on that secret.
- Folder ACL (including inherited parent folder ACL) is ignored for that secret.

3. Folder inheritance chain
- If a secret has no direct ACL entries, permissions are evaluated from folder ACL entries on:
  - the secret's folder
  - all ancestor folders recursively up to root

4. Role aggregation
- User effective permissions are additive across all assigned roles.
- A permission is granted if any applicable ACL entry for any assigned role has that permission set to `true`.

5. No explicit deny semantics
- There is no explicit deny bit in the current model.
- Absence of grant means denied.

## Operational Consequences

- Assigning a direct ACL to a secret is a hard boundary and can intentionally narrow access compared to folder inheritance.
- Moving a secret between folders changes inherited permissions only when no direct secret ACL exists.
- Deep folder hierarchies are supported for inherited checks.

## Validated By Tests

- `tests/integration-api.js`
  - nested folder inheritance for add/view
  - secret override behavior
  - list/search/reveal/update/delete consistency after override
- `src/api/services/permissions.js`
  - canonical permission resolver implementation
