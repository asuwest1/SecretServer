# Secret Server User Guide

This guide is for day-to-day users and administrators of the Secret Server web application.

## 1. Access and Sign-In

1. Open the server URL in your browser (for example: `https://your-secret-server-host`).
2. Sign in with your username and password.
3. If MFA is enabled, complete the TOTP challenge.

If login fails repeatedly, account lockout policy may apply. Contact an administrator if needed.

## 2. Roles and Permissions (What You Can Do)

Your access is controlled by role assignments and ACL entries.

Permission meanings:
- `View`: view metadata and reveal secret value.
- `Add`: create secrets in a folder.
- `Change`: update secret fields, ACL, and restore deleted secret.
- `Delete`: soft-delete secret.

Notes:
- Super Admin can access all administrative functions.
- Secret-level ACL entries override inherited folder ACL entries for that secret.

## 3. Common User Tasks

### 3.1 Search secrets

1. Go to the secrets list/search page.
2. Enter search text in the search box.
3. Results only include secrets you are authorized to view.

### 3.2 Reveal a secret value

1. Open a secret record.
2. Select reveal/view value.
3. Value access is audited.

### 3.3 Create a secret

1. Navigate to target folder.
2. Select create/add secret.
3. Enter required fields (name, value; optional notes/tags/username/url).
4. Save.

### 3.4 Update a secret

1. Open secret.
2. Edit fields and save.
3. Previous encrypted value is tracked in version history.

### 3.5 Delete and restore a secret

1. Delete action performs soft-delete (not immediate hard purge).
2. Use restore action if you have `Change` permission.

## 4. Version History

For secrets where you have `Change` access:
1. Open secret versions/history.
2. Review prior versions and change metadata.

## 5. API Tokens (Power Users/Automation)

1. Open your profile/token area (or admin creates for your account).
2. Create API token with required scopes:
   - `read`
   - `write`
   - `admin`
3. Store the token securely at creation time.

Use token in header:
- `X-API-Token: <token>`

## 6. MFA Setup

1. Start MFA setup from your account settings.
2. Scan QR/OTP URI in authenticator app.
3. Enter verification code to enable MFA.

## 7. Admin Tasks

Super Admin users can:
- Create/deactivate users.
- Create roles.
- Assign role membership.
- Configure folder and secret ACL entries.
- Query and export audit logs.

## 8. Audit and Compliance

Audited events include key security actions such as:
- Login success/failure
- Secret create/update/delete/restore/reveal
- Token usage and token creation

Audit data can be queried/exported by administrators.

## 9. Troubleshooting

- `401 Unauthenticated`: token expired/invalid or bad credentials.
- `403 Permission denied`: your role/ACL does not grant required action.
- Empty search results: no visible secrets for current permissions.
- MFA failure: check authenticator clock sync and retry.

## 10. Security Best Practices for Users

- Use strong unique passwords.
- Enable MFA.
- Do not share API tokens.
- Rotate sensitive secrets on a regular schedule.
- Report unexpected access or secret changes immediately.

