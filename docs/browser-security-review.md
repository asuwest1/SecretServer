# Browser Security Posture Review

Date: 2026-03-06
Scope: Web client and API interaction patterns for CSRF/XSS posture.

## Current Controls

- Auth model is bearer token based (`Authorization: Bearer`) and API token header (`x-api-token`), not cookie session auth.
- Security headers set by API server:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none';`
  - `Strict-Transport-Security`
  - `Permissions-Policy`

## CSRF Assessment

- Risk level: Low for authenticated API calls because auth is header token based and not browser-cookie implicit.
- Residual risk: If future browser clients store bearer tokens in cookies/localStorage without hardened handling, CSRF/XSS combined risk increases.

## XSS Assessment

- Risk level: Medium.
- Main concern: secret metadata/notes may be rendered by frontend components. Rendering must stay escaped and avoid unsafe HTML APIs.
- Current server CSP is restrictive but does not replace frontend output encoding discipline.

## Required Ongoing Checks

- Keep React rendering path free of `dangerouslySetInnerHTML` for untrusted text.
- Treat all user-supplied fields (name, username, url, notes, tags) as untrusted.
- Add security regression tests when new rich-text or HTML features are introduced.

## Residual Risks

- Stored XSS risk remains if future UI changes introduce unsafe rendering.
- Token theft risk remains if browser storage is compromised by XSS or extension abuse.
