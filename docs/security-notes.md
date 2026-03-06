# Security Notes (Scaffold)

This scaffold enforces:
- `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, basic CSP
- Login/MFA request throttling
- Account lockout after threshold failures
- Secret value encryption at rest in runtime store (AES-256-GCM)
- Token HMAC signing and expiration checks
- Secret/log field redaction in structured logs

Pending for production parity:
- Full CSRF strategy for browser session mode
- TLS termination and certificate pinning in front proxy
- Argon2id password hasher implementation (current scaffold uses scrypt)
- SQL append-only enforcement policy through DB roles
- Full security testing automation (OWASP ZAP/sqlmap/testssl scripts)
