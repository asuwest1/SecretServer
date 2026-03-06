# SIEM Forwarding and Validation

## Syslog Configuration

Environment variables:

- `SECRET_SERVER_SYSLOG_ENABLED` (`true|false`)
- `SECRET_SERVER_SYSLOG_SERVER` (hostname/IP)
- `SECRET_SERVER_SYSLOG_PORT` (numeric)
- `SECRET_SERVER_SYSLOG_PROTOCOL` (`udp|tcp|tls`)
- `SECRET_SERVER_SYSLOG_TLS_ENABLED` (`true|false`, only relevant with `tcp`)
- `SECRET_SERVER_SYSLOG_TLS_REJECT_UNAUTHORIZED` (`true|false`)

Each emitted message follows RFC5424-style framing and includes action/user/resource metadata.

## Validation Procedure

1. Enable syslog forwarding in a non-production environment.
2. Trigger known auditable actions (login success/failure, secret create/update/delete).
3. Confirm SIEM receives messages with expected action/resource metadata.
4. Force transport failures:
   - stop UDP listener
   - refuse TCP/TLS connections
   - set unsupported protocol value
5. Confirm application warning logs include:
   - `syslog_udp_failed`
   - `syslog_tcp_failed`
   - `syslog_tls_failed`
   - `syslog_protocol_invalid`

## Audit Integrity Validation

Use `GET /api/v1/audit/verify` as Super Admin to validate tamper-evident hash chain status.

## Retention Controls

- `SECRET_SERVER_AUDIT_RETENTION_DAYS`
- `SECRET_SERVER_AUDIT_MAX_ENTRIES`

Retention is enforced in-process during request handling.
