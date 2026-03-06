# API Error Codes

This catalog defines standardized error envelopes returned by `/api/v1` routes.

Envelope shape:

```json
{
  "error": {
    "code": "STRING_CODE",
    "message": "Human readable message",
    "traceId": "uuid-or-static"
  }
}
```

Codes:

- `VALIDATION_ERROR`: Request input failed validation.
- `INVALID_JSON`: Request JSON body is malformed.
- `PAYLOAD_TOO_LARGE`: Request body exceeds size limit.
- `UNAUTHENTICATED`: Missing, expired, or invalid authentication.
- `PERMISSION_DENIED`: Authenticated caller lacks required permission/scope.
- `NOT_FOUND`: Requested resource is missing or not visible.
- `CONFLICT`: Request conflicts with current state.
- `RATE_LIMITED`: Caller exceeded rate limit.
- `INTERNAL_ERROR`: Unexpected server-side failure.
