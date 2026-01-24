# Collector Communication

This document describes how collectors communicate with the central server, how enrollment works, and security guarantees.

## Enrollment Flow

1. Admin creates a short-lived enrollment token for a tenant (optionally scoped to a site).
2. Collector generates a keypair locally and builds a CSR.
3. Collector calls `POST /collectors/enroll` with the token and CSR.
4. Central verifies the token, issues a client certificate, and marks the token as used.

Notes
- Tokens are single-use and have a short TTL (10-30 minutes by default).
- The private key never leaves the collector host.

## Steady-State Auth (mTLS)

After enrollment, collectors use mTLS for every request. The reverse proxy enforces client cert validation and forwards verified metadata to the API.

- Client cert identifies the collector.
- Central maps cert serial/fingerprint to collector record and tenant scope.

## Authorization Rules

- Collector can only poll jobs assigned to its own collector ID and tenant.
- Collector can only upload results for jobs assigned to it.
- No access to global data or other tenants.

## Replay/Abuse Protection

- Jobs include job ID, expiration, and nonce.
- Collector must echo them in result uploads.
- Results are accepted only once and before expiration.

## Rotation and Revocation

- Client certs are short-lived (recommended 7-30 days).
- Collector renews via `POST /collectors/renew` using mTLS.
- Central can revoke by disabling a collector and/or using a CRL/OCSP in the TLS layer.

## UTC Time Handling

- All timestamps are stored and transmitted as UTC.
- Collector sends `collector_time_utc` and server responds with `server_time_utc` for skew tracking.

## Endpoints

- `POST /collectors/enroll`
- `POST /collectors/renew`
- `GET /collectors/jobs/poll`
- `POST /collectors/jobs/result`
- `POST /collectors/schedules/{schedule_id}/status`
- `POST /collectors/schedules/{schedule_id}/types/{type_id}/status`

## Edge Configuration

Refer to `docs/collector.md` for nginx, Traefik, and Caddy mTLS examples.
