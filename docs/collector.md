# Collector API & Auth

## Endpoint Sketch

- `POST /collectors/enroll`
  - Body: `{ "token": "...", "csr": "...", "name": "collector-1", "capabilities": "...", "labels": "..." }`
  - Response: `{ "collector_id": "uuid", "cert_pem": "..." }`

- `POST /collectors/renew`
  - Body: `{ "csr": "..." }`
  - Response: `{ "cert_pem": "..." }`

- `GET /collectors/jobs/poll`
  - Response: `{ "jobs": [], "server_time_utc": "..." }`

- `POST /collectors/jobs/result`
  - Body: `{ "job_id": "...", "collector_time_utc": "...", "results": {...} }`
  - Response: `{ "status": "accepted", "server_time_utc": "..." }`

- `POST /collectors/schedules/{schedule_id}/status`
  - Body: `{ "actual_start_at_utc": "...", "finished_at_utc": "..." }`

- `POST /collectors/schedules/{schedule_id}/types/{type_id}/status`
  - Body: `{ "actual_start_at_utc": "...", "finished_at_utc": "..." }`

## Collector Data Model

Collectors:
- `uuid`, `tenant_id`, `site_id`, `status`
- `labels`, `capabilities`, `allowed_scopes`
- `cert_serial`, `cert_fingerprint`, `cert_valid_from`, `cert_valid_to`
- `last_seen_utc`, `clock_skew_seconds`, `risk_flags`

Enrollment tokens:
- `token_hash`, `tenant_id`, `site_id`, `expires_at`, `used_at`

Certificate history:
- `serial`, `fingerprint`, `valid_from`, `valid_to`, `revoked_at`

## mTLS Enforcement (Edge)

### nginx (example)

```
server {
    listen 443 ssl;

    ssl_certificate     /etc/ssl/certs/server.pem;
    ssl_certificate_key /etc/ssl/private/server.key;

    ssl_client_certificate /etc/ssl/certs/collector-ca.pem;
    ssl_verify_client on;

    location /collectors/ {
        proxy_set_header X-Client-Cert-Serial $ssl_client_serial;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_pass http://central:8000;
    }
}
```

### Traefik (example)

```
http:
  routers:
    collectors:
      rule: PathPrefix(`/collectors/`)
      service: central
      tls:
        clientAuth:
          caFiles:
            - /certs/collector-ca.pem
          clientAuthType: RequireAndVerifyClientCert
    central:
      rule: PathPrefix(`/`)
      service: central
      tls: {}
  services:
    central:
      loadBalancer:
        servers:
          - url: http://central:8000
```

### Caddy (example)

```
central.example.com {
    tls /etc/ssl/certs/server.pem /etc/ssl/private/server.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /etc/ssl/certs/collector-ca.pem
        }
    }

    @collectors path /collectors/*
    reverse_proxy @collectors http://central:8000 {
        header_up X-Client-Cert-Serial {http.request.tls.client.certificate.serial_number}
        header_up X-Client-Cert-Fingerprint {http.request.tls.client.certificate.sha256_fingerprint}
    }

    reverse_proxy http://central:8000
}
```
```
