# API Notes

## JSON Responses

All GUI GET routes return JSON when `Accept: application/json` is set.

## UTC and Timezones

- All timestamps are UTC and use ISO 8601 with `Z`.
- Responses with display timestamps include `site.timezone` (IANA) when applicable.

### Pagination

- `limit` (default 50, max 200)
- `offset` (default 0)

### Filters

- `/tenants`: `name`
- `/tenants/{id}/users`: `email`, `role`
- `/tenants/{id}/sites`: `name`, `code`
- `/tenants/{id}/networks`: `name`, `cidr`, `site_id`
- `/admin/tenants`: `name`
- `/admin/users`: `email`, `superadmin` (`true` or `false`)
- `/admin/audit`: `action`, `entity_type`, `actor_user_id`, `entity_id`
- `/tenants/{id}/schedules`: `site_id`, `scan_type`, `start_after`, `start_before`
- `/tenants/{id}/collectors/enrollment`: `site_id`, `used` (`true` or `false`)

## Schedule Updates

Collectors can update timing fields via JSON:

- `POST /tenants/{id}/schedules/{schedule_id}/status`
  - Body: `actual_start_at_utc`, `finished_at_utc` (ISO 8601)
- `POST /tenants/{id}/schedules/{schedule_id}/types/{type_id}/status`
  - Body: `actual_start_at_utc`, `finished_at_utc` (ISO 8601)

### Collector Authentication

Set `settings.collector_tokens` to a comma-separated list of tokens. Collectors send one of:

- `Authorization: Bearer <token>`
- `X-Collector-Token: <token>`

## Collector Endpoints

See `docs/collector.md` for enrollment, renew, and job endpoints plus mTLS setup.
