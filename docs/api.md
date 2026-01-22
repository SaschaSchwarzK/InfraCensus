# API Notes

## JSON Responses

All GUI GET routes return JSON when `Accept: application/json` is set.

### Pagination

- `limit` (default 50, max 200)
- `offset` (default 0)

### Filters

- `/tenants`: `name`
- `/tenants/{id}/users`: `email`, `role`
- `/tenants/{id}/sites`: `name`, `code`
- `/tenants/{id}/networks`: `name`, `cidr`, `site_id`
- `/tenants/{id}/scan-results`: `label`, `scan_job_id`
- `/admin/tenants`: `name`
- `/admin/users`: `email`, `superadmin` (`true` or `false`)
- `/admin/audit`: `action`, `entity_type`, `actor_user_id`, `entity_id`
