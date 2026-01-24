# Tenant Roles and Access

InfraCensus uses tenant-scoped roles plus a global superadmin.

## Roles

- `ro` (read-only): view inventory, scans, and exports.
- `rw` (read-write): schedule scans and update inventory metadata.
- `user_admin`: manage tenant users and roles.
- `superadmin`: manage tenants and global configuration.

## Notes

- Users can hold multiple roles per tenant.
- Superadmins still require tenant membership for tenant data access.
