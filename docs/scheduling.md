# Scan Scheduling

## Schedule Fields (UTC)

- `scheduled_at_utc`: requested scan start time.
- `not_before_utc` / `not_after_utc`: execution window.
- `actual_start_at_utc`: when the collector began the scan.
- `finished_at_utc`: when the scan completed.

Schedules apply to an overall scan and each scan type. Per-type timing entries are tracked separately.

## Lifecycle

1. User schedules a scan with start date/time, networks, and scan types.
2. Collector updates actual start and finish timestamps via API (UTC only).
3. Central stores timing fields for audit and reporting.
