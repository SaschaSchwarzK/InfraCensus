# Architecture

InfraCensus is split into a central control plane and distributed collectors.

## Central

- API service for scheduling jobs, managing collectors, and storing inventory data.
- Plugins provide exports (e.g., NetBox/Neutobot) and custom enrichments.

## Collector

- Lightweight agent deployed per network segment.
- Performs discovery via protocol modules (e.g., SNMP, SSH) and reports results to the central API.

## Data Flow

1. Central schedules a job.
2. Collector runs a scan and normalizes results.
3. Central stores inventory and triggers exports.
