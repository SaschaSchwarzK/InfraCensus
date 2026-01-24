# Overview

InfraCensus is a network discovery and inventory platform with a central control plane and distributed collectors. The central API schedules scans, aggregates results, and exposes data to plugins and exports. Collectors run in network segments and execute discovery tasks with scoped permissions.

## Components

- Central API and GUI: job scheduling, inventory storage, user access.
- Collectors: lightweight agents for discovery and data collection.
- Database: stores tenants, devices, results, schedules, and audit logs.
- Sites include IANA timezones for UTC scheduling + local display.

## Data Flow

1. Admin schedules a scan for tenant networks.
2. Collector polls for jobs and executes assigned scans.
3. Results and timing updates are reported back.
4. Central stores versioned results and audit history.
