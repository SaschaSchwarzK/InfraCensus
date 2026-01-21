# InfraCensus

This is a project for an network infrastructure discovery and inventory collection tool.

## Overview

InfraCensus is designed to scan and identify various network devices, gather their configurations, and maintain an up-to-date inventory of the network infrastructure. It supports a wide range of device types including routers, switches, firewalls, and more.

## Application Design

InfraCensus consists of a centralized part with GUI that has a database (PostgreSQL) and is extenable with plugins. And a decentralized collector component that can be deployed as scanner/datat collector.
The centralized part keeps track of and controls all collectors, accumulates the data, schedules jobs and processes data and data exports.
Collectors are lightweight agents in docker containers that can be deployed on various network segments to perform discovery and data collection tasks. They communicate with the central server to report findings and receive instructions.

## Features

- Multi Tenant capabale.
- Networks can be scanned for responding devices.
    - Tools such as NMAP can be utilized.
    - Network ranges and IP addresses can be specified for scan or to be excluded.
- Devices can be identified with various protocols, fingerprints and by data from other devices.
    - SNMP (requires SNMP communities or v3 user/password for non public)
    - SSH (requires SSH keys or user/password)
    - HTTP/HTTPS (might require user/password)
    - Custom fingerprints
    - CDP/LLDP
    - ARP tables
    - MAC tables
    - Port descriptions
- Inventory can be stored in database and complemented with additonal data about tenant, location, etc
- Data can be exported in various formats (CSV, JSON, XML, etc)
- Data can be exported to other tools with plugins like Netbox, Neutobot.
- Plugin system to extend functionality and support more device types and data sources.

## Architecture
The architecture of InfraCensus is modular, consisting of the following main components:
- Central component consisting of multiple containers.
- Decentralized containers as data collectors.
- Database (PostgreSQL) for storing inventory data.
- Plugin system for extensibility.

## Requirements to the App
- Python 3.14+ or Go
- Asynchronous, non-blocking code that can execute many tasks in parralell.
- Containerized deployment (Docker, Kubernetes)
- REST API for communication between central server and collectors.
- Web-based GUI for management and monitoring.
- Secure communication (TLS/SSL) between components.
- Authentication and authorization for multi-tenant support.
- Logging and monitoring capabilities.
- Configuration management for easy setup and customization.
- Scheduling system for periodic scans and data collection/export tasks.
- Error handling and retry mechanisms for robust operation.
- Documentation and user guides for installation, configuration, and usage.
- Testing framework for unit, integration, and end-to-end tests.
- Frameworks can be used like Django or FastAPI.
- Credentials and secrets must be hosted in a secure entity like a vault.

## Requirement for Development
- Version control system (GitHub)
- Issue tracking system (GitHub Issues)
- Continuous integration/continuous deployment (CI/CD) pipeline
- Code review process
- Development environment setup instructions
- Coding standards and best practices documentation
- Testing framework and guidelines
- Documentation tools and guidelines
- Collaboration tools (Slack, Microsoft Teams, etc)
- Project management tools (Jira, Trello, etc)
- Regular team meetings and communication channels
- Access to necessary resources and tools for development
- Security guidelines and best practices
- Performance optimization guidelines
- Backup and recovery procedures
- Monitoring and logging setup for development and production environments
- Training and onboarding materials for new developers


