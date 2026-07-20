---
description: The rastreo discover CLI subcommand, the four target forms it accepts, the output sinks it can write to, and the enrichment fusers that turn bare records into identifiable devices.
---

# Discover

This section is the user-level reference for running a discovery scan. It covers the `rastreo discover` CLI subcommand — every flag it accepts, the two modes it supports (flag-driven and YAML scenario files), the four target forms (IP, CIDR, range, DNS), the output sinks records can be written to, and the enrichment fusers that populate vendor information on the records.

Topics covered here include the full CLI flag reference, the YAML scenario file that unlocks every prober from the CLI, the target syntax with worked examples, the three output sinks rastreo can emit to today (stdout, file, Kafka), and OUI vendor enrichment from MAC addresses.

## Pages in this section

- [CLI](cli.md) — every flag `rastreo discover` accepts, plus YAML-driven mode with `--file`. See the [Scenario schema](../reference/scenario.md) for the file shape.
- [Catalog](catalog.md) — `@name` references and the search order across `~/.config/rastreo/catalog/`, `/etc/rastreo/catalog/`, and `RASTREO_CATALOG_DIR`.
- [Validate](validate.md) — lint a scenario file offline before a real scan, including secured Kafka and NATS sink configs with no broker running.
- [Targets](targets.md) — the four target forms (IP, CIDR, range, DNS) and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output, plus the NDJSON contract.
- [Enrichment](enrichment.md) — OUI vendor lookup from MAC addresses, SNMP `sysObjectID` model lookup, the bundled seed tables, and how to override each.
- [Identity](identity.md) — merges records that describe the same physical device and populates `alt_ips` / `possible_alias_of`.
- [Classification](classification.md) — the pipeline stage that assigns canonical `platform`, `os_version`, and `role` values on each `DeviceRecord`.
- [Topology](topology.md) — turns [LLDP](../probe/lldp.md) neighbor data into `LinkRecord` edges emitted on a second stream, and how they map to NetBox cables and Nautobot interface connections.
