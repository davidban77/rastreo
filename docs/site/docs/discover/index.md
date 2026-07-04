---
description: The rastreo discover CLI subcommand, the four target forms it accepts, the output sinks it can write to, and the enrichment fusers that turn bare records into identifiable devices.
---

# Discover

This section is the user-level reference for running a discovery scan. It covers the `rastreo discover` CLI subcommand — every flag it accepts, the four target forms (IP, CIDR, range, DNS), the output sinks records can be written to, and the enrichment fusers that populate vendor information on the records.

Topics covered here include the full CLI flag reference, the target syntax with worked examples, the three output sinks rastreo can emit to today (stdout, file, Kafka), and OUI vendor enrichment from MAC addresses.

## Pages in this section

- [CLI](cli.md) — every flag `rastreo discover` accepts, with worked examples.
- [Targets](targets.md) — the four target forms (IP, CIDR, range, DNS) and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output, plus the NDJSON contract.
- [Enrichment](enrichment.md) — OUI vendor lookup from MAC addresses, the bundled Wireshark manuf snapshot, and how to override it.
