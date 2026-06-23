---
description: An open-source network discovery engine in Rust. Probes a network across multiple protocols, fuses OUI vendor data with active fingerprints into a deduplicated DeviceRecord, and emits each to a Kafka topic, NDJSON file, or stdout.
hide:
  - navigation
  - toc
---

# rastreo

Rastreo is a network discovery engine. It probes a network across TCP, UDP, HTTP, DNS, SNMP, and ARP, fuses OUI vendor data with active fingerprints into a deduplicated, classified device record, and emits each record as a Kafka event — or as NDJSON to a file or stdout. Reconciliation into a source of truth such as NetBox, Nautobot, or Infrahub is done by independent topic consumers.

For installation and a quickstart, see the [project README](https://github.com/davidban77/rastreo); for what is planned, see the [issue tracker](https://github.com/davidban77/rastreo/issues).
