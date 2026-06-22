---
description: Install rastreo, run a first discovery scan, and route the records to a destination — start to finish in five minutes.
---

# Get started

This section walks you from a fresh checkout to a running discovery scan that emits real `DeviceRecord` events. It is aimed at someone who has never used rastreo before and wants to know the shortest path from `cargo install` to a record on stdout.

Topics covered here include the install paths available today (Cargo from source, Docker), the first end-to-end scan against a local target, and how to point the same scenario at a real backend such as a Kafka topic or an NDJSON file.

## Pages in this section

- [Install](install.md) — install the `rastreo` CLI and `rastreo-server` from source or Docker.
- [First scan](first-scan.md) — run an end-to-end TCP-connect scan and read the resulting `DeviceRecord`.
