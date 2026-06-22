---
description: The rastreo discover CLI subcommand, the four target forms it accepts, and the output sinks it can write to.
---

# Discover

This section is the user-level reference for running a discovery scan. It covers the `rastreo discover` CLI subcommand — every flag it accepts, the four target forms (IP, CIDR, range, DNS), and the output sinks records can be written to.

Topics covered here include the full CLI flag reference, the target syntax with worked examples, and the three output sinks rastreo can emit to today (stdout, file, Kafka).

## Pages in this section

- [CLI](cli.md) — every flag `rastreo discover` accepts, with worked examples.
- [Targets](targets.md) — the four target forms (IP, CIDR, range, DNS) and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output, plus the NDJSON contract.
