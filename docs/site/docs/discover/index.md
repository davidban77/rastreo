---
description: The discover command, the scenario YAML format, target syntax (IP / CIDR / range / DNS), and the prober configuration knobs available today.
---

# Discover

This section is the user-level reference for running a discovery scan. It covers the `rastreo discover` CLI subcommand and the YAML scenario format that drives it. Both surfaces accept the same configuration; the YAML form is the canonical source of truth and the CLI flags map onto its fields.

Topics covered here include target syntax (IP, CIDR, ranges, DNS), the scenario schema (probers, encoders, sinks, fuser), CLI flag reference and override precedence, and configurable knobs like timeout, concurrency, and fuser confidence.
