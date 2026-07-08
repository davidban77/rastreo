---
description: Executable reference implementations of source-of-truth reconcilers — NetBox first, Nautobot and Infrahub next.
---

# Reference consumers

Reference consumers are self-contained, copy-shaped implementations of the [source-of-truth reconciliation pattern](source-of-truth.md). They live in the rastreo repository under `examples/` so you can read every line, fork them, or wire them into your own environment without pulling a heavy dependency.

Each reference consumer targets one source of truth, reads `DeviceRecord` events from Kafka, and upserts them idempotently. Priorities in order: readability first, correctness second, minimum code third. None of them ship a dead-letter queue, backoff/retry loop, or metrics endpoint — those are production concerns and the references point at where each would go.

## Available now

| Consumer | Source of truth | Location | Runtime |
|---|---|---|---|
| [NetBox](https://github.com/davidban77/rastreo/tree/main/examples/netbox-consumer) | NetBox 4.x | `examples/netbox-consumer/` | Python 3.12, `confluent-kafka` + `pynetbox` |

The NetBox reference demonstrates:

- Looking up `dcim.Device` by a `rastreo_identity_key` custom field.
- Creating the device on first sight, including `mgmt0` interface and `primary_ip4`/`primary_ip6`.
- Patching only changed custom fields, platform, role, and primary IP on subsequent scans.
- Slug-based lookups for `platform` and `device_role` foreign keys.
- Verbatim JSON custom fields for `signals`, `probe_kinds`, `alt_ips`, and `scan_metadata` — audit history without needing schema work per signal type.
- Manual Kafka offset commits after each successful upsert, so a crash mid-upsert replays the message.
- Ships a companion `netbox-custom-fields.yaml` for GitOps-managed NetBox instances and a UI walkthrough for smaller ops.

## Coming next

Nautobot and Infrahub references are in progress. Both will follow the same layout — `models.py`, `mapper.py`, `<sot>.py`, `consumer.py` — so a reader who has followed one can navigate the others without re-learning the pattern.

## See also

- [Source of truth](source-of-truth.md) — the reconciliation contract these consumers implement.
- [Kafka](kafka.md) — the wire contract each consumer reads from.
