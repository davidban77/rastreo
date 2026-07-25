---
description: Executable reference implementations of source-of-truth reconcilers — NetBox, Nautobot, and Infrahub.
---

# Reference consumers

Reference consumers are self-contained implementations of the [source-of-truth reconciliation pattern](source-of-truth.md) that you can read and copy. They live in the rastreo repository under `examples/`, so you can read every line, fork one, or adapt it to your own environment without pulling in a heavy dependency.

Each reference consumer targets one source of truth, reads `DeviceRecord` events from Kafka, and upserts them idempotently. Priorities in order: readability first, correctness second, minimum code third. None of them include a dead-letter queue (a side channel where records that repeatedly fail to deliver are parked instead of dropped — see [Sinks · Dead-letter queue](../discover/sinks.md#dead-letter-queue)), a retry-with-backoff loop, or a metrics endpoint. Those are production concerns, and each reference points at where they would go.

!!! info "The reference consumers read the device stream only"
    A scan that runs the [LLDP prober](../probe/lldp.md) also emits `LinkRecord` topology edges on a second Kafka topic (or NATS subject) — `rastreo.discovery.links.v1` by default. The three reference consumers below reconcile the device stream only. Reconciling links into NetBox cables or Nautobot interface connections is a separate consumer; see [Topology](../discover/topology.md#mapping-to-a-source-of-truth) for the mapping.

## Available now

| Consumer | Source of truth | Location | Runtime |
|---|---|---|---|
| [NetBox](https://github.com/davidban77/rastreo/tree/main/examples/netbox-consumer) | NetBox 4.x | `examples/netbox-consumer/` | Python 3.12, `confluent-kafka` + `pynetbox` |
| [Nautobot](https://github.com/davidban77/rastreo/tree/main/examples/nautobot-consumer) | Nautobot 2.x | `examples/nautobot-consumer/` | Python 3.12, `confluent-kafka` + `pynautobot` |
| [Infrahub](https://github.com/davidban77/rastreo/tree/main/examples/infrahub-consumer) | Infrahub 1.x | `examples/infrahub-consumer/` | Python 3.12, `confluent-kafka` + `infrahub-sdk` |

## Run the NetBox consumer

The NetBox consumer is a small Python program. To run it you need:

- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- A Kafka broker rastreo can publish to and the consumer can read.
- A NetBox instance and an API token with device read and write.
- The custom fields the consumer looks for, created once on the NetBox device table. The example ships a `netbox-custom-fields.yaml` and a UI walkthrough for this step.

From `examples/netbox-consumer/`:

```bash
uv sync                 # install dependencies
cp .env.example .env    # then fill in the required values (see the table below)
uv run python -m netbox_consumer
```

The consumer runs in the foreground, reads the topic, and logs one JSON line per record. Stop it with Ctrl-C. Set `DRY_RUN=true` in `.env` to log the NetBox call it would make without writing anything — a safe way to watch a live topic on the first run.

The required variables — `.env.example` documents these plus the optional settings (topic, consumer group, TLS, log level) with their defaults:

| Variable | What it is |
|---|---|
| `KAFKA_BROKERS` | Comma-separated broker list, for example `localhost:9092`. |
| `NETBOX_URL` | NetBox base URL, with no trailing `/api`. |
| `NETBOX_TOKEN` | A NetBox API token with device read and write. |
| `NETBOX_DEFAULT_DEVICE_TYPE` | Device type assigned to devices the consumer creates — must already exist in your NetBox. |
| `NETBOX_DEFAULT_SITE` | Site assigned to new devices — must already exist in your NetBox. |
| `NETBOX_DEFAULT_DEVICE_ROLE` | Device role assigned to new devices — must already exist in your NetBox. |

The [example's README](https://github.com/davidban77/rastreo/tree/main/examples/netbox-consumer) lists every variable and a docker-compose path that brings up Kafka and the consumer together. The Nautobot and Infrahub consumers follow the same shape: install with `uv sync`, copy `.env.example`, set the broker plus the source-of-truth URL and token, then run the module.

The NetBox reference demonstrates:

- Looking up `dcim.Device` by a `rastreo_identity_key` custom field.
- Creating the device on first sight, including `mgmt0` interface and `primary_ip4`/`primary_ip6`.
- Patching only changed custom fields, platform, role, and primary IP on subsequent scans.
- Slug-based lookups for `platform` and `device_role` foreign keys.
- Verbatim JSON custom fields for `signals`, `probe_kinds`, `alt_ips`, and `scan_metadata` — audit history without needing schema work per signal type.
- Manual Kafka offset commits after each successful upsert, so a crash mid-upsert replays the message.
- Ships a companion `netbox-custom-fields.yaml` for GitOps-managed NetBox instances and a UI walkthrough for smaller ops.

The Nautobot reference demonstrates:

- The same identity-key lookup and idempotent upsert shape, adapted to Nautobot 2.x's `extras.Role` and `extras.Status` models and its `dcim.Location` requirement.
- Resolving a default `DeviceType`, `Location`, and `Status` at startup and hard-failing when any name is missing — Nautobot 2.x requires all three on every device.
- Name-based lookups (Nautobot 2.x removed the `slug` field from `Role`, `Status`, `Platform`, `DeviceType`, and `Location`).
- Attaching `primary_ip4`/`primary_ip6` only when an enclosing `ipam.Prefix` exists — Nautobot 2.x requires `IPAddress.parent` at create time, so a reference consumer skips primary-IP attach with a WARN when no prefix contains the address.
- A pointer at the [`nautobot-app-ssot`](https://docs.nautobot.com/projects/ssot/en/latest/) framework as the canonical production path — the reference stays REST-only so wire calls stay readable.

The Infrahub reference demonstrates:

- **Schema-flexible modeling.** Infrahub has no fixed device kind — the reference ships an `infrahub-schema.yaml` declaring a `RastreoDevice` node with the attributes the mapper writes, and the consumer verifies the schema is loaded at boot with an actionable error if it's missing.
- **Branch-based mutations.** Every upsert lands on a persistent `rastreo-updates` branch (configurable), not on `main`. Ops teams review the accumulated diff via Infrahub's Proposed Changes UI before merging. Auto-merge is opt-in via `INFRAHUB_AUTO_MERGE=true`.
- Boot-time branch bootstrap: the consumer creates the target branch from `main` if it does not exist, so the first run works with an empty Infrahub.
- Identity-key lookup via the unique attribute constraint declared in the schema — no custom-field indirection like NetBox/Nautobot.
- Comparison-based idempotent patch: on repeat scans, each attribute is compared to the current node value and `node.update()` is only called when the diff is non-empty.
- **Sync-outer, async-inner runtime.** The outer Kafka poll loop is `confluent-kafka` (sync); the inner infrahub-sdk work is async. `asyncio.run(...)` per message keeps the boundary at exactly one line, at the cost of throughput — the reference documents where to switch to `aiokafka` for high-volume deployments.

## The three-reference series

The three reference consumers together demonstrate that the reconciliation pattern generalises across REST + custom-field SoTs (NetBox, Nautobot) and schema-flexible + branch-based SoTs (Infrahub). All three follow the same file layout — `models.py`, `mapper.py`, `<sot>.py`, `consumer.py` — so a reader who has followed one can navigate the others without re-learning the pattern. Copy whichever matches your SoT and adapt from there; forking one to target a fourth SoT (Netdot, Nornir Inventory, a custom REST SoT) is a few hundred lines of change.

The three references intentionally stop at readable single-instance reconciliation. Production concerns — DLQ topics, retry with backoff, metrics, sharding — are documented per reference as extension points, not shipped in the reference itself.

## See also

- [Source of truth](source-of-truth.md) — the reconciliation contract these consumers implement.
- [Kafka](kafka.md) — the wire contract each consumer reads from.
