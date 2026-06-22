---
description: End-to-end pipelines, Kafka topic consumers, integrating with NetBox / Nautobot / Infrahub, and troubleshooting common discovery failures.
---

# Integrate

This section covers what to do with the records once rastreo emits them. The headline path is Kafka — a topic of `DeviceRecord` events that downstream consumers reconcile into a source of truth (NetBox, Nautobot, Infrahub) on their own cadence. The same record stream can also be tailed off stdout for ad-hoc shell pipelines or persisted as NDJSON for batch use.

Topics covered here include the end-to-end discovery pipeline (resolver → scheduler → prober → fuser → encoder → sink), worked examples of feeding each supported source of truth via topic consumers, idempotency and dedup expectations on the consumer side, and a troubleshooting guide for common failures (unreachable targets, MAC randomization, DNS resolution issues).

## Pages in this section

- [Kafka](kafka.md) — the wire contract: batched vs per-record flush modes, NDJSON payload shape, and consumer parsing.
- [Source of truth](source-of-truth.md) — the reconciliation pattern consumers feeding NetBox, Nautobot, or Infrahub are expected to honour.
- [Troubleshooting](troubleshooting.md) — common failures when records do not land where you expect.
