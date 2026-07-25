---
description: End-to-end pipelines, Kafka topic consumers, integrating with NetBox / Nautobot / Infrahub, and troubleshooting common discovery failures.
---

# Integrate

This section covers what to do with the records once rastreo emits them. rastreo does not update your inventory system itself. It emits each discovered device as a record. A separate program you run — a *consumer* — reads those records and updates your [source of truth](../reference/glossary.md#source-of-truth) (NetBox, Nautobot, or Infrahub) on its own schedule.

## What a message broker does

Most integrations send records through a message broker. A broker is a service that stores each emitted record durably until a separate consumer program reads it. The scan and the consumer never have to run at the same time: rastreo writes records to the broker and exits, and the consumer catches up whenever it next runs.

rastreo supports two brokers — Kafka and NATS — and can also write records straight to a file or to stdout with no broker at all.

## Choose a transport

Pick the destination that matches how you already run things:

| Destination | Choose it when |
|---|---|
| **Kafka** | Your organization already runs Kafka, or several consumers need to read the same record stream independently. |
| **NATS** | You want a durable broker without Kafka's operational weight. NATS is a single lightweight binary. |
| **File or stdout** | You run one-shot scans and process the output in batch, or pipe it straight into a shell command. No broker to run or maintain. |

A broker fits a consumer that runs continuously and updates the source of truth on its own cadence. A file or stdout fits a scan you run by hand and read once.

## Pages in this section

- [Kafka](kafka.md) — the Kafka sink: the record format on the wire, batched vs per-record delivery, authentication, and a consumer sketch.
- [NATS](nats.md) — the NATS JetStream sink: subjects and streams, authentication, delivery modes, and a consumer sketch.
- [Source of truth](source-of-truth.md) — what "reconcile into NetBox, Nautobot, or Infrahub" means, and the contract a consumer honours.
- [Reference consumers](reference-consumers.md) — runnable example consumers, one per source of truth, that you can read and adapt.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive where you expect.
