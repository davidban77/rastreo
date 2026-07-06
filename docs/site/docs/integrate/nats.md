---
description: The NATS JetStream wire contract — auth methods, per-record vs batched delivery, subject and stream setup, and consumer parsing strategy.
---

# NATS

The NATS sink publishes `DeviceRecord` events to a JetStream subject encoded as NDJSON. Pick NATS when you want a lightweight persistent transport with at-least-once delivery, lower operational surface than Kafka, or when your downstream reconcilers already speak NATS. The wire payload is exactly the same NDJSON `DeviceRecord` shape as the Kafka sink; only the transport differs.

## Wire contract

A JetStream message payload is a sequence of NDJSON-encoded `DeviceRecord` objects, each terminated by a single `\n` byte. The message has no headers. The subject is a single subject (not a wildcard); the sink publishes exclusively to it. Every publish is confirmed by a JetStream `PublishAck` before the sink reports the write delivered.

In `per_record` mode (the default), the sink publishes one JetStream message per `DeviceRecord` and waits for the ack before returning from `write`. This is the simplest correctness model — every record is durable on the stream by the time the sink signals success.

In `batched` mode, records accumulate in an in-memory buffer until the buffer length reaches `threshold_bytes` (default 65536). When the threshold is reached the buffer is published as one JetStream message and the publish ack is held pending. `flush()` drains all pending acks and returns an error if any publish was not acknowledged. Batched mode is higher throughput but widens the failure window if the process is killed mid-batch.

## Basic scenario

Point rastreo at a NATS server, a subject, and the JetStream stream that binds the subject:

```yaml
targets:
  - 10.50.0.0/24
probers:
  - type: tcp_connect
    ports: [22, 80, 443]
sink:
  type: nats
  servers: ["nats://nats:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
```

Run with the `nats` feature enabled:

```
rastreo discover --file scenario.yaml
```

The stream `rastreo` must exist before rastreo connects — see [Stream setup](#stream-setup) below. Construction fails fast with a sink error if the stream is missing, so inventory records are never silently dropped.

## Authentication

The `credentials` field is optional and defaults to `anonymous`. Four auth methods are supported.

Anonymous — only appropriate for local dev / lab clusters:

```yaml
sink:
  type: nats
  servers: ["nats://nats:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    auth_type: anonymous
```

Username + password:

```yaml
sink:
  type: nats
  servers: ["nats://nats.prod:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    auth_type: user_pass
    username: rastreo-writer
    password: sekret
```

Bearer token:

```yaml
sink:
  type: nats
  servers: ["nats://nats.prod:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    auth_type: token
    token: bearer-token-value
```

JWT + nkey via a `.creds` file on disk. This is the canonical NGS / operator-issued credential format:

```yaml
sink:
  type: nats
  servers: ["tls://connect.ngs.global:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    auth_type: creds
    creds_file: /etc/rastreo/nats.creds
```

Password and token values are redacted in Debug output and in `source_config_hash`. Rotating a credential still changes the hash so consumers can detect config changes, but plaintext never leaves the `Password` newtype. The `creds_file` value is a filesystem path — not a secret — and is serialized verbatim.

## Delivery modes

`per_record` is the default and the right choice for most workloads. Every record is confirmed on the stream before the sink acknowledges the write, so a graceful shutdown never loses a record.

`batched` is the right choice for very high record rates where the extra ack round-trips dominate. `flush()` drains the outstanding acks and surfaces any errors; the pipeline calls it during graceful shutdown.

```yaml
sink:
  type: nats
  # ...
  delivery:
    mode: batched
    threshold_bytes: 65536
```

## Stream setup

The JetStream stream that binds the subject must be created out of band. rastreo does not create it — the stream lifetime is typically longer than any single rastreo scan, and stream retention / storage policy is deployment-specific.

Using the `nats` CLI:

```
nats stream add rastreo \
  --subjects 'rastreo.discovery.records.v1' \
  --storage file \
  --retention limits \
  --max-age 720h \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --discard old \
  --dupe-window 2m \
  --replicas 1
```

Adjust `--replicas`, `--storage`, and retention limits to match the cluster and the reconciler cadence. A file-backed stream with a 30-day retention window is a reasonable starting point for lab and small-production use.

## Consumer parsing

A JetStream consumer receives each message value, splits the bytes on `\n`, drops the empty trailing entry, and deserializes each remaining line as JSON. The same code handles both delivery modes — `per_record` yields one record per message, `batched` yields many.

```python
# Python async NATS consumer sketch
import asyncio
from json import loads

import nats

async def main():
    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()
    sub = await js.pull_subscribe("rastreo.discovery.records.v1", "rastreo-reconciler")
    while True:
        msgs = await sub.fetch(batch=32, timeout=5)
        for msg in msgs:
            for line in msg.data.split(b"\n"):
                if not line:
                    continue
                record = loads(line)
                upsert_record(record)
            await msg.ack()

asyncio.run(main())
```

## Idempotency

`identity_key` is the stable dedup key, identical to the Kafka sink. Consumers must upsert by `identity_key` — replace fields the new record carries, bump `last_seen`, and tolerate seeing the same key arrive any number of times. The NATS sink does not deduplicate. JetStream's built-in message deduplication window (`--dupe-window` on the stream) dedupes only on the JetStream message ID, not on the payload, so use it as a safety net against duplicate publishes, not as a record dedup mechanism.

## Build feature

The NATS sink is behind the `nats` Cargo feature on `rastreo-core` and on the binary crates. Build with:

```
cargo build --release --features nats -p rastreo
cargo build --release --features nats -p rastreo-server
```

The docker image and the release tarballs on GitHub Releases ship with the `nats` feature enabled alongside `kafka`, `http`, `snmp`, `arp`, `ndp`, and `oui`.

## See also

- [Scenario schema](../reference/scenario.md#sinks) — the exact JSON / YAML shape.
- [Kafka](kafka.md) — the parallel transport with the same NDJSON payload.
- [Source of truth](source-of-truth.md) — what consumers do with the records after parsing.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive.
