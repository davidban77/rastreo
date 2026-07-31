---
description: The NATS JetStream wire contract — auth methods, per-record vs batched delivery, subject and stream setup, and consumer parsing strategy.
---

# NATS

NATS is a lightweight message broker — a single binary rastreo writes records to, so one or more consumers can read them later, each at its own pace. Choose NATS when you want durable delivery with a smaller operational surface than Kafka, or when your consumers already speak NATS.

Three NATS terms are load-bearing on this page:

- A **subject** is the named channel a message is published on.
- **JetStream** is NATS's persistence layer — the part that stores messages instead of dropping them once delivered.
- A **stream** is the stored buffer that captures every message published on the subjects it is bound to.

To run the NATS sink you need a running NATS server, a subject to publish on, and a JetStream stream that stores that subject. The NATS sink publishes `DeviceRecord` events to a JetStream subject; each message carries exactly one `DeviceRecord`, encoded as JSON. The payload is the same JSON `DeviceRecord` as the Kafka sink — only the transport differs.

## Wire contract

A JetStream message payload is one JSON-encoded `DeviceRecord` followed by a single `\n` byte. The message has no headers. The subject is a single subject (not a wildcard); the sink publishes only to it. Every publish is confirmed by a JetStream `PublishAck` before the sink reports the write delivered.

In `per_record` mode (the default), the sink publishes one message per `DeviceRecord` and waits for its ack before returning from the write. This is the simplest correctness model — every record is durable on the stream by the time the sink signals success.

In `batched` mode, the sink still publishes one message per record, but it does not wait for each ack inline. It buffers records until the buffered bytes reach `threshold_bytes` (default 65536), fires the publishes back to back, and holds the acks pending. Pending acks are capped: once enough have piled up the sink drains them mid-scan, so `threshold_bytes` sizes the publish batch and not the ack window. `flush()` drains whatever is still pending and returns an error if any publish was not acknowledged. Batched mode raises throughput by overlapping the ack round-trips, at the cost of a failure window covering the records whose acks are still outstanding if the process is killed.

## Basic scenario

Point rastreo at a NATS server, a subject, and the JetStream stream that binds the subject:

```yaml title="scenario.yaml"
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: nats-scan
    targets:
      - Cidr: "10.50.0.0/24"
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
    type: anonymous
```

Username + password:

```yaml
sink:
  type: nats
  servers: ["nats://nats.prod:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    type: user_pass
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
    type: token
    token: bearer-token-value
```

JWT + nkey via a `.creds` file — the credential file a NATS administrator gives you for a hosted or operator-managed cluster (for example Synadia's NGS service):

```yaml
sink:
  type: nats
  servers: ["tls://connect.ngs.global:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  credentials:
    type: creds
    creds_file: /etc/rastreo/nats.creds
```

Password and token values are redacted in logs and in `source_config_hash`. Rotating a credential still changes the hash, so consumers can detect config changes — but the plaintext is never logged or serialized. The `creds_file` value is a filesystem path, not a secret, and is written verbatim.

Inline userinfo in a server URL (`nats://user:pass@nats.prod:4222`) does not authenticate. The sink connects with the `credentials` block and nothing else, so against a broker that requires a user and password the connection is refused with `authorization violation` however the URL is written. The `user:pass@` portion is stripped everywhere the server list is rendered back to you — connect and publish errors, `rastreo discover --dry-run` plans, and the `last_probe_error` field of the server's `/readyz` response — so a password that landed in a URL does not leak, while the host, port, and failure reason stay intact for diagnosis.

## Delivery modes

`per_record` is the default and the right choice for most workloads. Every record is confirmed on the stream before the sink acknowledges the write, so a graceful shutdown never loses a record.

`batched` is the right choice for very high record rates where the extra ack round-trips dominate. It publishes each record as its own message and pipelines the acks, draining them whenever enough are outstanding and again at `flush()`. The pipeline calls `flush()` during graceful shutdown, which surfaces any ack error still open at that point.

Because those drains happen during the scan, a rejected ack can fail a record write mid-scan instead of waiting for `flush()`. Handle a sink error from either call the same way: the records the broker refused are still buffered, or in the [dead-letter queue](../discover/sinks.md#dead-letter-queue_1) if one is configured.

Set `flush_mode.type` to `batched`. The optional `threshold_bytes` field is the buffered-byte count that triggers the pipelined publishes (default 65536):

```yaml
sink:
  type: nats
  # ...
  flush_mode:
    type: batched
    threshold_bytes: 65536
```

!!! info
    Batched delivery pipelines the acks; it does not combine records. In both modes a consumer reads one message and gets one `DeviceRecord`.

## Delivery retry

A brief broker reconnect should not surface as a publish failure. The sink retries the primary publish with bounded backoff before it reports an error. Retry is on by default: 3 attempts, 100 ms initial backoff doubling to a 2000 ms cap. Tune it with a `retry` block, or set `max_attempts: 1` to disable it.

```yaml
sink:
  type: nats
  servers: ["nats://nats:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  retry:
    max_attempts: 5
    backoff_initial_ms: 100
    backoff_max_ms: 2000
```

Retry covers the synchronous publish only. rastreo waits for each ack once and does not re-send the message inside the same attempt. A rejected ack keeps the record in the buffer instead, and the next publish of that buffer sends it again. Delivery is therefore at-least-once: a message JetStream already stored can reach the stream a second time. See [Idempotency](#idempotency) for why a repeated record is harmless.

With a dead-letter queue configured, an ack-rejected record goes there instead of staying in the buffer. See [Sinks · Retrying before the dead-letter queue](../discover/sinks.md#retrying-before-the-dead-letter-queue_1) for how retry composes with the dead-letter queue.

## Stream setup

The JetStream stream that binds the subject must be created out of band. rastreo does not create it — the stream lifetime is typically longer than any single rastreo scan, and stream retention / storage policy is deployment-specific.

Bind the stream to the wildcard subject `rastreo.discovery.>`. One stream then captures every subject a scan uses: the device records on `subject`, plus the topology links that the LLDP prober publishes on a second subject under the same `rastreo.discovery.` prefix. A filter that names only `rastreo.discovery.records.v1` refuses those later publishes — see [Topology links on a second subject](#topology-links-on-a-second-subject) below.

Using the `nats` CLI:

```
nats stream add rastreo \
  --subjects 'rastreo.discovery.>' \
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

A JetStream consumer receives each message and runs one `json.loads` on the payload. One message is one record — there is nothing to split. The same code handles both delivery modes.

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
            record = loads(msg.data)     # one DeviceRecord per message
            upsert_record(record)
            await msg.ack()

asyncio.run(main())
```

## Topology links on a second subject

When a scan runs the [LLDP prober](../probe/lldp.md), rastreo discovers links between devices and publishes them as `LinkRecord`s on a **second subject**, separate from the device stream. Device records go to `subject`; link records go to `links_subject`, which defaults to `rastreo.discovery.links.v1`.

!!! warning "If you bound the stream to only the device subject"
    A JetStream stream stores messages only on the subjects its filter covers. The wildcard `rastreo.discovery.>` in [Stream setup](#stream-setup) covers the link subject, so a stream created that way needs no change. A stream bound to only `rastreo.discovery.records.v1` is the failure case: link publishes to `rastreo.discovery.links.v1` are refused at ack time once LLDP data appears. rastreo checks that the stream exists, not that both subjects fall inside its filter, so this surfaces mid-scan.

    The fix is to widen the stream's subject filter to the wildcard `rastreo.discovery.>` — edit the existing stream, or delete and recreate it with the [Stream setup](#stream-setup) command above.

    A refused link publish is not discarded. The sink keeps the record buffered and publishes it again on the next flush. Widen the filter mid-scan and those links still reach the stream. If the filter is still too narrow when the scan ends, the run fails with a sink error. Those links never reached the stream. The [dead-letter queue](../discover/sinks.md#dead-letter-queue_1) covers the device stream only, so a link record never goes there.

A consumer that reconciles topology subscribes to both subjects: the device subject to create or update devices, the links subject to create or update cables. A `LinkRecord` carries the same one-message-per-record framing as a `DeviceRecord`. See [Topology](../discover/topology.md) for the record shape and the mapping to NetBox cables and Nautobot interface connections.

## Idempotency

`identity_key` is the stable dedup key, identical to the Kafka sink. Consumers must upsert by `identity_key` — replace fields the new record carries, bump `last_seen`, and tolerate seeing the same key arrive any number of times. The NATS sink does not deduplicate. JetStream's own duplicate window (`--dupe-window` on the stream) matches on a message ID. rastreo sets none, so the window never collapses a record the sink published twice. Upserting by `identity_key` is what makes a repeat harmless.

## Build feature

The NATS sink is behind the `nats` Cargo feature on `rastreo-core` and on the binary crates. Build with:

```
cargo build --release --features nats -p rastreo
cargo build --release --features nats -p rastreo-server
```

The docker image and the release tarballs on GitHub Releases ship with the `nats` feature enabled alongside `kafka`, `http`, `snmp`, `arp`, and `ndp`.

## See also

- [Scenario schema](../reference/scenario.md#sinks) — the exact JSON / YAML shape.
- [Kafka](kafka.md) — the parallel transport with the same NDJSON payload.
- [Source of truth](source-of-truth.md) — what consumers do with the records after parsing.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive.
