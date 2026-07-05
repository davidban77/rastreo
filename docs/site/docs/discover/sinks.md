---
description: Output sinks for rastreo discover — stdout (default), file, Kafka, and NATS. Configuration, NDJSON contract, and how to choose.
---

# Sinks

A sink is where `DeviceRecord` events go after they are encoded. rastreo ships four sinks today: stdout (the default), a file sink that writes NDJSON to a path, a Kafka sink that publishes events to a topic, and a NATS JetStream sink that publishes events to a subject. Every sink uses the same NDJSON encoder, so the on-the-wire shape is identical regardless of destination.

## stdout (default)

The default sink writes one NDJSON `DeviceRecord` per line to stdout. Tracing logs and the end-of-run summary go to stderr, which keeps stdout clean for downstream tools.

```bash
rastreo discover --target 1.1.1.1 --port 443 | jq .
```

The example above pipes stdout into `jq` without any log noise, because `jq` reads stdin and rastreo's logs went to stderr.

## file

The file sink appends one NDJSON record per line to the path you give. The file is opened in append mode, so repeated runs add to the existing file rather than overwriting it.

```bash
rastreo discover \
  --target 192.0.2.0/24 \
  --port 80 \
  --sink file \
  --output /tmp/scan.ndjson
```

`--sink file` without `--output` is rejected before any probe runs.

## Kafka

The Kafka sink publishes `DeviceRecord` events to a Kafka topic, encoded as NDJSON. Brokers are comma-separated; the topic is a single name. Two flush modes are available: batched (the default, accumulates records into one Kafka message at a configurable byte threshold) and per-record (one Kafka message per `DeviceRecord`). Use `--kafka-flush-per-record` or `--kafka-batch-threshold <BYTES>` on the CLI; see [Integrate](../integrate/index.md) for the full wire contract.

!!! warning "Requires the `kafka` build feature"
    The `kafka` value for `--sink` only exists when the binary is built with the `kafka` Cargo feature. The default build does not include it. To build with Kafka support:

    ```bash
    cargo build --workspace --features kafka
    cargo install --path rastreo --features kafka
    ```

```bash
rastreo discover \
  --target 192.0.2.0/24 \
  --port 80 \
  --sink kafka \
  --brokers localhost:9092 \
  --topic rastreo.devices
```

`--sink kafka` requires both `--brokers` and `--topic`; either missing is rejected before any probe runs.

## NATS

The NATS sink publishes `DeviceRecord` events to a NATS JetStream subject, encoded as NDJSON. Because the wire options are richer than Kafka (four auth methods, two delivery modes, a stream binding), the NATS sink is configured through YAML scenarios loaded with `--file` or through the `POST /scans` request body — there are no dedicated CLI flags. Two delivery modes are available: per-record (the default, publishes each record and waits for the JetStream ack) and batched (accumulates NDJSON bytes into one publish at a configurable byte threshold). See [Integrate · NATS](../integrate/nats.md) for the full wire contract, auth details, and stream setup.

!!! warning "Requires the `nats` build feature"
    The `type: nats` value only exists when the binary is built with the `nats` Cargo feature. The default build does not include it. To build with NATS support:

    ```bash
    cargo build --workspace --features nats
    cargo install --path rastreo --features nats
    ```

```yaml
# scenario.yaml
targets:
  - 192.0.2.0/24
probers:
  - type: tcp_connect
    ports: [80, 443]
sink:
  type: nats
  servers: ["nats://nats:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
```

```bash
rastreo discover --file scenario.yaml
```

## NDJSON contract

The stdout and file sinks emit one `DeviceRecord` per NDJSON line. Each line is a complete JSON object — no surrounding array, no trailing comma. The Kafka and NATS sinks use the same NDJSON encoding for their payload bytes; see the [Integrate](../integrate/index.md) section for how those bytes map to Kafka records or NATS JetStream messages.

```json
{"identity_key":"ip:1.1.1.1","mgmt_ip":"1.1.1.1","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":"2026-07-05T11:22:51.423959000Z","signals":[{"OpenPort":443}]}
```

The field-by-field meaning of a `DeviceRecord` is covered in [First scan](../get-started/first-scan.md#read-the-output).

## Choosing a sink

- **stdout** for ad-hoc shell pipelines: piping into `jq`, `grep`, or a script that consumes NDJSON. The default for a reason — no setup, no extra flags.
- **file** for one-shot dumps you want to keep, share, or feed into another tool later. Append-mode means repeated scans accumulate into one file.
- **Kafka** for streaming into a topic that downstream consumers reconcile into a source of truth such as NetBox, Nautobot, or Infrahub. Consumer offset management belongs to the downstream system. See [Integrate](../integrate/index.md) for the wire contract.
- **NATS** for a lighter-weight streaming transport with at-least-once JetStream delivery. Pick NATS when the reconcilers already speak NATS or when you want to avoid the Kafka broker footprint. See [Integrate · NATS](../integrate/nats.md) for the wire contract.

## See also

- [CLI](cli.md) — every flag `rastreo discover` accepts.
- [Integrate · Kafka](../integrate/kafka.md) — Kafka wire contract.
- [Integrate · NATS](../integrate/nats.md) — NATS JetStream wire contract.
