---
description: Output sinks for rastreo discover — stdout (default), file, Kafka, and NATS. Configuration, NDJSON contract, and how to choose.
---

# Sinks

A sink is where `DeviceRecord` events go after they are encoded. rastreo ships four sinks today: stdout (the default), a file sink that writes NDJSON to a path, a Kafka sink that publishes events to a topic, and a NATS JetStream sink that publishes events to a subject. Every sink uses the same NDJSON encoder, so the on-the-wire shape is identical regardless of destination.

## Choosing a sink

- **stdout** for ad-hoc shell pipelines: piping into `jq`, `grep`, or a script that consumes NDJSON. The default for a reason — no setup, no extra flags.
- **file** for one-shot dumps you want to keep, share, or feed into another tool later. Append-mode means repeated scans accumulate into one file.
- **Kafka** for streaming into a topic that downstream consumers reconcile into a source of truth such as NetBox, Nautobot, or Infrahub. Consumer offset management belongs to the downstream system. See [Integrate](../integrate/index.md) for the wire contract.
- **NATS** for a lighter-weight streaming transport with at-least-once JetStream delivery. Pick NATS when the reconcilers already speak NATS or when you want to avoid the Kafka broker footprint. See [Integrate · NATS](../integrate/nats.md) for the wire contract.

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

The Kafka sink publishes `DeviceRecord` events to a Kafka topic. Each Kafka message carries exactly one `DeviceRecord`. Brokers are comma-separated; the topic is a single name. Two flush modes are available: batched (the default — buffers records and sends them in one produce request at a configurable byte threshold) and per-record (sends each record immediately). Both put one record in each message; the mode changes throughput, not the wire framing. Use `--kafka-flush-per-record` or `--kafka-batch-threshold <BYTES>` on the CLI; see [Integrate](../integrate/index.md) for the full wire contract.

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
  --topic rastreo.discovery.records.v1
```

`--sink kafka` requires both `--brokers` and `--topic`; either missing is rejected before any probe runs.

Secured brokers — Confluent Cloud, Amazon MSK, any `SASL_SSL` listener — need TLS and SASL settings that the CLI flags do not cover. Configure them with `tls` and `sasl` blocks in a scenario file. The TLS `verify` field defaults to `false` (accept any certificate); set `verify: true` on production brokers. See [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication) for the full config surface and a Confluent Cloud example.

### Retrying before the dead-letter queue

A brief broker reconnect should not fill the dead-letter queue. The dead-letter queue, or DLQ, is a second topic for records the primary produce could not deliver. It is defined in full [below](#dead-letter-queue). The Kafka sink retries the primary produce with bounded backoff before it falls back to the DLQ. A short outage that clears within the retry budget reaches the primary topic and is never quarantined.

Retry is on by default. Every Kafka sink retries even with no `retry` block. Add the block to change the limits. It has three fields:

- `max_attempts` — the total number of primary produce attempts, including the first. The default `3` is the first attempt plus two retries. Set `1` to disable retry: the record goes to the DLQ on the first failure.
- `backoff_initial_ms` — the wait before the first retry, in milliseconds. Default `100`.
- `backoff_max_ms` — the largest wait between attempts, in milliseconds. Default `2000`.

The wait doubles after each failed attempt and stops growing at `backoff_max_ms`. With the defaults, the sink waits 100 ms, then 200 ms.

```yaml
sink:
  type: kafka
  brokers: [kafka-0.internal:9092]
  topic: rastreo.discovery.records.v1
  retry:
    max_attempts: 5
    backoff_initial_ms: 100
    backoff_max_ms: 2000
  dead_letter:
    topic: rastreo.discovery.dlq
```

Only the primary produce is retried. The DLQ produce is never retried. The total time is bounded: worst case is `max_attempts` produce attempts plus the capped waits between them. A failing sink cannot hang.

!!! tip "Disabling retry"
    Set `max_attempts: 1` to keep the earlier behavior: the record goes to the DLQ on the first primary failure, with no retry in between.

### Dead-letter queue

The Kafka sink can quarantine records the primary topic refused instead of dropping them silently. Configure a second Kafka topic under `dead_letter` in a YAML scenario (there is no CLI flag for the DLQ; it is a scenario-level concern). When the primary produce fails and a DLQ is configured, the sink publishes the same payload to the DLQ topic, logs a `WARN`, and returns success — the buffer is drained and the pipeline moves on. When no DLQ is configured, the primary failure surfaces as an error and the buffer is retained for `flush()` retry (the pre-existing behavior).

```yaml
sink:
  type: kafka
  brokers: [kafka-0.internal:9092]
  topic: rastreo.discovery.records.v1
  dead_letter:
    topic: rastreo.discovery.dlq
    include_error_metadata: true
```

DLQ messages default to carrying a small header envelope so downstream consumers can filter and diagnose without inspecting the payload:

| Header | Value | Encoding |
|---|---|---|
| `x-rastreo-source-topic` | Primary topic name (e.g. `rastreo.discovery.records.v1`) | UTF-8 bytes |
| `x-rastreo-error-class` | `produce_failure` — the class of a failed Kafka produce | UTF-8 bytes |
| `x-rastreo-dlq-timestamp` | RFC 3339 UTC timestamp of the DLQ publish | UTF-8 bytes |

Set `include_error_metadata: false` to ship the payload with no headers — the DLQ message body is byte-identical to what would have gone to the primary topic.

**Failure model.** Primary produce succeeds → the payload lands on the primary topic. Primary fails and DLQ succeeds → the payload lands on the DLQ topic, a `WARN` log is emitted, and the pipeline continues. Primary fails and DLQ also fails → an `ERROR` log records both failures, the sink returns the primary error, and the buffer is retained for the caller to retry via `flush()` (identical to the no-DLQ path).

**Consumer guidance.** A DLQ consumer typically re-publishes the payload to the primary topic once the underlying issue (broker outage, topic ACL, partition offline) is resolved. Filter on `x-rastreo-source-topic` when the same DLQ is shared across multiple discovery pipelines; use `x-rastreo-dlq-timestamp` to skip records older than a retention window.

**Metric.** Each successful Kafka DLQ delivery increments `rastreo_server_dlq_records_total{sink_type="kafka",error_class="produce_failure"}`, surfaced on `/metrics` and via OTLP. The `error_class` is the actual class of the failure that quarantined the record. A Kafka produce is the only path that sends a record to the Kafka DLQ, so Kafka DLQ traffic always carries `produce_failure`. See [Observability · DLQ error-class attribution](../reference/observability.md#dlq-error-class-attribution) for the full class list and the [DlqEnvelope schema](../reference/schema/dlq-envelope.md) for the header contract.

**Reachability probe.** When a DLQ is configured, the server-side sink reachability probe covers both partitions: it issues a `ListOffsets` against the primary partition **and** a `ListOffsets` against the DLQ partition on every tick, regardless of whether the primary succeeded. Either side returning an error flips `sink_reachable` to `false` on `/readyz`. `last_probe_error` names the failed side (`primary partition unreachable ...` or `dead-letter partition unreachable ...`); when both sides fail, both segments are included, joined by `; `. Operators get advance warning that DLQ fallback would fail — including the case where the primary is already down and the DLQ is the only remaining safety net.

**See also.** Sink failures surface operationally through the [`/readyz` readiness gate](../reference/health-endpoints.md#readyz-readiness) on `rastreo-server`: a sink error observed within `RASTREO_SINK_ERROR_QUARANTINE_SECS` flips the pod to `503 not_ready`.

## NATS

The NATS sink publishes `DeviceRecord` events to a NATS JetStream subject. Each NATS message carries exactly one `DeviceRecord`. Because the wire options are richer than Kafka (four auth methods, two delivery modes, a stream binding), the NATS sink is configured through YAML scenarios loaded with `--file` or through the `POST /scans` request body — there are no dedicated CLI flags. Two delivery modes are available: per-record (the default — publishes each record and waits for its JetStream ack) and batched (pipelines the acks of many per-record publishes at a configurable byte threshold). Both put one record in each message. See [Integrate · NATS](../integrate/nats.md) for the full wire contract, auth details, and stream setup.

!!! warning "Requires the `nats` build feature"
    The `type: nats` value only exists when the binary is built with the `nats` Cargo feature. The default build does not include it. To build with NATS support:

    ```bash
    cargo build --workspace --features nats
    cargo install --path rastreo --features nats
    ```

```yaml title="scenario.yaml"
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: nats-scan
    targets:
      - Cidr: "192.0.2.0/24"
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

### Retrying before the dead-letter queue

The dead-letter queue, or DLQ, is a second JetStream subject for records the primary publish could not deliver. It is defined in full [below](#dead-letter-queue_1). The NATS sink retries the primary publish with bounded backoff before it falls back to the DLQ. A short broker outage that clears within the retry budget reaches the primary subject and is never quarantined. Retry works the same way as the Kafka sink, with the same `retry` block and defaults.

The block has three fields:

- `max_attempts` — the total number of primary publish attempts, including the first. The default `3` is the first attempt plus two retries. Set `1` to disable retry.
- `backoff_initial_ms` — the wait before the first retry, in milliseconds. Default `100`.
- `backoff_max_ms` — the largest wait between attempts, in milliseconds. Default `2000`.

```yaml
sink:
  type: nats
  servers: ["nats://nats-0.internal:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  retry:
    max_attempts: 5
    backoff_initial_ms: 100
    backoff_max_ms: 2000
  dead_letter:
    stream: rastreo-dlq
    subject: rastreo.discovery.dlq
```

Retry covers the synchronous publish only. A JetStream ack rejection is not retried, because the message may already be stored and re-publishing it could duplicate the record. An ack rejection goes straight to the DLQ with error class `ack_rejection`. The DLQ publish is never retried either.

!!! tip "Disabling retry"
    Set `max_attempts: 1` to keep the earlier behavior: the record goes to the DLQ on the first primary publish failure, with no retry in between.

### Dead-letter queue

The NATS sink can quarantine records the primary subject refused instead of dropping them silently. Configure a second JetStream stream + subject under `dead_letter` in a YAML scenario (there is no CLI flag for the DLQ; it is a scenario-level concern). Unlike Kafka, NATS has two failure surfaces the DLQ absorbs: the synchronous `publish()` call (broker unreachable, subject invalid) and the JetStream ack (broker accepted the publish for routing but refused durable storage — stream retention limits, wrong stream binding, quota exceeded). When either surface fails and a DLQ is configured, the sink publishes the same payload to the DLQ subject, logs a `WARN`, and returns success. When no DLQ is configured, the failure surfaces as an error and the buffer / pending queue is retained.

```yaml
sink:
  type: nats
  servers: ["nats://nats-0.internal:4222"]
  subject: rastreo.discovery.records.v1
  stream: rastreo
  dead_letter:
    stream: rastreo-dlq
    subject: rastreo.discovery.dlq
    include_error_metadata: true
```

The DLQ subject must be bound to a JetStream stream that exists on the same NATS cluster; construction fails fast if the stream is missing so records never silently drop. Both primary and DLQ publishes share the sink's single NATS connection.

DLQ messages default to carrying a small header envelope so downstream consumers can filter and diagnose without inspecting the payload:

| Header | Value | Encoding |
|---|---|---|
| `x-rastreo-source-subject` | Primary subject name (e.g. `rastreo.discovery.records.v1`) | NATS header string |
| `x-rastreo-error-class` | `publish_failure` or `ack_rejection` (see below) | NATS header string |
| `x-rastreo-dlq-timestamp` | RFC 3339 UTC timestamp of the DLQ publish | NATS header string |

The two error classes are diagnostically distinct so an ops team can triage DLQ traffic:

| Class | Meaning |
|---|---|
| `publish_failure` | The synchronous `publish()` to the primary subject failed. Typically broker unreachable or the subject/stream binding is wrong. |
| `ack_rejection` | JetStream accepted the publish for routing but refused durable storage. Typically stream retention hit, quota exceeded, or the subject is bound to a different stream than expected. |

Set `include_error_metadata: false` to ship the payload with no headers — the DLQ message body is byte-identical to what would have gone to the primary subject.

**Failure model.** Primary publish OK, ack OK → the payload lands on the primary subject. Primary publish fails, DLQ publish + ack succeed → the payload lands on the DLQ subject, a `WARN` log is emitted, and the pipeline continues. Primary publish OK but ack fails, DLQ publish + ack succeed → same outcome, `WARN` log, pipeline continues. Any DLQ publish or ack failure → an `ERROR` log records the DLQ failure, the sink returns the original error, and the buffer / pending queue is retained for the caller to retry via `flush()`.

**Consumer guidance.** A DLQ consumer typically re-publishes the payload to the primary subject once the underlying issue (broker outage, stream misconfiguration, quota) is resolved. Filter on `x-rastreo-source-subject` when the same DLQ is shared across multiple discovery pipelines; filter on `x-rastreo-error-class` to split triage between broker-connectivity issues (`publish_failure`) and stream-durability issues (`ack_rejection`); use `x-rastreo-dlq-timestamp` to skip records older than a retention window.

**Metric.** Each successful NATS DLQ delivery increments `rastreo_server_dlq_records_total{sink_type="nats",error_class="..."}`, surfaced on `/metrics` and via OTLP. The `error_class` is the actual class of the failure that quarantined the record: `publish_failure` when the synchronous publish failed, `ack_rejection` when JetStream refused durable storage after accepting the publish. The two classes let you split triage without opening logs. See [Observability · DLQ error-class attribution](../reference/observability.md#dlq-error-class-attribution) for the full class list and the [DlqEnvelope schema](../reference/schema/dlq-envelope.md) for the header contract.

**See also.** Sink failures surface operationally through the [`/readyz` readiness gate](../reference/health-endpoints.md#readyz-readiness) on `rastreo-server`: a sink error observed within `RASTREO_SINK_ERROR_QUARANTINE_SECS` flips the pod to `503 not_ready`. Caveat: the current server-side gate only trips when a scan attempts a write and fails; it does not detect pre-request unreachability against a broker that is already down. For proactive detection, set `RASTREO_SINK_CONFIG_PATH` on `rastreo-server` to probe broker reachability on a fixed cadence and gate `/readyz` before a scan writes — see [Health endpoints](../reference/health-endpoints.md#readyz-readiness).

## NDJSON contract

The stdout and file sinks emit one `DeviceRecord` per NDJSON line. Each line is a complete JSON object — no surrounding array, no trailing comma. The Kafka and NATS sinks use the same JSON encoding, and each message they publish carries exactly one `DeviceRecord`. See the [Integrate](../integrate/index.md) section for the full transport contract.

```json
{"identity_key":"ip:1.1.1.1","mgmt_ip":"1.1.1.1","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":"2026-07-05T11:22:51.423959000Z","signals":[{"OpenPort":443}]}
```

The field-by-field meaning of a `DeviceRecord` is covered in [First scan](../get-started/first-scan.md#read-the-output).

## See also

- [CLI](cli.md) — every flag `rastreo discover` accepts.
- [Integrate · Kafka](../integrate/kafka.md) — Kafka wire contract.
- [Integrate · NATS](../integrate/nats.md) — NATS JetStream wire contract.
- [DlqEnvelope schema](../reference/schema/dlq-envelope.md) — the header and payload contract on every dead-letter message.
