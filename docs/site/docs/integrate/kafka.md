---
description: The Kafka wire contract — one message per DeviceRecord, batched vs per-record flush modes, consumer parsing, and idempotency.
---

# Kafka

The Kafka sink publishes `DeviceRecord` events to a topic on a single partition. Each Kafka message carries exactly one `DeviceRecord`, encoded as JSON. Two flush modes control how the sink groups the network round-trips: `batched` (the default) and `per_record`. Both put one record in each message — the mode changes throughput, not the wire framing.

## Wire contract

A Kafka message value is one JSON-encoded `DeviceRecord` followed by a single `\n` byte. The message has no key, no headers, and is produced without compression. The topic is single-partition (partition `0`). The producer timestamp is wall-clock time at produce time.

A single Kafka message value looks like this:

```json
{"identity_key":"ip:10.50.0.10","mgmt_ip":"10.50.0.10","mac":null,"manufacturer":null,"platform":null,"os_version":null,"role":null,"confidence":0.2,"last_seen":"2026-07-05T13:47:22.678133Z","signals":[{"OpenPort":80}],"probe_kinds":["TcpConnect"],"schema_version":"v1","schema_id":"https://davidban77.github.io/rastreo/schemas/device-record-v1.json","possible_alias_of":null,"scan_metadata":{"scan_id":"01KXC3Z94835AJY8WWSYQ81Y1P","scenario_name":null,"initiated_at":"2026-07-05T13:47:22.676000Z","source_config_hash":"sha256:63b96614fd6aa54b03a6f04d56b311d00c795f32881a27d0d4168411ec6a2f30"}}
```

The trailing `\n` is a single byte at the end of the value. A JSON parser ignores trailing whitespace, so a consumer passes the whole value straight to `json.loads`.

## Choosing a mode

Both modes put one `DeviceRecord` in each Kafka message. They differ only in how the sink groups the network round-trips.

`batched` (the default) buffers records in memory until the buffered bytes reach `threshold_bytes` (default 65536, override with `--kafka-batch-threshold <BYTES>`). At the threshold, the sink sends the buffered records in one produce request. That request still carries N separate messages — one per record. When the scan ends, the sink sends any remaining buffered records in one final produce request. Choose it for large scans: fewer produce requests lower broker overhead and raise throughput.

`per_record` (opt in with `--kafka-flush-per-record`) sends one produce request per record, with no buffering. Choose it when records must reach downstream systems as soon as they are discovered, for example low-latency reconciliation, or when a tool keys off Kafka offsets one-to-one with records.

!!! info
    Batching changes throughput, not the wire framing. In both modes a consumer reads one message and gets one `DeviceRecord`.

## TLS and SASL authentication

Managed Kafka services — Confluent Cloud, Amazon MSK, or any broker on a `SASL_SSL` listener — require an encrypted connection and credentials. The Kafka sink accepts two optional, independent config blocks for this: `tls` for the encrypted connection and `sasl` for the credentials. Both are scenario-only. There are no CLI flags for them, so a secured broker needs a scenario file (`--file`) or a `POST /scans` request body.

### TLS

The `tls` block has two fields. `verify` decides whether the sink checks the broker's certificate. `ca_cert` supplies a PEM certificate for a private certificate authority, and the sink reads it only when `verify: true`.

!!! warning "`verify` defaults to `false` — set `verify: true` on production brokers"
    The `verify` field defaults to `false`, which accepts any broker certificate without checking it. This matches the permissive TLS default across rastreo's probers. rastreo is built for lab and internal networks, where self-signed broker certificates are common.

    On a broker that carries SASL credentials, an unverified certificate is a man-in-the-middle risk. An attacker who intercepts the connection presents any certificate and collects the SASL username and password.

    Set `verify: true` on every production broker. Add `ca_cert` when the broker's certificate comes from a private certificate authority that the system trust store does not already include.

Enable verification against the standard public root certificates. They are bundled in the binary, so no system root store is needed:

```yaml
sink:
  type: kafka
  brokers: ["broker.internal:9093"]
  topic: rastreo.discovery.records
  tls:
    verify: true
```

Verify against a private certificate authority by pointing `ca_cert` at a PEM file. Use the `!file` tag so the certificate stays out of the scenario YAML:

```yaml
sink:
  type: kafka
  brokers: ["broker.internal:9093"]
  topic: rastreo.discovery.records
  tls:
    verify: true
    ca_cert: !file /run/secrets/kafka-ca.pem
```

### SASL

The `sasl` block has three fields. `mechanism` names the SASL mechanism. `username` is the account name. `password` is its secret. Three mechanisms are supported:

| Mechanism | `mechanism` value |
|---|---|
| PLAIN | `plain` |
| SCRAM-SHA-256 | `scram_sha_256` |
| SCRAM-SHA-512 | `scram_sha_512` |

Never write the `password` inline. Use a `${VAR}` environment reference or the `!file` tag so the secret stays out of the scenario file. See [Secrets](../reference/secrets.md) for both syntaxes.

```yaml
sink:
  type: kafka
  brokers: ["broker.internal:9092"]
  topic: rastreo.discovery.records
  sasl:
    mechanism: scram_sha_512
    username: rastreo-writer
    password: ${KAFKA_PASSWORD}
```

### How the blocks compose

The `tls` and `sasl` blocks are independent, so every Kafka security protocol is a combination of the two. Include the blocks the broker's listener requires:

| Broker listener | `tls` block | `sasl` block |
|---|---|---|
| `PLAINTEXT` | omit | omit |
| `SSL` | present | omit |
| `SASL_PLAINTEXT` | omit | present |
| `SASL_SSL` | present | present |

Managed brokers are almost always `SASL_SSL`. Confluent Cloud uses SASL/PLAIN over TLS, and Amazon MSK offers SASL/SCRAM over TLS. Both need the `tls` and `sasl` blocks together.

### Example: Confluent Cloud

Confluent Cloud authenticates with a cluster API key as the username and an API secret as the password, over TLS. The API key and secret come from the environment so neither appears in the scenario file:

```yaml
sink:
  type: kafka
  brokers: ["pkc-xxxxx.us-east-1.aws.confluent.cloud:9092"]
  topic: rastreo.discovery.records
  tls:
    verify: true
  sasl:
    mechanism: plain
    username: ${KAFKA_API_KEY}
    password: ${KAFKA_API_SECRET}
```

Export the two values before the run:

```bash
export KAFKA_API_KEY="your-cluster-api-key"
export KAFKA_API_SECRET="your-cluster-api-secret"
rastreo discover --file scenario.yaml
```

## Consumer parsing

A consumer reads each Kafka message and runs one `json.loads` on the message value. One message is one record — there is nothing to split.

```python
from json import loads

from confluent_kafka import Consumer

consumer = Consumer({
    "bootstrap.servers": "localhost:9092",
    "group.id": "rastreo-reconciler",
    "auto.offset.reset": "earliest",
})
consumer.subscribe(["rastreo.devices"])

while True:
    msg = consumer.poll(1.0)
    if msg is None or msg.error():
        continue
    record = loads(msg.value())     # one DeviceRecord per message
    upsert_record(record)
```

```go
// franz-go consumer sketch
for _, rec := range fetches.Records() {
    var record DeviceRecord
    if err := json.Unmarshal(rec.Value, &record); err != nil {
        log.Printf("skip malformed message: %v", err)
        continue
    }
    upsertRecord(record)
}
```

## Topology links on a second topic

When a scan runs the [LLDP prober](../probe/lldp.md), rastreo discovers links between devices and emits them as `LinkRecord`s on a **second topic**, separate from the device stream. Device records go to `topic`; link records go to `links_topic`, which defaults to `rastreo.discovery.links.v1`.

A consumer that reconciles topology subscribes to both topics: the device topic to create or update devices, the links topic to create or update cables. A `LinkRecord` carries the same one-message-per-record wire framing as a `DeviceRecord`, so the parsing code is identical — only the topic and the payload shape differ. See [Topology](../discover/topology.md) for the record shape and the mapping to NetBox cables and Nautobot interface connections.

## Idempotency

`identity_key` is the stable dedup key. For IP targets, it is `ip:<address>`. The same target probed twice produces two `DeviceRecord` events with the same `identity_key` but different `last_seen` timestamps. Consumers must upsert by `identity_key` — replace the fields the new record carries, update `last_seen`, and tolerate seeing the same key arrive any number of times.

The Kafka sink does not deduplicate. Records are emitted as the discovery pipeline observes them; deduplication is a consumer responsibility.

## Tuning the threshold

`--kafka-batch-threshold <BYTES>` sets the buffered-byte count that triggers a produce request in `batched` mode. The default is 65536 (64 KiB); the minimum is 1. A low value sends more frequent, smaller produce requests. A high value keeps records in memory longer — records wait in the buffer until the threshold is reached or the scan ends. The message count on the topic is the same either way; only the number of produce requests changes.

For interactive scans where you want records on the topic as the scan runs, prefer `--kafka-flush-per-record` over lowering the batch threshold to 1. The flag is the clear way to say "send after every record".

## Delivery retry

Managed brokers — Confluent Cloud, Amazon MSK — drop and re-establish connections routinely. The sink retries the primary produce with bounded backoff so a transient reconnect does not surface as a failure. Retry is on by default: 3 attempts, 100 ms initial backoff doubling to a 2000 ms cap. Tune it with a `retry` block on the sink, or set `max_attempts: 1` to disable it.

```yaml
sink:
  type: kafka
  brokers: ["broker.internal:9092"]
  topic: rastreo.discovery.records
  retry:
    max_attempts: 5
    backoff_initial_ms: 100
    backoff_max_ms: 2000
```

See [Sinks · Retrying before the dead-letter queue](../discover/sinks.md#retrying-before-the-dead-letter-queue) for the full field reference and how retry composes with the dead-letter queue.

## See also

- [Sinks](../discover/sinks.md) — the CLI surface for choosing a sink and setting its flags.
- [Secrets](../reference/secrets.md) — `${VAR}` and `!file` syntax for the SASL password and the TLS `ca_cert`.
- [Source of truth](source-of-truth.md) — what consumers do with the records after parsing.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive on the topic.
