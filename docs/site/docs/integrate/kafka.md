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

## Idempotency

`identity_key` is the stable dedup key. For IP targets, it is `ip:<address>`. The same target probed twice produces two `DeviceRecord` events with the same `identity_key` but different `last_seen` timestamps. Consumers must upsert by `identity_key` — replace the fields the new record carries, update `last_seen`, and tolerate seeing the same key arrive any number of times.

The Kafka sink does not deduplicate. Records are emitted as the discovery pipeline observes them; deduplication is a consumer responsibility.

## Tuning the threshold

`--kafka-batch-threshold <BYTES>` sets the buffered-byte count that triggers a produce request in `batched` mode. The default is 65536 (64 KiB); the minimum is 1. A low value sends more frequent, smaller produce requests. A high value keeps records in memory longer — records wait in the buffer until the threshold is reached or the scan ends. The message count on the topic is the same either way; only the number of produce requests changes.

For interactive scans where you want records on the topic as the scan runs, prefer `--kafka-flush-per-record` over lowering the batch threshold to 1. The flag is the clear way to say "send after every record".

## See also

- [Sinks](../discover/sinks.md) — the CLI surface for choosing a sink and setting its flags.
- [Source of truth](source-of-truth.md) — what consumers do with the records after parsing.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive on the topic.
