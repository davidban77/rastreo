---
description: The Kafka wire contract — batched vs per-record flush modes, NDJSON payload shape, consumer parsing strategy, and idempotency model.
---

# Kafka

The Kafka sink publishes `DeviceRecord` events to a topic on a single partition, encoded as NDJSON. The sink supports two flush modes: `Batched` (the default — accumulates records into one Kafka message at a configurable byte threshold) and `PerRecord` (one Kafka message per record). The wire format is the same in both modes; the difference is how many `DeviceRecord` lines end up inside each Kafka message value.

## Wire contract

A Kafka message value is a sequence of NDJSON-encoded `DeviceRecord` objects, each terminated by a single `\n` byte. The message has no key, no headers, and is produced with `NoCompression`. The topic is single-partition (partition `0`). The producer timestamp is wall-clock time at produce time.

In `Batched` mode (default), records accumulate in an in-memory buffer until the buffer length reaches `threshold_bytes` (default 65536, override with `--kafka-batch-threshold <BYTES>`). When the threshold is reached, the buffer is produced as one Kafka message. When the discovery scan ends, any remaining buffered records are produced as one final message on `flush()`. A typical `Batched`-mode Kafka message value with three records looks like:

```text
{"identity_key":"ip:10.50.0.10","mgmt_ip":"10.50.0.10","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":{"secs_since_epoch":1782167242,"nanos_since_epoch":678133082},"signals":[{"OpenPort":80}]}
{"identity_key":"ip:10.50.0.11","mgmt_ip":"10.50.0.11","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":{"secs_since_epoch":1782167242,"nanos_since_epoch":681947013},"signals":[{"OpenPort":80}]}
{"identity_key":"ip:10.50.0.12","mgmt_ip":"10.50.0.12","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":{"secs_since_epoch":1782167242,"nanos_since_epoch":684201874},"signals":[{"OpenPort":80}]}
```

In `PerRecord` mode (opt in via `--kafka-flush-per-record`), the sink calls `produce()` after every record, so every Kafka message value contains exactly one NDJSON-encoded `DeviceRecord` followed by a single `\n` byte.

## Choosing a mode

`Batched` is the default and the right choice when the consumer can split NDJSON on `\n`. Fewer Kafka messages mean lower broker overhead and higher throughput for large scans.

`PerRecord` is the right choice when the consumer can not split NDJSON itself, when records must be available to downstream systems as soon as they are discovered (low-latency reconciliation), or when downstream tools key off Kafka offsets one-to-one with records.

## Consumer parsing

A consumer reads each Kafka message value, splits the bytes on `\n`, drops the empty trailing entry, and deserializes each remaining line as JSON. The same code handles both flush modes — `PerRecord` simply yields one record per message instead of many.

```python
# Python kafka-python consumer sketch
from json import loads
from kafka import KafkaConsumer

consumer = KafkaConsumer(
    "rastreo.devices",
    bootstrap_servers=["localhost:9092"],
    auto_offset_reset="earliest",
)

for msg in consumer:
    for line in msg.value.split(b"\n"):
        if not line:
            continue
        record = loads(line)
        upsert_record(record)
```

```go
// Go franz-go consumer sketch
for _, rec := range fetches.Records() {
    for _, line := range bytes.Split(rec.Value, []byte("\n")) {
        if len(line) == 0 {
            continue
        }
        var record DeviceRecord
        if err := json.Unmarshal(line, &record); err != nil {
            log.Printf("skip malformed line: %v", err)
            continue
        }
        upsertRecord(record)
    }
}
```

## Idempotency

`identity_key` is the stable dedup key. For IP targets, it is `ip:<address>`. The same target probed twice produces two `DeviceRecord` events with the same `identity_key` but different `last_seen` timestamps. Consumers must upsert by `identity_key` — replace fields the new record carries, bump `last_seen`, and tolerate seeing the same key arrive any number of times.

The Kafka sink does not deduplicate. Records are emitted as the discovery pipeline observes them; deduplication is a consumer responsibility.

## Tuning the threshold

`--kafka-batch-threshold <BYTES>` sets the byte-count trigger for `Batched` mode. The default is 65536 (64 KiB), the minimum is 1. A value too low produces many small Kafka messages and wastes broker overhead. A value too high keeps records in memory longer and delays delivery — records sit in the buffer until either the threshold is reached or the scan ends.

For interactive scans where you want to see records on the topic as the scan runs, prefer `--kafka-flush-per-record` over lowering the batch threshold to 1. The flag is the readable way to say "flush after every record".

## See also

- [Sinks](../discover/sinks.md) — the CLI surface for choosing a sink and setting its flags.
- [Source of truth](source-of-truth.md) — what consumers do with the records after parsing.
- [Troubleshooting](troubleshooting.md) — common failures when records do not arrive on the topic.
