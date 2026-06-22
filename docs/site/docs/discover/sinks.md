---
description: Output sinks for rastreo discover — stdout (default), file, and Kafka. Configuration, NDJSON contract, and how to choose.
---

# Sinks

A sink is where `DeviceRecord` events go after they are encoded. rastreo ships three sinks today: stdout (the default), a file sink that writes NDJSON to a path, and a Kafka sink that publishes events to a topic. Every sink uses the same NDJSON encoder, so the on-the-wire shape is identical regardless of destination.

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

The Kafka sink publishes `DeviceRecord` events to a Kafka topic, encoded as NDJSON. Brokers are comma-separated; the topic is a single name. The detailed wire contract (how records are batched, how to tune the batch threshold) is covered in [Integrate](../integrate/index.md).

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

## NDJSON contract

The stdout and file sinks emit one `DeviceRecord` per NDJSON line. Each line is a complete JSON object — no surrounding array, no trailing comma. The Kafka sink uses the same NDJSON encoding for its payload bytes; see the [Integrate](../integrate/index.md) section for how those bytes map to Kafka records.

```json
{"identity_key":"ip:1.1.1.1","mgmt_ip":"1.1.1.1","mac":null,"manufacturer":null,"platform":null,"role":null,"confidence":0.2,"last_seen":{"secs_since_epoch":1782158571,"nanos_since_epoch":423959000},"signals":[{"OpenPort":443}]}
```

The field-by-field meaning of a `DeviceRecord` is covered in [First scan](../get-started/first-scan.md#read-the-output).

## Choosing a sink

- **stdout** for ad-hoc shell pipelines: piping into `jq`, `grep`, or a script that consumes NDJSON. The default for a reason — no setup, no extra flags.
- **file** for one-shot dumps you want to keep, share, or feed into another tool later. Append-mode means repeated scans accumulate into one file.
- **Kafka** for streaming into a topic that downstream consumers reconcile into a source of truth such as NetBox, Nautobot, or Infrahub. Consumer offset management belongs to the downstream system. See [Integrate](../integrate/index.md) for the wire contract.

## See also

- [CLI](cli.md) — every flag `rastreo discover` accepts.
- [Integrate](../integrate/index.md) — Kafka wire contract and downstream consumer guidance.
