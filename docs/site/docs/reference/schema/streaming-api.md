---
description: rastreo describes its streaming surface with an AsyncAPI 3.0 document. This page covers topic and subject naming, correlation IDs, and how Kafka and NATS see the same wire format.
---

# Streaming API

rastreo ships a transport-neutral description of its streaming surface as an AsyncAPI 3.0 document at `schemas/asyncapi.yaml`. The spec describes two channels — a primary channel `rastreo.discovery.records.v1` carrying `DeviceRecord` messages, and a dead-letter channel for records that failed primary delivery — each attached to two servers (Kafka and NATS). Both transports carry the same JSON payload; the only difference is that Kafka calls a channel a "topic" and NATS calls it a "subject".

## What is AsyncAPI

AsyncAPI is to event-driven APIs what OpenAPI is to REST: a transport-neutral, YAML/JSON description of the messages an application produces or consumes, the channels those messages flow over, and the servers that host those channels. The spec is tool-friendly — it feeds AsyncAPI Studio for browsing, `@asyncapi/generator` for producing client code, and a growing set of documentation and testing tools.

For rastreo, the value is that a new consumer team can look at one file and know exactly what a `DeviceRecord` looks like on the wire, what topic / subject to subscribe to, what content type to expect, and how to correlate messages back to a scan.

## Where the spec lives

`schemas/asyncapi.yaml` in the source repo. It is hand-authored (not generated) and reviewed as source. The payload block references `./device-record-v1.json` — the same JSON Schema file the `schema_id` URL resolves to — so the AsyncAPI spec and the JSON Schema stay in sync automatically.

## Topic and subject naming

The channel address is `rastreo.discovery.records.v1`. That string is used verbatim as the Kafka topic name and as the NATS subject. The convention has three parts:

- `rastreo` — the producer / vendor namespace.
- `discovery.records` — the domain and record type.
- `v1` — the wire schema version.

A breaking change to the `DeviceRecord` shape ships a new channel at `rastreo.discovery.records.v2`. Both channels run in parallel for one release cycle so consumers can migrate on their own schedule. Additive changes stay on `v1`.

## Dead-letter channel

The spec declares a second channel, `deadLetterRecords`, for records that failed primary delivery. Its address in the spec (`rastreo.discovery.dlq.v1`) is illustrative — the real topic (Kafka) or subject (NATS) is whatever the sink's `dead_letter` config names. Each dead-letter message carries one unmodified `DeviceRecord` payload plus a set of `x-rastreo-*` headers. The `x-rastreo-error-class` header names the failure class so a consumer triages without parsing the payload. A consumer typically re-publishes the payload to the primary channel once the underlying issue is resolved.

The full header and payload contract is on the [DlqEnvelope schema page](dlq-envelope.md).

## Correlation ID

The AsyncAPI spec declares the correlation ID as `$message.payload#/scan_metadata/scan_id` — the ULID stamped on `ScanMetadata` at scan entry. Consumers use it to group records that were produced together into a single logical batch.

A ULID sorts lexicographically by generation time, so a consumer that groups by `scan_id` and sorts groups by that same key gets scans in chronological order for free — no separate timestamp field needed for group ordering.

## Consumer pattern

A consumer reads the record, checks `schema_id` against the URL it validates against, and processes the payload:

```json
{
  "identity_key": "mac:aa:bb:cc:dd:ee:ff",
  "schema_version": "v1",
  "schema_id": "https://davidban77.github.io/rastreo/schemas/device-record-v1.json",
  "scan_metadata": {
    "scan_id": "01HZY8K5QW9V4P0C6R8T3XM2ZB",
    "initiated_at": "2026-07-01T12:00:00Z"
  }
}
```

If the consumer sees a `schema_id` it has not cached, it can fetch and cache the schema at that URL. Because the URL is versioned, cache invalidation is trivial. See [the schema overview](index.md) for the full discovery pattern.

## Same wire format on Kafka and NATS

Both transports carry the same UTF-8 JSON bytes. The transport-level differences that matter for consumers:

- **Kafka**: the channel address is the topic name. Partitioning key is not set by rastreo today — consumers that need affinity should set a downstream key transform. `content-type: application/json` is set as a message header.
- **NATS**: the channel address is the subject. Subject-level wildcards (`rastreo.discovery.records.>`) work as expected for consumers subscribing to every version.

The AsyncAPI document below is the source of truth for both. A snippet:

```yaml
channels:
  discoveryRecords:
    address: rastreo.discovery.records.v1
    servers:
      - $ref: '#/servers/kafka'
      - $ref: '#/servers/nats'
    messages:
      deviceRecord:
        $ref: '#/components/messages/deviceRecord'

components:
  messages:
    deviceRecord:
      payload:
        $ref: './device-record-v1.json'
      correlationId:
        location: $message.payload#/scan_metadata/scan_id
```

See `schemas/asyncapi.yaml` in the source repo for the full spec.

## See also

- [DeviceRecord field reference](device-record.md)
- [ScanMetadata field reference](scan-metadata.md)
- [Schema overview and versioning](index.md)
