---
description: The dead-letter envelope wraps a DeviceRecord that failed primary delivery. This page describes the `x-rastreo-*` transport headers, the error-class values, and the payload contract.
---

# DlqEnvelope

When a record fails primary delivery and a dead-letter destination is configured, rastreo quarantines the record there inside a dead-letter envelope. The envelope is a set of `x-rastreo-*` transport headers plus a payload that is one unmodified `DeviceRecord`. You filter and triage on the headers without parsing the payload.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/dlq-envelope-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `schemas/dlq-envelope-v1.json`

## Envelope

A dead-letter message has two parts. The `headers` part carries the failure context; the `payload` part carries the record itself.

- `headers` — a set of `x-rastreo-*` transport headers. These are Kafka record headers or NATS message headers, depending on the sink. Present only when the sink's `dead_letter` config sets `include_error_metadata: true` (the default).
- `payload` — one unmodified `DeviceRecord`, byte-identical to what would have reached the primary channel.

## Headers

Every dead-letter message carries four headers. The `x-rastreo-source-topic` and `x-rastreo-source-subject` headers are mutually exclusive: a Kafka DLQ message sets the topic header, a NATS DLQ message sets the subject header.

| Header | Type | Required | Description |
|---|---|---|---|
| `x-rastreo-source-topic` | string | no | Kafka only. The primary topic the record failed to reach. Set instead of `x-rastreo-source-subject`. |
| `x-rastreo-source-subject` | string | no | NATS only. The primary subject the record failed to reach. Set instead of `x-rastreo-source-topic`. |
| `x-rastreo-error-class` | string (enum) | yes | The class of the failure that quarantined the record, set at the point of failure. One of the six values below. |
| `x-rastreo-dlq-timestamp` | string (date-time) | yes | RFC 3339 timestamp of when the record reached the dead-letter destination. |

## Error classes

The `x-rastreo-error-class` header names the actual failure that quarantined the record. The value is one of six stable labels.

| Value | Meaning |
|---|---|
| `publish_failure` | The synchronous publish to the primary subject failed. Usually the broker is unreachable or the subject binding is wrong. NATS. |
| `ack_rejection` | JetStream accepted the publish for routing but refused durable storage. Usually a retention limit, a quota, or a wrong stream binding. NATS. |
| `produce_failure` | A Kafka produce to the primary topic failed. Kafka DLQ messages carry this class. |
| `write_failure` | A file or stdout write failed. |
| `flush_failure` | A buffered drain on flush failed. |
| `other` | Any failure that does not map to a class above. |

A dead-letter message today carries `produce_failure` (Kafka) or `publish_failure` / `ack_rejection` (NATS), because only the Kafka and NATS sinks have a dead-letter destination. The `write_failure`, `flush_failure`, and `other` classes appear on the `rastreo_server_sink_errors_total` metric instead. The enum is shared across both surfaces, so a consumer can match on the full set of labels.

## Payload

The payload is one unmodified `DeviceRecord` — the same JSON the primary channel would have carried, byte for byte. Validate it against the [DeviceRecord schema](device-record.md). The record still carries its `schema_id` and `scan_metadata`, so a consumer correlates a quarantined record back to its scan with the same `scan_metadata.scan_id` it uses on the primary channel.

## When headers are absent

Set `include_error_metadata: false` in the sink's `dead_letter` config to send the payload with no headers. The dead-letter message body is then byte-identical to what would have gone to the primary channel, and a consumer has no failure context to triage on. Leave it at the default (`true`) unless a downstream consumer rejects unknown headers.

## See also

- [Sinks · dead-letter queue](../../discover/sinks.md#dead-letter-queue) — how to configure a Kafka or NATS dead-letter destination.
- [Streaming API](streaming-api.md) — the AsyncAPI channels, including the dead-letter channel.
- [DeviceRecord field reference](device-record.md) — every field on the quarantined payload.
- [Observability · DLQ error-class attribution](../observability.md#dlq-error-class-attribution) — the `rastreo_server_dlq_records_total` metric partitioned by class.
