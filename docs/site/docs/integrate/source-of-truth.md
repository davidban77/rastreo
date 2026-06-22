---
description: How downstream consumers reconcile rastreo records into a source of truth (NetBox, Nautobot, Infrahub) — the contract, the dedup key, and one sketch per system.
---

# Source of truth reconciliation

rastreo discovers devices and emits `DeviceRecord` events; reconciling those events into a source of truth (NetBox, Nautobot, Infrahub, or anything else) is the job of an independent consumer. rastreo does not ship consumer code, and the consumer is intentionally outside the core scope. The page below describes the contract a consumer is expected to honour and gives one short sketch per target system to anchor the pattern.

## The reconciliation pattern

A consumer reads `DeviceRecord` events from the Kafka topic (or an NDJSON file, or stdin), groups by `identity_key`, and upserts each unique key into the source of truth. The same `identity_key` may arrive any number of times across scans — the consumer must be idempotent.

The minimum upsert flow is:

1. Read a `DeviceRecord` from the stream.
2. Look up the existing entry in the source of truth by `identity_key`.
3. If it exists, replace populated fields and bump `last_seen`. If it does not, create it.
4. Acknowledge the Kafka offset (or advance the NDJSON cursor) only after the upsert succeeds.

`last_seen` is `{secs_since_epoch, nanos_since_epoch}` — the Unix timestamp at which the last probe touched the device. Consumers should keep the most recent value seen for a given `identity_key` and use it to drive staleness policies (for example, a device that has not been seen in 30 days could be flagged or retired).

## Confidence filtering

`confidence` is a float in the range 0.0 to 1.0 produced by the fuser. A consumer can drop records below a chosen threshold to filter out weak observations. A reasonable default is `< 0.3` for "drop"; tune higher when the source of truth is sensitive to noise, lower when you want every signal in.

A record from a single TCP-connect probe (one open port) lands at `confidence: 0.2` with the default `DirectFuser`. The score rises as more signals fuse into the same `identity_key`.

## NetBox

NetBox exposes a REST API at `/api/dcim/devices/`. Map `identity_key` to a NetBox custom field (for example `rastreo_identity_key`) and use it as the idempotency key. Look up the device by the custom field; if it exists, `PATCH` the changed fields; otherwise `POST` a new device.

```bash
curl -X PATCH https://netbox.example.com/api/dcim/devices/123/ \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_fields": {
      "rastreo_identity_key": "ip:10.50.0.10",
      "rastreo_confidence": 0.2,
      "rastreo_last_seen": "2026-06-22T22:30:00Z"
    }
  }'
```

## Nautobot

Nautobot's REST API mirrors NetBox at `/api/dcim/devices/`. The shape is the same; the difference is the host and the auth header convention. Reuse the same `identity_key`-to-custom-field mapping.

```bash
curl -X PATCH https://nautobot.example.com/api/dcim/devices/abc-123/ \
  -H "Authorization: Token $NAUTOBOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_fields": {
      "rastreo_identity_key": "ip:10.50.0.10",
      "rastreo_last_seen": "2026-06-22T22:30:00Z"
    }
  }'
```

## Infrahub

Infrahub is GraphQL-first. Upserts are expressed as mutations against the device kind your schema defines. Use the `identity_key` as the upsert key on a string attribute.

```graphql
mutation {
  DcimDeviceUpsert(
    data: {
      rastreo_identity_key: { value: "ip:10.50.0.10" }
      mgmt_ip:              { value: "10.50.0.10" }
      rastreo_confidence:   { value: 0.2 }
      rastreo_last_seen:    { value: "2026-06-22T22:30:00Z" }
    }
  ) {
    ok
    object { id }
  }
}
```

Adjust the kind name (`DcimDeviceUpsert`) to match your Infrahub schema.

## See also

- [Kafka](kafka.md) — the wire contract a consumer reads from.
- [Troubleshooting](troubleshooting.md) — what to check when records do not reach the source of truth.
