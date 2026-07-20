---
description: How rastreo turns a gNMI Capabilities answer into a CollectionProfileRecord — a compact "how to collect telemetry from me" descriptor a downstream collector reads to auto-configure streaming telemetry. Covers the record fields, when a profile is emitted, the advertised_only confidence, the one-profile-per-endpoint relationship, and the second stream it travels on.
---

# Collection profiles

rastreo discovers devices, and for gNMI endpoints it also describes how to collect telemetry from them. When the [gNMI prober](../probe/gnmi.md) answers a Capabilities call, rastreo emits a `CollectionProfileRecord` — a compact "how to collect telemetry from me" descriptor. A downstream telemetry collector reads it and configures a streaming subscription without writing the config by hand. Telegraf's gnmi input plugin and gNMIc are two collectors that consume gNMI this way. This page explains what a collection profile is, when rastreo emits one, and where it goes.

## What a collection profile is

A collection profile records how to collect telemetry from one gNMI endpoint. rastreo emits one record per endpoint that answered a Capabilities call with capability data.

Each record carries these fields:

- `identity_key` — points at the matching `DeviceRecord`, so you can join a profile to its device. See [One profile per gNMI endpoint](#one-profile-per-gnmi-endpoint).
- `endpoint` — the gNMI endpoint that answered. It has an `address` (the IP), a `port`, and a `transport` (`tls` for an encrypted channel, `plaintext` for cleartext gRPC).
- `confidence` — how much to trust the profile. Always `advertised_only` today. See [Confidence](#confidence).
- `collection` — the protocol-tagged descriptor of how to collect. Its `protocol` field is `gnmi` today, and it carries:
    - `gnmi_version` — the gNMI protocol version the endpoint reported, such as `0.10.0`.
    - `encoding` — the encoding a collector should request. rastreo picks it from what the endpoint advertised, preferring `JSON_IETF`.
    - `supported_models` — the YANG models the endpoint advertised, each rendered as `name version (organization)`.
    - `suggested_subscriptions` — recommended subscription paths. Empty today. See [Suggested subscriptions](#suggested-subscriptions).
- `observed_at` — when rastreo last saw the endpoint.
- `scan_metadata` — the same per-scan provenance object stamped on every `DeviceRecord`.
- `note` — optional free text. Absent today.
- `schema_version` and `schema_id` identify the record shape.

Here is one collection profile from an SR Linux node that answered Capabilities over TLS:

```json
{
  "schema_version": "v1",
  "schema_id": "https://davidban77.github.io/rastreo/schemas/collection-profile-record-v1.json",
  "identity_key": "ip:198.51.100.11",
  "endpoint": {
    "address": "198.51.100.11",
    "port": 57400,
    "transport": "tls"
  },
  "confidence": "advertised_only",
  "collection": {
    "protocol": "gnmi",
    "gnmi_version": "0.10.0",
    "encoding": "JSON_IETF",
    "supported_models": [
      "openconfig-interfaces 3.0.0 (OpenConfig)",
      "openconfig-system 2.0.0 (OpenConfig)",
      "srl_nokia-system"
    ],
    "suggested_subscriptions": []
  },
  "observed_at": "2026-07-05T13:47:22Z",
  "scan_metadata": {
    "scan_id": "01KXC3Z94835AJY8WWSYQ81Y1P",
    "initiated_at": "2026-07-05T13:47:22.676000Z",
    "source_config_hash": "sha256:63b96614fd6aa54b03a6f04d56b311d00c795f32881a27d0d4168411ec6a2f30"
  }
}
```

## When rastreo emits a profile

rastreo emits a profile only for a gNMI endpoint that returned capability data. That means the endpoint answered the Capabilities call with a gNMI version, at least one supported model, or at least one advertised encoding. An endpoint that accepted the connection but returned no capabilities gets no profile — reachability alone is not a collection profile.

A device that rejects your credentials answers with a gRPC status and no capabilities. That is a fingerprint fault on its `DeviceRecord`, not a collection profile. Provide valid `username` and `password` to the [gNMI prober](../probe/gnmi.md) to get the endpoint's capabilities, and with them a profile.

!!! note "A profile advertises capability, not device state"
    rastreo builds a profile from the endpoint's advertised capabilities alone. It never copies a state value read with `get_paths` into a profile, so a hostname or any other value from a Get call cannot leak onto the profiles stream.

## Confidence

The `confidence` field is always `advertised_only` today. That value means the encoding and models come from what the endpoint advertised in its Capabilities answer, not from a check against the device. Treat them as the endpoint's own claims about what it can stream.

The schema also defines a `verified_on_device` value. rastreo does not emit it yet. A later release will use it for a profile whose models rastreo confirmed against the device.

## One profile per gNMI endpoint

One device can expose more than one gNMI endpoint. rastreo emits one profile per endpoint, so a profile has an N:1 relationship with its device. Every profile from the same device carries the same `identity_key`, and each profile's `supported_models` describes only the endpoint it came from — not a merged union across the device's endpoints.

Correlate a profile to its device by `identity_key` alone, exactly as you join the [device](identity.md) and [topology](topology.md) streams. rastreo sets `identity_key` to the value on the device's `DeviceRecord`, so a consumer needs no identity logic of its own. When rastreo could not match an endpoint back to a probed device, it emits no profile for that endpoint.

## Suggested subscriptions

The `suggested_subscriptions` field is part of the record, but rastreo does not populate it yet. The array is empty on every profile today. Until then, a collector builds its subscription paths from `supported_models` or from its own configuration.

A later release will curate a list of recommended subscription paths from the advertised models. When a later release adds them, `suggested_subscriptions` carries ready-to-use paths a collector can take straight from the profile.

## Where profiles are emitted

Collection profiles travel on their own stream, separate from the device and topology streams. How the streams are split depends on the sink.

=== "Kafka"

    Device records go to `topic`. Collection profiles go to `profiles_topic`, which defaults to `rastreo.discovery.profiles.v1`. Set `profiles_topic` to route profiles to a topic of your choice.

    ```yaml
    sink:
      type: kafka
      brokers: ["kafka-0.internal:9092"]
      topic: rastreo.discovery.records.v1
      profiles_topic: rastreo.discovery.profiles.v1
    ```

=== "NATS"

    Device records go to `subject`. Collection profiles go to `profiles_subject`, which defaults to `rastreo.discovery.profiles.v1`. Set `profiles_subject` to route profiles to a subject of your choice.

    ```yaml
    sink:
      type: nats
      servers: ["nats://nats:4222"]
      subject: rastreo.discovery.records.v1
      profiles_subject: rastreo.discovery.profiles.v1
      stream: rastreo
    ```

    !!! warning "Bind the JetStream stream to the profiles subject"
        The stream must capture the device subject, the links subject, and the profiles subject. A stream bound only to the device subject refuses profile publishes at ack time once gNMI capability data appears. Bind it to a filter that covers all three, for example the wildcard `rastreo.discovery.>`. See [NATS · Stream setup](../integrate/nats.md#stream-setup).

=== "stdout / file"

    All record kinds share one NDJSON stream. Tell a collection profile apart by `schema_id`: it carries the `collection-profile-record-v1.json` URL.

    ```bash
    rastreo discover --file scenario.yaml \
      | jq 'select(.schema_id | contains("collection-profile-record"))'
    ```

The scan summary reports how many profiles the scan produced in `profiles_emitted`, alongside the device-record and link-record counts.

## How a collection profile is consumed

A collection profile gives a telemetry collector everything it needs to start a streaming subscription without writing the config by hand. From one record a collector reads:

- where to connect — `endpoint.address` on `endpoint.port`, over `endpoint.transport`;
- how to speak — the `encoding` to request;
- what is available — the YANG trees in `supported_models`.

Telegraf's gnmi input plugin and gNMIc are two collectors that consume gNMI this way. Today you supply the subscription paths yourself. When `suggested_subscriptions` is populated in a later release, a collector can take the paths straight from the profile.

## See also

- [gNMI prober](../probe/gnmi.md) — how rastreo reads a device's gNMI capabilities.
- [CollectionProfileRecord schema](../reference/schema/collection-profile-record.md) — every field on the emitted record.
- [Topology](topology.md) — the sibling second stream of `LinkRecord` topology edges.
- [Identity](identity.md) — the correlation that sets `identity_key` on each record.
- [Streaming API](../reference/schema/streaming-api.md) — the Kafka topic and NATS subject conventions for every stream.
