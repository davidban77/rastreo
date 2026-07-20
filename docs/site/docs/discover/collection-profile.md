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
    - `suggested_subscriptions` — curated OpenConfig telemetry paths, matched from the advertised models (see [Suggested subscriptions](#suggested-subscriptions)). Each entry carries:
        - `name` — a short label for the path, such as `if_counters`.
        - `origin` — the model origin. Always `openconfig` for a curated path.
        - `path` — the gNMI path a collector streams.
        - `mode` — `sample` for a value read on a fixed timer, `on_change` for a value the device pushes only when it changes.
        - `sample_interval_ns` — the sample period in nanoseconds. Present only in `sample` mode.
        - `matched_model` — the advertised model that produced the path, including its version.
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
    "suggested_subscriptions": [
      {
        "name": "if_counters",
        "origin": "openconfig",
        "path": "/interfaces/interface/state/counters",
        "mode": "sample",
        "sample_interval_ns": 10000000000,
        "matched_model": "openconfig-interfaces 3.0.0 (OpenConfig)"
      },
      {
        "name": "if_oper_status",
        "origin": "openconfig",
        "path": "/interfaces/interface/state/oper-status",
        "mode": "on_change",
        "matched_model": "openconfig-interfaces 3.0.0 (OpenConfig)"
      },
      {
        "name": "if_admin_status",
        "origin": "openconfig",
        "path": "/interfaces/interface/state/admin-status",
        "mode": "on_change",
        "matched_model": "openconfig-interfaces 3.0.0 (OpenConfig)"
      },
      {
        "name": "system_cpu_utilization",
        "origin": "openconfig",
        "path": "/system/cpus/cpu/state/total/instant",
        "mode": "sample",
        "sample_interval_ns": 10000000000,
        "matched_model": "openconfig-system 2.0.0 (OpenConfig)"
      },
      {
        "name": "system_memory",
        "origin": "openconfig",
        "path": "/system/memory/state",
        "mode": "sample",
        "sample_interval_ns": 30000000000,
        "matched_model": "openconfig-system 2.0.0 (OpenConfig)"
      }
    ]
  },
  "observed_at": "2026-07-05T13:47:22Z",
  "scan_metadata": {
    "scan_id": "01KXC3Z94835AJY8WWSYQ81Y1P",
    "initiated_at": "2026-07-05T13:47:22.676000Z",
    "source_config_hash": "sha256:63b96614fd6aa54b03a6f04d56b311d00c795f32881a27d0d4168411ec6a2f30"
  }
}
```

The device also advertised `srl_nokia-system`, a vendor-native model. It stays in `supported_models`, but it produced no curated path, so it adds nothing to `suggested_subscriptions`. Only universal OpenConfig models get suggestions — see [Suggested subscriptions](#suggested-subscriptions).

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

`suggested_subscriptions` lists ready-to-use telemetry paths a collector can stream. rastreo matches the endpoint's advertised models against a curated table of universal OpenConfig `/state` paths and copies each match onto the profile. A collector takes the paths straight from the record — no path list to write by hand.

Only universal OpenConfig models get suggestions. A vendor-native model such as `srl_nokia-system`, `Cisco-IOS-XR-*`, or `arista-*` still appears in `supported_models`, but its paths are device-specific, so it produces no suggestion. To stream a native path, add it to the collector's config yourself.

Each subscription names a `mode`:

- `sample` — the collector reads the value on a fixed timer. `sample_interval_ns` gives the period in nanoseconds. rastreo uses this for counters and gauges, such as interface counters or CPU load.
- `on_change` — the device pushes the value only when it changes, and `sample_interval_ns` is absent. rastreo uses this for status values, such as interface oper-status or BGP session state.

`matched_model` carries the exact advertised model and version that produced the path, copied verbatim. Say a device advertises `openconfig-interfaces 2.5.0` while your standard is `3.0.0`. The profile records `2.5.0`, so a consumer sees the version skew and can react.

!!! note "Suggestions are advisory, not verified on-device"
    The profile's `confidence` is `advertised_only`, so the suggested paths follow from the models the endpoint claims to support. rastreo does not stream them to confirm the device answers. Treat the list as a strong starting point a collector can refine. Some paths subscribe to whole `/state` containers (interface counters, platform components), which stream broadly on a high-port-count or large-chassis device — a collector may narrow them to the specific leaves it needs. And a model-derived path such as BGP neighbor state is suggested whenever the model is advertised, even on a device not running that protocol, where the subtree is simply empty.

### The curated paths

rastreo suggests paths from these OpenConfig models. A device that advertises none of them gets an empty `suggested_subscriptions` list.

| Advertised model | Name | Path | Mode | Interval |
|---|---|---|---|---|
| `openconfig-interfaces` | `if_counters` | `/interfaces/interface/state/counters` | `sample` | 10s |
| `openconfig-interfaces` | `if_oper_status` | `/interfaces/interface/state/oper-status` | `on_change` | — |
| `openconfig-interfaces` | `if_admin_status` | `/interfaces/interface/state/admin-status` | `on_change` | — |
| `openconfig-system` | `system_cpu_utilization` | `/system/cpus/cpu/state/total/instant` | `sample` | 10s |
| `openconfig-system` | `system_memory` | `/system/memory/state` | `sample` | 30s |
| `openconfig-platform` | `component_state` | `/components/component/state` | `sample` | 30s |
| `openconfig-network-instance` | `bgp_neighbor_session_state` | `/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state/session-state` | `on_change` | — |
| `openconfig-network-instance` | `bgp_neighbor_established_transitions` | `/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state/established-transitions` | `sample` | 30s |

The `Interval` column is shown as a duration for readability. The record stores it as `sample_interval_ns` in nanoseconds, matching the gNMI protobuf — `10s` is `10000000000`.

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
- what is available — the YANG trees in `supported_models`;
- what to stream — the paths in `suggested_subscriptions`.

Telegraf's gnmi input plugin and gNMIc are two collectors that consume gNMI this way. The `suggested_subscriptions` list gives a collector its subscription paths directly — see [Turn a profile into a Telegraf subscription](#turn-a-profile-into-a-telegraf-subscription) for a worked mapping.

## Turn a profile into a Telegraf subscription

Telegraf's gNMI input plugin streams telemetry over gNMI. Its config splits into one connection block, `[[inputs.gnmi]]`, and one `[[inputs.gnmi.subscription]]` block per path. A profile fills in almost all of it.

rastreo supplies the parts it discovered: the endpoint address and port (Telegraf's `addresses`), the `encoding`, and the suggested subscription paths. Your collector or automation supplies the parts rastreo never sees — the `username` and `password`, and the TLS policy (the CA to trust, or whether to skip verification). rastreo redacts credentials, so a profile never carries them.

Take the profile from [What a collection profile is](#what-a-collection-profile-is): an SR Linux node at `198.51.100.11:57400` advertising `openconfig-interfaces` and `openconfig-system`. A lab automation reads it and generates the config below. Each subscription block maps from one entry in `suggested_subscriptions`:

- `name`, `origin`, and `path` copy across unchanged.
- `mode` becomes Telegraf's `subscription_mode`.
- `sample_interval_ns` becomes `sample_interval`, converted from nanoseconds to a Telegraf duration string — `10000000000` nanoseconds is `"10s"`. The record stores nanoseconds to match the gNMI protobuf; Telegraf wants a duration string.

```toml title="telegraf.conf"
[[inputs.gnmi]]
  addresses = ["198.51.100.11:57400"]
  # Your automation supplies the credentials; rastreo redacts them.
  username = "admin"
  password = "${GNMI_PASSWORD}"
  encoding = "json_ietf"

  # transport was "tls", so enable TLS and set your own trust policy.
  enable_tls = true
  # tls_ca = "/etc/telegraf/ca.pem"
  insecure_skip_verify = true

  [[inputs.gnmi.subscription]]
    name = "if_counters"
    origin = "openconfig"
    path = "/interfaces/interface/state/counters"
    subscription_mode = "sample"
    sample_interval = "10s"

  [[inputs.gnmi.subscription]]
    name = "if_oper_status"
    origin = "openconfig"
    path = "/interfaces/interface/state/oper-status"
    subscription_mode = "on_change"

  [[inputs.gnmi.subscription]]
    name = "if_admin_status"
    origin = "openconfig"
    path = "/interfaces/interface/state/admin-status"
    subscription_mode = "on_change"

  [[inputs.gnmi.subscription]]
    name = "system_cpu_utilization"
    origin = "openconfig"
    path = "/system/cpus/cpu/state/total/instant"
    subscription_mode = "sample"
    sample_interval = "10s"

  [[inputs.gnmi.subscription]]
    name = "system_memory"
    origin = "openconfig"
    path = "/system/memory/state"
    subscription_mode = "sample"
    sample_interval = "30s"
```

The device's native `srl_nokia-system` model produced no suggested path, so it has no subscription block. Add native paths to the config by hand if you need them.

## See also

- [gNMI prober](../probe/gnmi.md) — how rastreo reads a device's gNMI capabilities.
- [CollectionProfileRecord schema](../reference/schema/collection-profile-record.md) — every field on the emitted record.
- [Topology](topology.md) — the sibling second stream of `LinkRecord` topology edges.
- [Identity](identity.md) — the correlation that sets `identity_key` on each record.
- [Streaming API](../reference/schema/streaming-api.md) — the Kafka topic and NATS subject conventions for every stream.
