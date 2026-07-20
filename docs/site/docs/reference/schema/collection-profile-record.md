---
description: How to collect telemetry from a discovered endpoint: the endpoint that answered, the confidence in the profile, and a protocol-tagged `collection` descriptor. One record per gNMI endpoint, so a device with two management endpoints yields two profiles sharing an `identity_key`.
---

# CollectionProfileRecord

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

How to collect telemetry from a discovered endpoint: the endpoint that answered, the confidence
in the profile, and a protocol-tagged `collection` descriptor. One record per gNMI endpoint, so a
device with two management endpoints yields two profiles sharing an `identity_key`.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/collection-profile-record-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/model/collection_profile.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `collection` | [`Collection`](#collection) | yes | — |
| `confidence` | [`ProfileConfidence`](#profileconfidence) | yes | — |
| `endpoint` | [`ProfileEndpoint`](#profileendpoint) | yes | — |
| `identity_key` | string | yes | — |
| `note` | string \| null | no | — |
| `observed_at` | string (date-time) | yes | — |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | yes | — |
| `schema_id` | string | yes | — |
| `schema_version` | string | yes | — |

## Definitions

### `Collection` {#collection}

Protocol-tagged collection descriptor. The `protocol` tag discriminates the variant, leaving room
for `snmp` and other protocols without reshaping the envelope.

One of:

- { `encoding`: string, `gnmi_version`: string \| null, `protocol`: `gnmi`, `suggested_subscriptions`: array<[`Subscription`](#subscription)>, `supported_models`: array<string> }

### `ProfileConfidence` {#profileconfidence}

How much the profile can be trusted. v1 is always `advertised_only`: the models and any suggested
subscriptions are derived from the endpoint's advertised capabilities, not verified against it.

Type: string

### `ProfileEndpoint` {#profileendpoint}

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | — |
| `port` | uint16 | yes | — |
| `transport` | [`Transport`](#transport) | yes | — |

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | — |
| `scan_id` | string | yes | — |
| `scenario_name` | string \| null | no | — |
| `source_config_hash` | string \| null | no | — |

### `Subscription` {#subscription}

A recommended gNMI subscription. Empty in v1; a later revision curates the list from advertised models.

| Field | Type | Required | Description |
|---|---|---|---|
| `matched_model` | string | yes | — |
| `mode` | string | yes | — |
| `name` | string | yes | — |
| `origin` | string | yes | — |
| `path` | string | yes | — |
| `sample_interval_ns` | uint64 \| null | no | `None` for on-change or target-defined modes. |

### `Transport` {#transport}

Wire transport an endpoint answered over: `tls` for an encrypted channel, `plaintext` for `http`/2.

Type: string

