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
| `collection` | [`Collection`](#collection) | yes | Protocol-tagged descriptor of what to collect and how. |
| `confidence` | [`ProfileConfidence`](#profileconfidence) | yes | — |
| `endpoint` | [`ProfileEndpoint`](#profileendpoint) | yes | The endpoint that returned the capability data. |
| `identity_key` | string | yes | Identity of the device this profile belongs to; shared across the device's endpoints. |
| `note` | string \| null | no | Optional human-readable note about the profile; omitted when unset. |
| `observed_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the capability data was observed. |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | yes | Provenance stamped by the pipeline at scan entry. |
| `schema_id` | string | yes | URL of the JSON Schema this record conforms to — the same value as this schema's `$id`. |
| `schema_version` | string | yes | Schema version tag; `v1` for records emitted by this build. Versioned independently of the device record. |

## Definitions

### `Collection` {#collection}

Protocol-tagged collection descriptor. The `protocol` tag discriminates the variant, leaving room
for `snmp` and other protocols without reshaping the envelope.

One of:

- { `encoding`: string, `gnmi_version`: string \| null, `protocol`: `gnmi`, `suggested_subscriptions`: array<[`Subscription`](#subscription)>, `supported_models`: array<string> }

### `ProfileConfidence` {#profileconfidence}

How much the profile can be trusted. v1 is always `advertised_only`: the models and any suggested
subscriptions are derived from the endpoint's advertised capabilities, not verified against it.

One of:

- `advertised_only`
- `verified_on_device`

### `ProfileEndpoint` {#profileendpoint}

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | IP address the endpoint answered on. |
| `port` | uint16 | yes | — |
| `transport` | [`Transport`](#transport) | yes | — |

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted record. `scan_id` is a ULID, identical on every record in a scan, so consumers correlate a scan's records by it; across scans it orders only to the millisecond its timestamp encodes.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the scan started. |
| `scan_id` | string | yes | ULID identifying this scan. |
| `scenario_name` | string \| null | no | Name of the scenario that produced this scan; absent (null) for an unnamed scenario. |
| `source_config_hash` | string \| null | no | `sha256:…` digest of the canonicalized scenario config that produced this scan. |

### `Subscription` {#subscription}

A recommended gNMI subscription a collector can stream, matched from the device's advertised models.

| Field | Type | Required | Description |
|---|---|---|---|
| `matched_model` | string | yes | Advertised model this subscription was matched from. |
| `mode` | string | yes | Subscription mode (e.g. `sample`, `on_change`, `target_defined`). |
| `name` | string | yes | — |
| `origin` | string | yes | gNMI path origin (e.g. `openconfig`). |
| `path` | string | yes | gNMI path to subscribe to. |
| `sample_interval_ns` | uint64 \| null | no | Absent (null) for on-change or target-defined modes. |

### `Transport` {#transport}

Wire transport an endpoint answered over: `tls` for an encrypted channel, `plaintext` for `http`/2.

One of:

- `tls`
- `plaintext`

