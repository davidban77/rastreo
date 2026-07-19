---
description: A deduplicated topology edge between two endpoints. Both directions of a physical link collapse into one record keyed by the unordered pair of LLDP chassis-ids.
---

# LinkRecord

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

A deduplicated topology edge between two endpoints. Both directions of a physical link collapse
into one record keyed by the unordered pair of LLDP chassis-ids.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/link-record-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/model/link.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `a` | [`LinkEndpoint`](#linkendpoint) | yes | — |
| `b` | [`LinkEndpoint`](#linkendpoint) | yes | — |
| `discovered_via` | string | yes | Discovery mechanism that produced the link (`lldp` today; leaves room for `cdp`/`gnmi`). |
| `observed_at` | string (date-time) | yes | — |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | yes | — |
| `schema_id` | string | yes | — |
| `schema_version` | string | yes | — |

## Definitions

### `LinkEndpoint` {#linkendpoint}

One end of a discovered link. `identity_key` correlates the endpoint to a probed device; it is
`None` for a neighbor rastreo learned via LLDP but never probed ("known-unknown").

| Field | Type | Required | Description |
|---|---|---|---|
| `chassis_id` | string | yes | — |
| `identity_key` | string \| null | no | — |
| `port` | string | yes | — |
| `sys_name` | string \| null | no | — |

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | — |
| `scan_id` | string | yes | — |
| `scenario_name` | string \| null | no | — |
| `source_config_hash` | string \| null | no | — |

