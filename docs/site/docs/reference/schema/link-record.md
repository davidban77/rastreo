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
| `a` | [`LinkEndpoint`](#linkendpoint) | yes | One end of the link; the `a`/`b` ordering is not significant. |
| `b` | [`LinkEndpoint`](#linkendpoint) | yes | The other end of the link. |
| `discovered_via` | string | yes | Discovery mechanism that produced the link (`lldp` today; leaves room for `cdp`/`gnmi`). |
| `observed_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the link was observed. |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | yes | Provenance stamped by the pipeline at scan entry. |
| `schema_id` | string | yes | Canonical schema URL; always `LINK_SCHEMA_ID` for records emitted by this build. |
| `schema_version` | string | yes | Schema version tag; always `LINK_CURRENT_SCHEMA_VERSION` for records emitted by this build. |

## Definitions

### `LinkEndpoint` {#linkendpoint}

One end of a discovered link. `identity_key` correlates the endpoint to a probed device; it is
absent (null) for a neighbor rastreo learned via LLDP but never probed ("known-unknown").

| Field | Type | Required | Description |
|---|---|---|---|
| `chassis_id` | string | yes | LLDP chassis ID of the endpoint. |
| `identity_key` | string \| null | no | Identity of the probed device at this endpoint; absent (null) for a neighbor learned via LLDP but never probed. |
| `port` | string | yes | LLDP port ID at this endpoint (e.g. `Gi0/1`), not a TCP port number. |
| `sys_name` | string \| null | no | LLDP system name of the endpoint, when advertised. |

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted record. `scan_id` is a ULID; consumers can sort and correlate records by it.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the scan started. |
| `scan_id` | string | yes | ULID identifying this scan. |
| `scenario_name` | string \| null | no | Name of the scenario that produced this scan; absent (null) for an unnamed scenario. |
| `source_config_hash` | string \| null | no | `sha256:…` digest of the canonicalized scenario config that produced this scan. |

