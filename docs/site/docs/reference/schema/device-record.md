---
description: Deserialization of `DeviceRecord` requires `schema_version` and `schema_id`. Legacy NDJSON produced by rastreo v0.5 or earlier will fail to deserialize; consumers should tag legacy records with an explicit v0 marker before ingest.
---

# DeviceRecord

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Deserialization of `DeviceRecord` requires `schema_version` and `schema_id`. Legacy NDJSON produced by rastreo v0.5 or earlier will fail to deserialize; consumers should tag legacy records with an explicit v0 marker before ingest.

- Schema ID: `n/a`
- JSON Schema draft: `http://json-schema.org/draft-07/schema#`
- Source of truth: `rastreo-core/src/model/device.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `alt_ips` | array<string (ip)> | no | Additional IPs the fuser correlated to the same identity — empty until a correlator fuser populates it. |
| `confidence` | double | yes | Confidence score in `[0.0, 1.0]` computed as `baseline + signals_observed * per_signal`, clamped. Higher values indicate stronger evidence that the record reflects a real device. |
| `identity_key` | [`IdentityKey`](#identitykey) | yes | Canonical device identifier: `mac:XX:XX:XX:XX:XX:XX` when a MAC is discovered, else `ip:<address>`. Consumers use this as the primary correlation key across scans. |
| `last_seen` | string (date-time) | yes | RFC 3339 UTC timestamp of the most recent probe that produced signals for this device. |
| `mac` | string \| null | no | First MAC address emitted across all probers against this device. Formatted as lower-case colon-separated hex. |
| `manufacturer` | string \| null | no | Vendor name resolved from the MAC OUI prefix by the OUI enrichment fuser. `null` when the OUI is not in the bundled Wireshark manuf database. |
| `mgmt_ip` | string (ip) \| null | no | Management IP the device was probed on. For multi-IP devices merged by the correlation fuser, this is the first target IP that survived resolution. |
| `platform` | string \| null | no | Fielded platform identifier (e.g. `cisco_ios`, `linux`, `junos`) derived from SNMP `sysDescr` or SSH banner parsing. Currently always `null`; populated once platform classification lands. |
| `possible_alias_of` | [`IdentityKey`](#identitykey) \| null | no | When set, this record is a medium-confidence alias of another record identified by the given `IdentityKey`. |
| `role` | string \| null | no | Fielded device role (e.g. `router`, `switch`, `host`) derived from `sysObjectID` prefix or port-based heuristics. Currently always `null`; populated once role classification lands. |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | no | Provenance stamped by the pipeline at scan entry. |
| `schema_id` | string | yes | Canonical schema URL; always `CURRENT_SCHEMA_ID` for records emitted by this build. |
| `schema_version` | string | yes | Schema version tag; always `CURRENT_SCHEMA_VERSION` for records emitted by this build. |
| `signals` | array<[`Signal`](#signal)> | yes | Deduplicated list of every observable fact collected from every prober that targeted this device. |

## Definitions

### `IdentityKey` {#identitykey}

Type: string

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | — |
| `scan_id` | string | yes | — |
| `scenario_name` | string \| null | no | — |
| `source_config_hash` | string \| null | no | — |

### `Signal` {#signal}

One of:

- { `OpenPort`: uint16 }
- { `HttpBanner`: string }
- { `SnmpSysObjectId`: string }
- { `SnmpSysDescr`: string }
- { `Mac`: string }
- { `DnsHost`: string }
- { `NtpBanner`: string }
- { `SipUserAgent`: string }
- { `MemcachedVersion`: string }
- { `StunMappedAddress`: string }
- { `SnmpSysName`: string }

