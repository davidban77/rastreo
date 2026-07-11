---
description: Deserialization of `DeviceRecord` requires `schema_version` and `schema_id`. Legacy NDJSON produced by rastreo v0.5 or earlier will fail to deserialize; consumers should tag legacy records with an explicit v0 marker before ingest.
---

# DeviceRecord

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Deserialization of `DeviceRecord` requires `schema_version` and `schema_id`. Legacy NDJSON produced by rastreo v0.5 or earlier will fail to deserialize; consumers should tag legacy records with an explicit v0 marker before ingest.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/device-record-v1.json`
- JSON Schema draft: `http://json-schema.org/draft-07/schema#`
- Source of truth: `rastreo-core/src/model/device.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `alt_ips` | array<[`AltIp`](#altip)> | no | Additional IPs merged into this device by the identity fuser — omitted when no identity fuser is configured or when the fuser saw nothing to merge. Each entry carries a role hint and the probe kinds that responded on that IP. |
| `confidence` | double | yes | Confidence score in `[0.0, 1.0]` computed as `baseline + signals_observed * per_signal`, clamped. Higher values indicate stronger evidence that the record reflects a real device. |
| `http_server` | string \| null | no | Web-server product name captured by a `PlatformRule` from `HttpBanner` — for `nginx/1.24.0` populates `Some("nginx")`. `None` when no `HttpBanner` rule with `http_server_capture` matched. |
| `http_version` | string \| null | no | Web-server version captured by a `PlatformRule` from `HttpBanner` — for `nginx/1.24.0` populates `Some("1.24.0")`. `None` when no `HttpBanner` rule with `http_version_capture` matched. |
| `identity_key` | [`IdentityKey`](#identitykey) | yes | Canonical device identifier: `mac:XX:XX:XX:XX:XX:XX` when a MAC is discovered, else `ip:<address>`. Consumers use this as the primary identity key across scans. |
| `last_seen` | string (date-time) | yes | RFC 3339 UTC timestamp of the most recent probe that produced signals for this device. |
| `mac` | string \| null | no | First MAC address emitted across all probers against this device. Formatted as lower-case colon-separated hex. |
| `manufacturer` | string \| null | no | Vendor name resolved from the MAC OUI prefix by the OUI enrichment fuser. `null` when the OUI is not in the bundled Wireshark manuf database. |
| `mgmt_ip` | string (ip) \| null | no | Management IP the device was probed on. For multi-IP devices merged by the identity fuser, this is the first target IP that survived resolution. |
| `os_version` | string \| null | no | Version string paired with `platform`, captured from the same signal that identified the platform (e.g. `15.7`, `1.24.0`). `null` when the classifier matched a platform but the pattern had no version capture group, or when no rule matched. |
| `platform` | string \| null | no | Fielded platform identifier (e.g. `cisco_ios`, `linux`, `junos`) derived from SNMP `sysDescr` or SSH banner parsing. |
| `possible_alias_of` | [`IdentityKey`](#identitykey) \| null | no | When set, this record is a medium-confidence alias of another record identified by the given `IdentityKey`. |
| `probe_kinds` | array<[`ProbeKind`](#probekind)> | no | Deduplicated `ProbeKind` values whose outcomes contributed to this record. Preserves authoritative provenance from ingest through fusion so consumers do not infer prober attribution from signals. |
| `role` | string \| null | no | Fielded device role (e.g. `router`, `switch`, `web_server`, `host`) populated by `RulesClassifier` from `ports_open` and `sys_object_id_prefix` role rules. `null` when no rule matched, when the classifier is disabled, or when the record carries no signals a role rule can act on. |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | no | Provenance stamped by the pipeline at scan entry. |
| `schema_id` | string | yes | Canonical schema URL; always `CURRENT_SCHEMA_ID` for records emitted by this build. |
| `schema_version` | string | yes | Schema version tag; always `CURRENT_SCHEMA_VERSION` for records emitted by this build. |
| `signals` | array<[`Signal`](#signal)> | yes | Deduplicated list of every observable fact collected from every prober that targeted this device. |
| `ssh_version` | string \| null | no | SSH software identifier captured by a `PlatformRule` from `SshBanner` — for `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` populates `Some("OpenSSH_8.9p1")`. `None` when no `SshBanner` rule with `ssh_version_capture` matched. |

## Definitions

### `AltIp` {#altip}

Additional IP merged into a `DeviceRecord` by the identity fuser, carrying the role hint and the probe kinds that responded on that IP.

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string (ip) | yes | — |
| `responded_via` | array<[`ProbeKind`](#probekind)> | no | Probe kinds that responded on this IP before the identity fuser merged it into the primary record. |
| `role` | [`AltIpRole`](#altiprole) \| null | no | Role hint mapped to NetBox / Nautobot / Infrahub IP-address role models. `None` when the identity fuser can't infer a role from available signals. |

### `AltIpRole` {#altiprole}

Role hint attached to each `AltIp`. Values map 1:1 to NetBox / Nautobot / Infrahub IP-address role models so downstream reconcilers pull the role directly instead of re-inferring it.

One of:

- `secondary`
- `loopback`
- `vrrp`
- `hsrp`
- `carp`
- `anycast`
- `vip`

### `IdentityKey` {#identitykey}

Type: string

### `ProbeKind` {#probekind}

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
- { `SshBanner`: string }
- { `SshHostKey`: string }
- { `IcmpEchoRttMicros`: uint64 }
- { `TlsSubject`: string }
- { `TlsSanName`: string }
- { `ReverseDnsName`: string }

