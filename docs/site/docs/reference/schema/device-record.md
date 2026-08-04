---
description: One discovered device: the identity it is keyed by, everything the probers learned about it, and the platform and role the classifier assigned. A device that answered on several addresses arrives as a single record, with the extra addresses under `alt_ips`.
---

# DeviceRecord

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

One discovered device: the identity it is keyed by, everything the probers learned about it, and the platform and role the classifier assigned. A device that answered on several addresses arrives as a single record, with the extra addresses under `alt_ips`.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/device-record-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/model/device.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `alt_ips` | array<[`AltIp`](#altip)> | no | Additional IPs merged into this device by the identity fuser — omitted when no identity fuser is configured or when the fuser saw nothing to merge. Each entry carries a role hint and the probe kinds that responded on that IP. |
| `confidence` | double | yes | Confidence score in `[0.0, 1.0]` computed as `baseline + signals_observed * per_signal`, clamped. Higher values indicate stronger evidence that the record reflects a real device. |
| `http_server` | string \| null | no | Web-server product name captured from the device's `HttpBanner` signal by a `platform_rules` entry — for `nginx/1.24.0` holds `"nginx"`; absent (null) when no `HttpBanner` rule with `http_server_capture` matched. |
| `http_version` | string \| null | no | Web-server version captured from the device's `HttpBanner` signal by a `platform_rules` entry — for `nginx/1.24.0` holds `"1.24.0"`; absent (null) when no `HttpBanner` rule with `http_version_capture` matched. |
| `identity_key` | string | yes | Canonical device identifier: `mac:XX:XX:XX:XX:XX:XX` when a MAC is discovered, else `ip:<address>`. Consumers use this as the primary identity key across scans. |
| `last_seen` | string (date-time) | yes | RFC 3339 UTC timestamp of the most recent probe that produced signals for this device. |
| `mac` | string \| null | no | First MAC address emitted across all probers against this device. Formatted as lower-case colon-separated hex. |
| `manufacturer` | string \| null | no | Vendor name resolved from the SNMP `sysObjectID` by the MIB enrichment fuser. `null` when no MIB table entry matched. |
| `mgmt_ip` | string (ip) \| null | no | Management IP the device was probed on. For multi-IP devices merged by the identity fuser, this is the first target IP that survived resolution. |
| `model` | string \| null | no | Hardware model resolved from the SNMP `sysObjectID` by the MIB enrichment fuser. `null` when no MIB table entry matched. |
| `os_version` | string \| null | no | Version string paired with `platform`, captured from the same signal that identified the platform (e.g. `15.7`, `1.24.0`). `null` when the classifier matched a platform but the pattern had no version capture group, or when no rule matched. |
| `platform` | string \| null | no | Fielded platform identifier (e.g. `cisco_ios`, `nokia_srlinux`, `linux`, `junos`) derived from SNMP `sysDescr`. SSH and HTTP banners name the software on a port rather than the device OS, so they claim a platform only under the opt-in banner heuristics. |
| `possible_alias_of` | string \| null | no | This record may be the same device as another (referenced by its `identity_key`), but the evidence wasn't strong enough to merge them (unlike the high-confidence `alt_ips` merge). |
| `probe_kinds` | array<[`ProbeKind`](#probekind)> | no | Deduplicated `ProbeKind` values whose outcomes contributed to this record. Preserves authoritative provenance from ingest through fusion so consumers do not infer prober attribution from signals. |
| `product_family` | string \| null | no | Product family resolved from the SNMP `sysObjectID` by the MIB enrichment fuser. `null` when no MIB table entry matched. |
| `role` | string \| null | no | Fielded device role (e.g. `router`, `switch`, `web_server`, `host`) assigned by the `rules` classifier from its `ports_open`, `sys_object_id_prefix`, and `signal_match` role rules. `null` when no rule matched, when the classifier is disabled, or when the record carries no signals a role rule can act on. |
| `scan_metadata` | [`ScanMetadata`](#scanmetadata) | no | Provenance stamped by the pipeline at scan entry. |
| `schema_id` | string | yes | URL of the JSON Schema this record conforms to — the same value as this schema's `$id`. |
| `schema_version` | string | yes | Schema version tag; `v1` for records emitted by this build. |
| `signals` | array<[`Signal`](#signal)> | yes | Deduplicated list of every observable fact collected from every prober that targeted this device. |
| `ssh_version` | string \| null | no | SSH software identifier captured from the device's `SshBanner` signal by a `platform_rules` entry — for `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` holds `"OpenSSH_8.9p1"`; absent (null) when no `SshBanner` rule with `ssh_version_capture` matched. |

## Definitions

### `AltIp` {#altip}

Additional IP merged into a `DeviceRecord` by the identity fuser, carrying the role hint and the probe kinds that responded on that IP.

| Field | Type | Required | Description |
|---|---|---|---|
| `address` | string (ip) | yes | Additional IP address merged into the device. |
| `responded_via` | array<[`ProbeKind`](#probekind)> | no | Probe kinds that responded on this IP before the identity fuser merged it into the primary record. |
| `role` | [`AltIpRole`](#altiprole) \| null | no | Role hint mapped to NetBox / Nautobot / Infrahub IP-address role models. Absent (null) when the identity fuser can't infer a role from available signals. |

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

### `ProbeKind` {#probekind}

One of:

- `TcpConnect`
- `Udp`
- `Http`
- `Dns`
- `Snmp`
- `Arp`
- `Ndp`
- `Ssh`
- `Icmp`
- `Tls`
- `ReverseDns`
- `Gnmi`
- `Lldp`

### `ScanMetadata` {#scanmetadata}

Per-scan provenance stamped on every emitted record. `scan_id` is a ULID, identical on every record in a scan, so consumers correlate a scan's records by it; across scans it orders only to the millisecond its timestamp encodes.

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the scan started. |
| `scan_id` | string | yes | ULID identifying this scan. |
| `scenario_name` | string \| null | no | Name of the scenario that produced this scan; absent (null) for an unnamed scenario. |
| `source_config_hash` | string \| null | no | `sha256:…` digest of the canonicalized scenario config that produced this scan. |

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
- { `TlsProtocolVersion`: string }
- { `TlsCipherSuite`: string }
- { `TlsAlpn`: string }
- { `ReverseDnsName`: string }
- { `GnmiVersion`: string }
- { `GnmiSupportedModel`: string }
- { `GnmiSupportedEncoding`: string }
- { `GnmiState`: object }

