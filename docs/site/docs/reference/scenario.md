---
description: The DiscoverScenarioConfig JSON shape used by POST /scans and by library callers — every field, every variant, with defaults and validation rules.
---

# Scenario schema

A scenario describes one discovery run: which targets to probe, which probers to use, how to encode the results, and where to send them. The `rastreo-server` HTTP API accepts a scenario as the JSON body of `POST /scans`; library callers construct the same shape in code. The `rastreo` CLI loads a `ScenarioFile` (one or more scenarios plus a top-level `version` / `kind` / `defaults` header) from disk via `rastreo discover --file <path>`.

This page documents the JSON form. Field names match the wire shape exactly (the underlying Rust type is `rastreo_core::config::DiscoverScenarioConfig`).

!!! tip "Loading from the CLI"
    `rastreo discover --file scan.yml` loads a YAML `ScenarioFile` and runs each `scenarios[]` entry sequentially. The file must set `version: 1` and `kind: discovery`. See the [CLI reference](../discover/cli.md#yaml-driven-mode) for the full mode surface, including CLI flag overrides on YAML values.

## Top-level fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string \| null | `null` | Optional human-readable label for the scenario. Not interpreted by the runtime. |
| `rate_limit` | integer \| null | `null` | Maximum number of in-flight probes. Maps to scheduler concurrency at runtime. |
| `timeout_ms` | integer \| null | `null` | Per-probe timeout in milliseconds. |
| `encoder` | object \| null | `null` (NDJSON) | Output encoding. See [Encoders](#encoders). |
| `fuser` | object \| null | `null` (Direct, baseline 0.1 / per-signal 0.1) | Signal-fusion strategy. See [Fusers](#fusers). |
| `sink` | object \| null | `null` | Output destination. See [Sinks](#sinks). On `POST /scans` the server strips this and writes records to an internal buffer that is returned in the response body. |
| `targets` | array | — (required) | List of targets to probe. Must not be empty for `POST /scans`. See [Targets](#targets). |
| `probers` | array | `[]` | List of probers to run against each target. Must not be empty for `POST /scans`. See [Probers](#probers). |

## Targets

The `targets` array contains externally-tagged enum values — each entry has a single key naming the variant and a value describing it. Four variants exist.

A single IP address:

```json
{"Ip": "10.0.0.1"}
```

A CIDR block (IPv4 or IPv6):

```json
{"Cidr": "10.0.0.0/24"}
```

An inclusive IP range:

```json
{"Range": {"start": "10.0.0.1", "end": "10.0.0.5"}}
```

A DNS name. The system resolver is used unless the library caller installs a custom resolver. The server uses the host's system resolver, captured once at startup.

```json
{"DnsName": "router-1.lab.local"}
```

## Probers

The `probers` array contains internally-tagged objects (each carries a `type` field). Nine probers are available today: `tcp_connect`, `http`, `dns`, `udp`, `snmp`, `arp`, `ndp`, `ssh`, and `icmp`. The `http`, `snmp`, `arp`, `ndp`, `ssh`, and `icmp` variants are gated behind their matching Cargo features on `rastreo-core` (all bundled with the published binaries and Docker image); `tcp_connect`, `dns`, and `udp` are always available.

### `tcp_connect`

Establishes a TCP connection to each listed port on each resolved target IP; an open port produces an `OpenPort(<port>)` signal.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"tcp_connect"`. |
| `ports` | array of u16 | yes | List of ports to probe. |

```json
{"type": "tcp_connect", "ports": [22, 80, 443]}
```

### `http`

Issues a `GET` request against each configured port and emits the response `Server:` header as an `HttpBanner(<value>)` signal. See the [HTTP prober page](../probe/http.md) for TLS behaviour and scheme resolution rules.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"http"`. |
| `ports` | array of u16 | yes | — | List of ports to probe. |
| `scheme` | string | no | `auto` | One of `auto`, `http`, `https`. Under `auto`, ports 443 and 8443 use HTTPS; all others use HTTP. |
| `path` | string | no | `/` | Request path. Must start with `/`. |
| `tls_verify` | bool | no | `false` | When `false`, accepts self-signed and expired certificates. |
| `user_agent` | string | no | `rastreo/<version>` | Sent as the `User-Agent` header on every probe. |

```json
{"type": "http", "ports": [80, 443], "scheme": "auto", "tls_verify": false}
```

### `dns`

Treats each resolved target as a DNS server, sends a query for each configured `query_name` over the chosen transport, and emits each answer record as a `DnsHost(<value>)` signal. See the [DNS prober page](../probe/dns.md) for the full signal-format table and reachability semantics.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"dns"`. |
| `ports` | array of u16 | no | `[53]` | Ports to probe. |
| `query_names` | array of string | yes | — | DNS names to query. Each name is validated: non-empty labels, each label at most 63 bytes, total length at most 253 bytes. |
| `query_type` | string | no | `a` | One of `a`, `aaaa`, `mx`, `txt`, `ptr`, `ns`, `cname`. |
| `transport` | string | no | `udp` | One of `udp`, `tcp`. |
| `recursion_desired` | bool | no | `true` | Sets the RD bit on the outgoing query. |

```json
{"type": "dns", "ports": [53], "query_names": ["example.com"], "query_type": "a"}
```

### `udp`

Speaks one of four UDP protocols against each configured port and emits a typed signal per protocol. See the [UDP prober page](../probe/udp.md) for the per-protocol request shape, response parsing, and signal formats.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"udp"`. |
| `ports` | array of u16 | yes | List of ports to probe. |
| `protocol` | string | yes | One of `ntp`, `sip_options`, `memcached_stats`, `stun_binding`. |

```json
{"type": "udp", "ports": [123], "protocol": "ntp"}
```

### `snmp`

Issues an SNMPv1, SNMPv2c, or SNMPv3 `GetRequest` against each configured port for three MIB-II system-group OIDs (`sysDescr`, `sysObjectID`, `sysName`) and emits each returned varbind as a typed signal. See the [SNMP prober page](../probe/snmp.md) for version behaviour, USM credential shape, OID mapping, and the security caveat around cleartext community strings.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"snmp"`. |
| `ports` | array of u16 | no | `[161]` | Ports to probe. |
| `version` | string | no | `v2c` | One of `v1`, `v2c`, `v3`. |
| `community` | string | no | `public` | SNMP community string. Transmitted in cleartext on v1 and v2c. Ignored on v3. |
| `credentials` | object | no | `{}` | USM credentials. Required on `v3` (username must be non-empty). Ignored on v1 and v2c. See [SNMPv3 credentials](../probe/snmp.md#snmpv3-credentials). |

```json
{"type": "snmp", "ports": [161], "version": "v2c", "community": "public"}
```

An SNMPv3 example with `authPriv`, SHA-256, and AES-128:

```yaml
type: snmp
version: v3
credentials:
  username: probe
  auth:
    algorithm: sha256
    password: authpassword
  privacy:
    algorithm: aes128
    password: privpassword
```

### `arp`

Sends an ARP Request (RFC 826) as a broadcast Ethernet frame on the local IPv4 subnet and emits the target's MAC address as a `Mac(<address>)` signal. Requires `CAP_NET_RAW` at runtime — the raw socket is refused otherwise. Only works for targets on a locally-reachable L2 segment. See the [ARP prober page](../probe/arp.md) for interface auto-selection rules, degenerate-case handling, and per-runtime capability instructions.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"arp"`. |
| `interface` | string | no | `""` (auto-select) | Name of the sending interface, e.g. `eth0`. Empty string means auto-select based on the target IP's subnet. |

```json
{"type": "arp"}
```

```yaml
type: arp
interface: eth1
```

### `ndp`

Sends an ICMPv6 Neighbor Solicitation (RFC 4861 §4.3) on the local IPv6 subnet, expects a Neighbor Advertisement in return, and emits the target's MAC address as a `Mac(<address>)` signal. Requires `CAP_NET_RAW` at runtime. Only works for targets on a locally-reachable IPv6 L2 segment. See the [NDP prober page](../probe/ndp.md) for solicited-node multicast address computation, checksum semantics, and per-runtime capability instructions.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"ndp"`. |
| `interface` | string | no | `""` (auto-select) | Name of the sending interface. Empty string means auto-select based on the target's subnet and scope. |

```json
{"type": "ndp"}
```

```yaml
type: ndp
interface: eth0
```

### `ssh`

Opens a TCP connection to each configured port, captures the pre-negotiation SSH banner (`SSH-2.0-…`), then completes the SSH key exchange to record the server's host public key in OpenSSH single-line format. Emits `SshBanner(<value>)` and `SshHostKey(<value>)` signals. No authentication is attempted. See the [SSH prober page](../probe/ssh.md) for banner shape, host-key format, and identity-fuser interaction.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"ssh"`. |
| `ports` | array of u16 | no | `[22]` | Ports to probe. |

```json
{"type": "ssh", "ports": [22]}
```

### `icmp`

Sends ICMP Echo Requests (IPv4 protocol 1, IPv6 protocol 58 — dispatched by target family) and emits the minimum round-trip time observed across the send batch as an `IcmpEchoRttMicros(<microseconds>)` signal in unsigned integer microseconds. The target is marked reachable as soon as any reply arrives; a target with no replies contributes no signal. The prober tries an unprivileged `SOCK_DGRAM` socket first and falls back to `SOCK_RAW` when the kernel refuses it; the `SOCK_RAW` path requires `CAP_NET_RAW`. See the [ICMP prober page](../probe/icmp.md) for the payload shape, capability requirements, and per-runtime setup.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"icmp"`. |
| `count` | u32 | no | `3` | Number of Echo Requests to send. Minimum 1. |
| `interval_ms` | u64 | no | `200` | Milliseconds between consecutive requests. Zero means send as fast as the kernel accepts. |

```json
{"type": "icmp", "count": 3, "interval_ms": 200}
```

## Encoders

The `encoder` field is an internally-tagged object. One encoder is available today: `ndjson`. It writes one JSON-encoded `DeviceRecord` per line, separated by `\n`. When the field is omitted, NDJSON is used.

```json
{"type": "ndjson"}
```

## Sinks

The `sink` field is an internally-tagged object. Five variants exist; the `kafka` variant is only available when `rastreo-core` is built with the `kafka` Cargo feature and the `nats` variant is only available with the `nats` Cargo feature. The `memory` variant is reachable from the library API and is what the HTTP server uses internally to capture records for the response body. Clients can submit a `memory` sink on `POST /scans`, but the server strips and replaces any client-supplied sink either way.

Write each NDJSON line to standard output:

```json
{"type": "stdout"}
```

Append each NDJSON line to a file. The path is opened in append mode; repeated runs accumulate rather than overwrite.

```json
{"type": "file", "path": "/tmp/scan.ndjson"}
```

Buffer records in memory. Useful for library tests and for the HTTP server's internal capture; not typically set by clients.

```json
{"type": "memory"}
```

Publish each `DeviceRecord` to a Kafka topic encoded as NDJSON. Requires the `kafka` build feature on `rastreo-core` and on the consuming binary.

| Field | Type | Required | Notes |
|---|---|---|---|
| `brokers` | array of string | yes | Kafka broker `host:port` list. |
| `topic` | string | yes | Topic name. |
| `flush_mode` | object | no | Defaults to `batched` with a 64 KiB threshold. See below. |

```json
{
  "type": "kafka",
  "brokers": ["localhost:9092"],
  "topic": "rastreo.devices",
  "flush_mode": {"type": "batched", "threshold_bytes": 65536}
}
```

The `flush_mode` field is itself an internally-tagged object with two variants. `per_record` produces one Kafka message per `DeviceRecord` and prioritises freshness over throughput. `batched` accumulates NDJSON bytes in an internal buffer and produces a single Kafka message when the buffer reaches `threshold_bytes` (default 65536). Inside `batched`, `threshold_bytes` is optional and defaults to 64 KiB.

```json
{"type": "per_record"}
```

```json
{"type": "batched", "threshold_bytes": 65536}
```

Publish each `DeviceRecord` to a NATS JetStream subject encoded as NDJSON. Requires the `nats` build feature on `rastreo-core` and on the consuming binary. The JetStream stream that binds the subject must be created out of band (`nats stream add` or Terraform); construction fails fast if the stream is missing so records never silently drop.

| Field | Type | Required | Notes |
|---|---|---|---|
| `servers` | array of string | yes | NATS server URLs, e.g. `["nats://nats-01:4222"]`. |
| `subject` | string | yes | Subject to publish to. |
| `stream` | string | yes | JetStream stream name bound to the subject. |
| `credentials` | object | no | Auth details. Defaults to anonymous. See below. |
| `delivery` | object | no | Delivery / flush mode. Defaults to `per_record`. See below. |

```json
{
  "type": "nats",
  "servers": ["nats://nats:4222"],
  "subject": "rastreo.discovery.records.v1",
  "stream": "rastreo",
  "credentials": {"auth_type": "user_pass", "username": "admin", "password": "sekret"},
  "delivery": {"mode": "per_record"}
}
```

The `credentials` field is an internally-tagged object with four variants distinguished by `auth_type`. `anonymous` connects with no auth (lab / dev only). `user_pass` sends a username and password. `token` sends a bearer token. `creds` reads a NATS `.creds` file (JWT + nkey seed) from disk. Password and token values are redacted in Debug output and in `source_config_hash` — rotation still changes the hash, plaintext never leaks.

```json
{"auth_type": "anonymous"}
```

```json
{"auth_type": "user_pass", "username": "admin", "password": "sekret"}
```

```json
{"auth_type": "token", "token": "bearer-xyz"}
```

```json
{"auth_type": "creds", "creds_file": "/etc/rastreo/nats.creds"}
```

The `delivery` field is an internally-tagged object with two variants. `per_record` publishes each record and waits for the JetStream ack — the simplest at-least-once model. `batched` accumulates NDJSON bytes until the buffer reaches `threshold_bytes` (default 65536) before publishing one JetStream message; pending acks are drained on `flush()`. Batched mode raises throughput at the cost of a wider failure window if the process is killed mid-batch.

```json
{"mode": "per_record"}
```

```json
{"mode": "batched", "threshold_bytes": 65536}
```

## Fusers

The `fuser` field is an internally-tagged object. Three fusers are available: `direct` (always), `oui_enrichment` (with the `oui` build feature), and `identity` (always). `oui_enrichment` and `identity` are wrapper fusers — they delegate to an inner fuser and add their own logic on top.

### direct

`direct` groups probe outcomes by target IP, dedups signals, and emits one `DeviceRecord` per group. Confidence is computed as `confidence_baseline + (signals_observed * confidence_per_signal)`, clamped to `1.0`.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"direct"`. |
| `include_unreachable` | bool | no | `false` | When `true`, emit a record for targets that produced no reachable probe outcomes. |
| `confidence_baseline` | float | no | `0.1` | Starting confidence before any signals are counted. Must be finite and in `[0.0, 1.0]`. |
| `confidence_per_signal` | float | no | `0.1` | Confidence added per observed signal. Must be finite and non-negative. |

```json
{
  "type": "direct",
  "include_unreachable": false,
  "confidence_baseline": 0.3,
  "confidence_per_signal": 0.2
}
```

### oui_enrichment

`oui_enrichment` wraps another fuser: it delegates fusion to `inner`, then looks up the returned record's MAC address in an OUI database and populates `DeviceRecord.manufacturer` with the vendor name. Records without a MAC are returned unchanged. Records whose MAC prefix is not in the database are also returned unchanged (`manufacturer` stays `null`).

Requires the `oui` build feature. The bundled OUI database is a Wireshark manuf snapshot embedded at compile time (see the [OUI enrichment page](../discover/enrichment.md) for provenance and refresh cadence). Set `data_path` to load an alternative manuf-format file from disk instead.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"oui_enrichment"`. |
| `data_path` | string | no | `""` | Path to a manuf-format file. Empty string loads the compiled-in bundled snapshot. |
| `inner` | object | yes | — | Nested fuser config (typically `direct`). Validated recursively. |

```json
{
  "type": "oui_enrichment",
  "data_path": "",
  "inner": {
    "type": "direct",
    "confidence_baseline": 0.1,
    "confidence_per_signal": 0.1
  }
}
```

Longest-prefix wins on lookup: a /36 MA-S allocation takes precedence over a /28 MA-M, which takes precedence over a /24 MA-L. Vendor names come from the manuf file's long-name column, falling back to the short-name column when the long name is empty.

### identity

`identity` wraps another fuser: it delegates fusion to `inner`, then runs union-find over the returned records and merges records that share identity signals (non-virtual MAC, `SnmpSysName`). Merged records get `alt_ips` populated with the other IPs; medium-confidence non-merged pairs get `possible_alias_of` set on both records. See the [Identity page](../discover/identity.md) for the full algorithm, virtual MAC prefixes hard-excluded, and confidence bands.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"identity"`. |
| `identity_hints` | object | no | `{}` | User-declared identity signals — see below. |
| `inner` | object | yes | — | Nested fuser config (typically `direct` or `oui_enrichment`). Validated recursively. |

The `identity_hints.vrrp_groups` array declares physical members of a shared virtual IP so their records stay separate even when their MACs would otherwise match. Each entry:

| Field | Type | Required | Notes |
|---|---|---|---|
| `virtual_ip` | IP address | yes | The shared virtual IP. |
| `virtual_mac` | string | yes | The shared virtual MAC. Validated at construction; must parse as a MAC address. Records with this MAC contribute zero weight to identity fusion. |
| `members` | array of IP addresses | no | Physical member IPs of the VRRP group. Pairs of member IPs are capped below the medium band. |

```json
{
  "type": "identity",
  "identity_hints": {
    "vrrp_groups": [
      {
        "virtual_ip": "10.0.0.1",
        "virtual_mac": "00:00:5e:00:01:0a",
        "members": ["10.0.0.2", "10.0.0.3"]
      }
    ]
  },
  "inner": {
    "type": "oui_enrichment",
    "inner": {"type": "direct"}
  }
}
```

## Example: minimal POST /scans body

The smallest body that `POST /scans` accepts. Targets a single IP on port 80, uses the default fuser, and returns NDJSON records in the response body. The client does not need to set `sink` — the server provides an in-memory capture and returns the records.

```json
{
  "targets": [
    {"Ip": "127.0.0.1"}
  ],
  "probers": [
    {"type": "tcp_connect", "ports": [80]}
  ]
}
```

A fuller body with explicit fuser knobs and a custom timeout:

```json
{
  "name": "lab scan",
  "rate_limit": 32,
  "timeout_ms": 500,
  "fuser": {
    "type": "direct",
    "confidence_baseline": 0.3,
    "confidence_per_signal": 0.2
  },
  "targets": [
    {"Cidr": "10.0.0.0/29"}
  ],
  "probers": [
    {"type": "tcp_connect", "ports": [22, 80, 443]}
  ]
}
```

## See also

- [CLI reference](cli.md) — every flag for `rastreo` and `rastreo-server`.
- [Error reference](errors.md) — what `POST /scans` returns on bad input.
- [Sinks](../discover/sinks.md) — sink behaviour explained.
