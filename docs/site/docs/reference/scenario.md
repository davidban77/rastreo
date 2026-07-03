---
description: The DiscoverScenarioConfig JSON shape used by POST /scans and by library callers — every field, every variant, with defaults and validation rules.
---

# Scenario schema

A scenario describes one discovery run: which targets to probe, which probers to use, how to encode the results, and where to send them. The `rastreo-server` HTTP API accepts a scenario as the JSON body of `POST /scans`; library callers construct the same shape in code. The `rastreo` CLI does not load this file directly today — the CLI flags build an equivalent scenario in memory.

This page documents the JSON form. Field names match the wire shape exactly (the underlying Rust type is `rastreo_core::config::DiscoverScenarioConfig`).

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

The `probers` array contains internally-tagged objects (each carries a `type` field). Five probers are available today: `tcp_connect`, `http`, `dns`, `udp`, and `snmp`. The `http` and `snmp` variants are gated behind the `http` and `snmp` Cargo features on `rastreo-core` respectively (both bundled with the published binaries and Docker image); `tcp_connect`, `dns`, and `udp` are always available.

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

## Encoders

The `encoder` field is an internally-tagged object. One encoder is available today: `ndjson`. It writes one JSON-encoded `DeviceRecord` per line, separated by `\n`. When the field is omitted, NDJSON is used.

```json
{"type": "ndjson"}
```

## Sinks

The `sink` field is an internally-tagged object. Four variants exist; the `kafka` variant is only available when `rastreo-core` is built with the `kafka` Cargo feature. The `memory` variant is reachable from the library API and is what the HTTP server uses internally to capture records for the response body. Clients can submit a `memory` sink on `POST /scans`, but the server strips and replaces any client-supplied sink either way.

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

## Fusers

The `fuser` field is an internally-tagged object. One fuser is available today: `direct`. It groups probe outcomes by target IP, dedups signals, and emits one `DeviceRecord` per group. Confidence is computed as `confidence_baseline + (signals_observed * confidence_per_signal)`, clamped to `1.0`.

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
