---
description: The DiscoverScenarioConfig JSON shape used by POST /scans and by library callers — every field, every variant, with defaults and validation rules.
---

# Scenario schema

A scenario describes one discovery run: which targets to probe, which probers to use, how to encode the results, and where to send them. The `rastreo-server` HTTP API accepts a scenario as the JSON body of `POST /scans`; library callers construct the same shape in code. The `rastreo` CLI loads a `ScenarioFile` (one or more scenarios plus a top-level `version` / `kind` / `defaults` header) from disk via `rastreo discover --file <path>`.

This page documents the JSON form. Field names match the wire shape exactly (the underlying Rust type is `rastreo_core::config::DiscoverScenarioConfig`).

!!! tip "Loading from the CLI"
    `rastreo discover --file scan.yml` loads a YAML `ScenarioFile` and runs each `scenarios[]` entry sequentially. The file must set `version: 1` and `kind: discovery`. See the [CLI reference](../discover/cli.md#yaml-driven-mode) for the full mode surface, including CLI flag overrides on YAML values.

Any string scalar in the scenario may use `${VAR}` to interpolate an environment variable, or the `!file /path` YAML tag to substitute the contents of a file mount. Both syntaxes are resolved at scenario load. See [Secrets](secrets.md) for the syntax rules, error behaviour, and the recommended pattern for Vault / AWS Secrets Manager (a wrapper script that exports env vars before spawning rastreo).

## Top-level fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string \| null | `null` | Optional human-readable label for the scenario. Not interpreted by the runtime. |
| `max_concurrent` | integer \| null | `null` | Maximum number of probes in flight at once. Maps to scheduler concurrency at runtime. |
| `probe_rate` | integer \| null | `null` | Maximum number of probes started per second. When unset, probes start as fast as `max_concurrent` allows. |
| `timeout_ms` | integer \| null | `null` | Per-probe timeout in milliseconds. |
| `retries` | integer \| null | `null` (0, single-shot) | Retransmit attempts for the connectionless probers (UDP, SNMP, DNS, reverse DNS) on lossy links. `0` sends one request and never resends. Range 0–1024; a larger value is rejected at load. It divides `timeout_ms` across `retries + 1` attempts, so the total time per probe is unchanged. TCP-based probers (`tcp_connect`, `http`, `ssh`, `tls`) and ICMP ignore it. See [CLI · Retries on lossy links](../discover/cli.md#retries-on-lossy-links). |
| `encoder` | object \| null | `null` (the destination decides) | Output encoding. Unset, the CLI renders the table for a stdout sink and NDJSON everywhere else; the HTTP server always pins NDJSON. See [Encoders](#encoders). |
| `fuser` | object \| null | `null` (Direct, baseline 0.1 / per-signal 0.1) | Signal-fusion strategy. See [Fusers](#fusers). |
| `classifier` | object \| null | `null` (Rules, baked-in tables, merge_mode extend) | Platform / os_version / role classifier applied after fusion. See [Classifier](#classifier). |
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

The `probers` array contains internally-tagged objects (each carries a `type` field). Thirteen probers are available today: `tcp_connect`, `http`, `dns`, `reverse_dns`, `udp`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, `gnmi`, and `lldp`. The `http`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, and `gnmi` variants are gated behind their matching Cargo features on `rastreo-core`, all bundled with the published binaries and Docker image. The `lldp` variant is gated behind the `lldp` feature (which turns on `snmp`), bundled with the published binaries and Docker image. The `tcp_connect`, `dns`, `reverse_dns`, and `udp` variants are always available.

### `tcp_connect`

Establishes a TCP connection to each listed port on each resolved target IP; an open port produces an `OpenPort(<port>)` signal.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"tcp_connect"`. |
| `ports` | array of u16 | yes | List of ports to probe. |

```json
{"type": "tcp_connect", "ports": [22, 80, 443]}
```

A port that is closed, refused, or silent is a normal negative result, not an error. A socket failure on the scan host itself — file-descriptor exhaustion, for example — is a probe fault and surfaces as an error. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults).

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

### `reverse_dns`

Issues a PTR query for each target IP against the configured resolvers (or the host's system resolver when none are configured) and emits each returned hostname as a `ReverseDnsName(<hostname>)` signal. IPv4 arpa-name construction (`in-addr.arpa`) and IPv6 arpa-name construction (`ip6.arpa`) are handled automatically from the target `IpAddr`. See the [reverse DNS prober page](../probe/reverse-dns.md) for resolver-selection semantics and empty-response handling.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"reverse_dns"`. |
| `resolvers` | array of IP address | no | `[]` (system resolver) | Explicit resolver IPs to query. Empty means use the host's system resolver configuration. Resolvers are contacted over UDP on port 53. |

```json
{"type": "reverse_dns", "resolvers": ["1.1.1.1", "8.8.8.8"]}
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

### `lldp`

Walks the LLDP-MIB over SNMP to read a device's link-layer neighbors, then assembles them into topology links emitted as `LinkRecord`s. Emits no device signals — a device it reaches produces a reachable `DeviceRecord` with `probe_kinds: ["Lldp"]` and no signals, while its neighbors flow onto a second stream. Takes the same transport fields as the `snmp` prober plus `max_rows`. See the [LLDP prober page](../probe/lldp.md) for the SNMP transport, credential shape, and reachability model, and [Topology](../discover/topology.md) for the `LinkRecord` shape and where links are emitted.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"lldp"`. |
| `ports` | array of u16 | no | `[161]` | SNMP ports to read from. |
| `version` | string | no | `v2c` | One of `v1`, `v2c`, `v3`. |
| `community` | string | no | `public` | SNMP community string. Transmitted in cleartext on v1 and v2c. Ignored on v3. |
| `credentials` | object | no | `{}` | USM credentials. Required on `v3` (username must be non-empty). Ignored on v1 and v2c. See [SNMPv3 credentials](../probe/snmp.md#snmpv3-credentials). |
| `max_rows` | integer | no | `4096` | Maximum neighbor-table rows a single walk reads. |

```json
{"type": "lldp", "ports": [161], "version": "v2c", "community": "public"}
```

An SNMPv3 example with `authPriv`, SHA-256, and AES-128:

```yaml
type: lldp
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

### `tls`

Opens a TCP connection to each configured port, performs a TLS handshake accepting any certificate, then extracts the Subject Common Name and Subject Alternative Names from the server's leaf certificate. Emits `TlsSubject(<value>)` for the CN and one `TlsSanName(<value>)` per SAN entry. No trust-chain validation is performed — the prober fingerprints what a server calls itself, it does not authenticate it. See the [TLS prober page](../probe/tls.md) for the SAN encoding rules, IP-vs-DNS format, and the identity-fingerprint rationale.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"tls"`. |
| `ports` | array of u16 | no | `[443]` | Ports to probe. Sorted and deduplicated at construction. |

```json
{"type": "tls", "ports": [443, 8443]}
```

### `gnmi`

Connects to a device's gRPC/gNMI endpoint on each configured port, issues a Capabilities call and a Get call, and emits the gNMI version, supported YANG models and encodings, and configured state values as typed signals. TLS accepts any server certificate — the prober fingerprints the endpoint, it does not authenticate it. Credentials are optional but unlock the state values; without them most devices reject the read. See the [gNMI prober page](../probe/gnmi.md) for the transport, authentication, and reachability rules.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"gnmi"`. |
| `ports` | array of u16 | no | `[57400]` | Ports to probe. Sorted and deduplicated at construction. |
| `plaintext` | bool | no | `false` | When `false`, connects over TLS accepting any certificate. When `true`, connects over cleartext gRPC. |
| `username` | string | no | `""` | gNMI username. Empty means an anonymous probe. |
| `password` | string | no | `""` | gNMI password. Redacted in Debug output. Accepts `${VAR}` and `!file` secrets. |
| `get_paths` | array of string | no | `["/system/state/hostname", "/system/state/software-version"]` | gNMI paths for the Get call. Supports path origins and keyed list elements. An empty list runs Capabilities only. |
| `lldp` | bool | no | `false` | Also discover LLDP neighbors over the OpenConfig `/lldp` tree for [topology](../discover/topology.md). Runs alongside `get_paths`. See the [gNMI prober page](../probe/gnmi.md#lldp-topology). |

```json
{"type": "gnmi", "ports": [57400], "username": "admin", "password": "${GNMI_PASSWORD}", "get_paths": ["/system/state/hostname"]}
```

## Encoders

The `encoder` field is an internally-tagged object. Two encoders are available: `ndjson` and `table`.

When the field is omitted, the destination decides: a `stdout` sink renders the table, and every other sink renders NDJSON. Setting `encoder` pins the choice regardless of destination — subject to the `table`-against-a-broker rejection below. `rastreo discover --format` overrides the field on any scenario. The HTTP server ignores it entirely and pins NDJSON.

### ndjson

Writes one JSON-encoded record per line, separated by `\n`. This is the complete view: every field of the `DeviceRecord`, plus the link and collection-profile second streams.

```json
{"type": "ndjson"}
```

### table

Writes an aligned fixed-width table for reading a scan directly, with one header line and one row per device. It is a triage view — four columns answering "which host, what is it called, what is it, what is open" — not a complete record. Use `ndjson` when you need every field.

```json
{"type": "table", "width": 100}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `width` | integer | `100` | Total line width the columns are laid out within. Clamped up to 55 (the sum of the column minimums) and capped at 153 (the sum of the column maximums), so any larger value renders the same table as 153. |

| Column | Source |
|---|---|
| `ADDRESS` | `mgmt_ip`, falling back to `identity_key` when the device was not probed on an IP. |
| `NAME` | The SNMP `sysName` signal, falling back to the reverse-DNS (PTR) name. |
| `PLATFORM` | `platform`, falling back to `model`, then `product_family`. |
| `PORTS` | Every `OpenPort` signal on the record, comma-separated, in record order. |

A cell with no value renders as `-`. Columns start at their minimum width and share the surplus round-robin up to a per-column maximum, so a wider `width` grows every column rather than only the last.

A value longer than its column is truncated with a trailing `…`, except in the last column: `PORTS` runs past `width` rather than dropping ports, because it has no following column to stay aligned with. Truncation counts characters, so a cell of full-width CJK text still fits its character budget but will overflow the column visually.

Links and collection profiles are not rendered as table rows. A scan that collects LLDP or gNMI capability data still assembles them, but nothing is written for those streams and `links_emitted` / `profiles_emitted` report `0`. Use `ndjson` to capture them.

The `table` encoder is rejected against the `kafka` and `nats` sinks, whose consumers read one structured record per message. `rastreo validate` reports it offline, without contacting the broker.

## Sinks

The `sink` field is an internally-tagged object. Five variants exist; the `kafka` variant is only available when `rastreo-core` is built with the `kafka` Cargo feature and the `nats` variant is only available with the `nats` Cargo feature. The `memory` variant is reachable from the library API and is what the HTTP server uses internally to capture records for the response body. Clients can submit a `memory` sink on `POST /scans`, but the server strips and replaces any client-supplied sink either way.

### stdout

Write each encoded record to standard output. With no `encoder` set, `rastreo discover` renders the [table](#table) here. See [Encoders](#encoders).

```json
{"type": "stdout"}
```

### file

Append each encoded record to a file, one per line. With no `encoder` set, that is NDJSON. The path is opened in append mode; repeated runs accumulate rather than overwrite.

```json
{"type": "file", "path": "/tmp/scan.ndjson"}
```

### memory

Buffer records in memory. Useful for library tests and for the HTTP server's internal capture; not typically set by clients.

```json
{"type": "memory"}
```

### kafka

Publish each `DeviceRecord` to a Kafka topic encoded as NDJSON. Requires the `kafka` build feature on `rastreo-core` and on the consuming binary.

| Field | Type | Required | Notes |
|---|---|---|---|
| `brokers` | array of string | yes | Kafka broker `host:port` list. |
| `topic` | string | yes | Topic name for the `DeviceRecord` stream. |
| `links_topic` | string | no | Topic for the `LinkRecord` stream. Defaults to `rastreo.discovery.links.v1`. Used only when an [LLDP prober](../probe/lldp.md) produces links. See [Topology](../discover/topology.md#where-links-are-emitted). |
| `profiles_topic` | string | no | Topic for the `CollectionProfileRecord` stream. Defaults to `rastreo.discovery.profiles.v1`. Used only when a [gNMI prober](../probe/gnmi.md) produces collection profiles. See [CollectionProfileRecord](schema/collection-profile-record.md). |
| `flush_mode` | object | no | Defaults to `batched` with a 64 KiB threshold. See below. |
| `dead_letter` | object | no | Quarantine topic for records the primary produce refused. Omit it and a produce failure returns an error with the records left in the sink buffer, so nothing is quarantined and nothing is dropped. |
| `tls` | object | no | Optional TLS for the broker connection. `verify` defaults to `false`. See [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication). |
| `sasl` | object | no | Optional SASL credentials (`plain`, `scram_sha_256`, or `scram_sha_512`). See [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication). |
| `retry` | object | no | Bounded backoff on the primary produce before the DLQ. Defaults to 3 attempts, 100 ms initial / 2000 ms max backoff. Set `max_attempts: 1` to disable. See below. |

```json
{
  "type": "kafka",
  "brokers": ["localhost:9092"],
  "topic": "rastreo.devices",
  "flush_mode": {"type": "batched", "threshold_bytes": 65536},
  "dead_letter": {"topic": "rastreo.devices.dlq", "include_error_metadata": true}
}
```

The `flush_mode` field is itself an internally-tagged object with two variants. Both put exactly one `DeviceRecord` in each Kafka message. `per_record` sends each record immediately and prioritises freshness over throughput. `batched` buffers records and sends them in one produce request when the buffer reaches `threshold_bytes` (default 65536); each record is still its own message, so batching raises throughput without changing the wire framing. Inside `batched`, `threshold_bytes` is optional and defaults to 64 KiB.

The `dead_letter` field carries two properties: `topic` (required, the DLQ Kafka topic name) and `include_error_metadata` (optional, default `true`). When enabled, DLQ messages carry three headers: `x-rastreo-source-topic`, `x-rastreo-error-class` (currently always `produce_failure`), and `x-rastreo-dlq-timestamp` (RFC 3339 UTC). See [Sinks · Dead-letter queue](../discover/sinks.md#dead-letter-queue) for the failure model and consumer guidance.

The `retry` field tunes how the sink handles a transient primary-produce failure before it falls back to the DLQ. It carries three optional integer fields:

- `max_attempts` — total primary produce attempts including the first. Default `3`. Set `1` to disable retry, sending the record to the DLQ on the first failure.
- `backoff_initial_ms` — milliseconds to wait before the first retry. Default `100`.
- `backoff_max_ms` — the largest wait between attempts, in milliseconds. Default `2000`.

The wait doubles after each failed attempt, capped at `backoff_max_ms`. Retry is on by default; omit the block to get these defaults. The same `retry` shape and defaults apply to the `nats` sink. See [Sinks · Retrying before the dead-letter queue](../discover/sinks.md#retrying-before-the-dead-letter-queue).

The `tls` and `sasl` fields secure the broker connection. `tls` carries `verify` (default `false`) and an optional `ca_cert` PEM string, read only when `verify: true`. `sasl` carries `mechanism` (`plain`, `scram_sha_256`, or `scram_sha_512`), `username`, and `password`. The two blocks are independent, so `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, and `SASL_SSL` brokers all compose. Keep `password` and `ca_cert` in `${VAR}` environment references or `!file` mounts — see [Secrets](secrets.md). See [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication) for full examples.

```json
{
  "type": "kafka",
  "brokers": ["broker.internal:9093"],
  "topic": "rastreo.devices",
  "tls": {"verify": true},
  "sasl": {"mechanism": "scram_sha_512", "username": "rastreo-writer", "password": "${KAFKA_PASSWORD}"}
}
```

```json
{"type": "per_record"}
```

```json
{"type": "batched", "threshold_bytes": 65536}
```

### nats

Publish each `DeviceRecord` to a NATS JetStream subject encoded as NDJSON. Requires the `nats` build feature on `rastreo-core` and on the consuming binary. The JetStream stream that binds the subject must be created out of band (`nats stream add` or Terraform); construction fails fast if the stream is missing so records never silently drop.

| Field | Type | Required | Notes |
|---|---|---|---|
| `servers` | array of string | yes | NATS server URLs, e.g. `["nats://nats-01:4222"]`. |
| `subject` | string | yes | Subject to publish the `DeviceRecord` stream to. |
| `links_subject` | string | no | Subject for the `LinkRecord` stream. Defaults to `rastreo.discovery.links.v1`. Used only when an [LLDP prober](../probe/lldp.md) produces links. See [Topology](../discover/topology.md#where-links-are-emitted). |
| `profiles_subject` | string | no | Subject for the `CollectionProfileRecord` stream. Defaults to `rastreo.discovery.profiles.v1`. Used only when a [gNMI prober](../probe/gnmi.md) produces collection profiles. See [CollectionProfileRecord](schema/collection-profile-record.md). |
| `stream` | string | yes | JetStream stream name bound to the subject. |
| `credentials` | object | no | Auth details. Defaults to anonymous. See below. |
| `flush_mode` | object | no | Flush mode. Defaults to `per_record`. See below. |
| `dead_letter` | object | no | Quarantine subject for records the primary publish or JetStream ack refused. Omit it and either failure returns an error with the records left in the sink buffer and the pending-ack queue, so nothing is quarantined and nothing is dropped. |
| `retry` | object | no | Bounded backoff on the primary publish before the DLQ. Same shape and defaults as the `kafka` sink. Set `max_attempts: 1` to disable. See below. |

```json
{
  "type": "nats",
  "servers": ["nats://nats:4222"],
  "subject": "rastreo.discovery.records.v1",
  "stream": "rastreo",
  "credentials": {"type": "user_pass", "username": "admin", "password": "sekret"},
  "flush_mode": {"type": "per_record"}
}
```

The `credentials` field is an internally-tagged object with four variants distinguished by `type`. `anonymous` connects with no auth (lab / dev only). `user_pass` sends a username and password. `token` sends a bearer token. `creds` reads a NATS `.creds` file (JWT + nkey seed) from disk. Password and token values are redacted in Debug output and in `source_config_hash` — rotation still changes the hash, plaintext never leaks.

```json
{"type": "anonymous"}
```

```json
{"type": "user_pass", "username": "admin", "password": "sekret"}
```

```json
{"type": "token", "token": "bearer-xyz"}
```

```json
{"type": "creds", "creds_file": "/etc/rastreo/nats.creds"}
```

The `flush_mode` field is an internally-tagged object with two variants. Both put exactly one `DeviceRecord` in each NATS message. `per_record` publishes each record and waits for its JetStream ack — the simplest at-least-once model. `batched` publishes each record as its own message too, but pipelines the acks: it buffers until `threshold_bytes` (default 65536), fires the publishes, and drains the pending acks once enough are outstanding and again on `flush()`. Batched mode raises throughput at the cost of a wider failure window if the process is killed mid-batch; a rejected ack can surface from a record write, not only from `flush()`. See [NATS · Delivery modes](../integrate/nats.md#delivery-modes).

```json
{"type": "per_record"}
```

```json
{"type": "batched", "threshold_bytes": 65536}
```

The `dead_letter` field carries three properties: `stream` (required, the DLQ JetStream stream name), `subject` (required, the DLQ subject), and `include_error_metadata` (optional, default `true`). When enabled, DLQ messages carry three headers: `x-rastreo-source-subject`, `x-rastreo-error-class` (either `publish_failure` for a synchronous `publish()` failure or `ack_rejection` when JetStream refused durable storage), and `x-rastreo-dlq-timestamp` (RFC 3339 UTC). The DLQ stream must exist on the same NATS cluster as the primary stream; construction fails fast if it is missing. See [Sinks · Dead-letter queue](../discover/sinks.md#dead-letter-queue_1) for the failure model, error-class taxonomy, and consumer guidance.

The `retry` field has the same three integer fields and defaults as the `kafka` sink (`max_attempts: 3`, `backoff_initial_ms: 100`, `backoff_max_ms: 2000`). It retries the synchronous publish only. A JetStream ack rejection is not retried, because the message may already be stored; it goes straight to the DLQ as `ack_rejection`. See [Sinks · Retrying before the dead-letter queue](../discover/sinks.md#retrying-before-the-dead-letter-queue_1).

```json
{"stream": "rastreo-dlq", "subject": "rastreo.discovery.dlq", "include_error_metadata": true}
```

## Fusers

The `fuser` field is an internally-tagged object. Three fusers are available: `direct` (always), `mib_enrichment` (with the `mib_enrichment` build feature), and `identity` (always). `mib_enrichment` and `identity` are wrapper fusers — they delegate to an inner fuser and add their own logic on top.

### direct

`direct` groups probe outcomes by target IP, dedups signals, and emits one `DeviceRecord` per group. Confidence is computed as `confidence_baseline + (signals_observed * confidence_per_signal)`, clamped to `1.0`.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"direct"`. |
| `include_unreachable` | bool | no | `false` | Emit a record for every probed address, including addresses that no prober reached. See [Recording addresses that did not answer](#recording-addresses-that-did-not-answer). |
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

#### Recording addresses that did not answer

By default (`include_unreachable: false`) an address that no prober reached produces no record. A scan of `10.0.0.0/24` with twelve live hosts emits twelve records, not 254. This is what you want when the records feed a source of truth: only real devices are written.

Set `include_unreachable: true` when you want one record per probed address, silent ones included. A silent address gets a record with an empty `signals` list and no `probe_kinds` field at all: no prober observed the device, so there is no provenance to report. Its confidence equals `confidence_baseline` (`0.1` by default). Two cases where you want this:

- **Address-space audits** — you need to know which addresses in a range are in use and which are free, so the free ones must appear too.
- **Change detection** — a consumer compares consecutive scans. It needs to see an address turn silent, rather than watch it vanish from the stream.

`mib_enrichment` and `identity` wrap an inner fuser. Set the flag on the `direct` fuser at the bottom of the chain.

```json
{
  "type": "identity",
  "inner": {
    "type": "direct",
    "include_unreachable": true
  }
}
```

### mib_enrichment

`mib_enrichment` wraps another fuser: it delegates fusion to `inner`, then matches the returned record's SNMP `sysObjectID` against a table and populates `DeviceRecord.model`, `DeviceRecord.product_family`, and `DeviceRecord.manufacturer` — each only when the record does not already carry a value, so an inner enricher's answer survives. Records without a `SnmpSysObjectId` signal, or whose OID is not in the table, are returned unchanged. `mib_enrichment` never sets `platform` — the classifier owns that field.

Requires the `mib_enrichment` build feature, which is not in the default binaries or the published Docker image — so `mib_enrichment` is absent from the published [scenario JSON schema](schema/scenario-config.md), and a default build rejects it. The bundled table is a small seed; set `data_path` to merge your fleet's OIDs on top of it (your entries win on collision). Lookup is an exact match on the full dotted OID — no prefix matching. See the [Enrichment page](../discover/enrichment.md#mib_enrichment) for the overlay file format and worked examples.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"mib_enrichment"`. |
| `data_path` | string | no | bundled seed | Path to an overlay file that merges on top of the bundled seed. Omit or leave empty to use only the seed. |
| `inner` | object | yes | — | Nested fuser config (typically `direct`). Validated recursively. |

```json
{
  "type": "mib_enrichment",
  "data_path": "/etc/rastreo/mib_identity.tsv",
  "inner": {
    "type": "direct"
  }
}
```

### identity

`identity` wraps another fuser: it delegates fusion to `inner`, then runs union-find over the returned records and merges records that share identity signals (non-virtual MAC, `SnmpSysName`). Merged records get `alt_ips` populated with the other IPs; medium-confidence non-merged pairs get `possible_alias_of` set on both records. See the [Identity page](../discover/identity.md) for the full algorithm, virtual MAC prefixes hard-excluded, and confidence bands.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"identity"`. |
| `identity_hints` | object | no | `{}` | User-declared identity signals — see below. |
| `inner` | object | yes | — | Nested fuser config (typically `direct`). Validated recursively. |

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
    "type": "direct"
  }
}
```

## Classifier

The `classifier` field is an internally-tagged object. Two classifiers ship today: `rules` (a platform phase for `platform` + `os_version` and a role phase for `role`, each with a baked-in default table) and `noop` (pass-through). When the field is omitted, `rules` is used with `merge_mode: extend` and no user rules, which runs the baked-in tables on their own. See the [Classification page](../discover/classification.md) for what classification does and where in the pipeline it runs.

### noop

Pass-through classifier. Assigns nothing on the record; `platform`, `os_version`, and `role` stay at whatever the fuser set them to. Set it explicitly to turn classification off.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"noop"`. |

```json
{"type": "noop"}
```

### rules

Rules classifier, and the default when `classifier` is omitted. Runs a platform phase (regex patterns) and a role phase (signal-driven prefix and set-membership rules). First match per phase sets the corresponding field. See [Baked-in platform rules](../discover/classification.md#baked-in-platform-rules), [Baked-in role rules](../discover/classification.md#baked-in-role-rules), and [Extending the rule set](../discover/classification.md#extending-the-rule-set) for the shipped defaults and merge-mode semantics.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"rules"`. |
| `merge_mode` | string | no | `"extend"` (default) prepends user rules to the baked-in lists for both phases. `"replace"` runs only user rules. Applies uniformly to `platform_rules` and `role_rules`. |
| `platform_rules` | array | no | User-supplied `PlatformRule` list. Empty array (or field omitted) is equivalent under `extend` to running the baked-in platform rules alone. |
| `role_rules` | array | no | User-supplied `RoleRule` list. Empty array (or field omitted) is equivalent under `extend` to running the baked-in role rules alone. |

Each `PlatformRule` has:

| Field | Type | Required | Notes |
|---|---|---|---|
| `signal` | string | yes | Which probe signal the pattern matches against. One of `snmp_sys_descr`, `snmp_sys_object_id`, `snmp_sys_name`, `ssh_banner`, `http_banner`. See [Signal kinds](../discover/classification.md#signal-kinds). |
| `pattern` | string | yes | Regex pattern. Validated when the classifier is built; a bad pattern is rejected before the scan starts. |
| `platform` | string \| null | no | Canonical OS label assigned on match (e.g. `cisco_ios`, `nokia_srlinux`, `linux`). Omit it for a rule that only extracts `ssh_version`, `http_server`, or `http_version` from a service banner. |
| `os_version_capture` | string \| null | no | Named regex capture group whose match populates `DeviceRecord.os_version`. Requires `platform` — a rule capturing `os_version` without one is rejected when the classifier is built. When absent, `os_version` stays `null` even on a platform match. |
| `ssh_version_capture` | string \| null | no | Named regex capture group whose match populates `DeviceRecord.ssh_version`. Only meaningful for `signal: ssh_banner`. |
| `http_server_capture` | string \| null | no | Named regex capture group whose match populates `DeviceRecord.http_server`. Only meaningful for `signal: http_banner`. |
| `http_version_capture` | string \| null | no | Named regex capture group whose match populates `DeviceRecord.http_version`. Requires `http_server_capture` — a rule capturing `http_version` without one is rejected when the classifier is built. Only meaningful for `signal: http_banner`. |

Each `RoleRule` is an internally-tagged object. Three variants exist.

`sys_object_id_prefix` matches when the record carries an `SnmpSysObjectId` signal equal to `prefix` or inside its subtree. Whole OID arcs are compared, so `1.3.6.1.4.1.9.1` matches `1.3.6.1.4.1.9.1.2050` but not `1.3.6.1.4.1.9.15.2`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"sys_object_id_prefix"`. |
| `prefix` | string | yes | SNMP `sysObjectID` subtree (e.g. `"1.3.6.1.4.1.9.1"`). Must be dotted-decimal — two or more digit arcs, no leading dot, no whitespace — and is rejected when the classifier is built otherwise. |
| `role` | string | yes | Role label assigned on match (e.g. `router`, `switch`). |

`signal_match` matches when `pattern` matches the text of any signal of kind `signal` on the record. Same signal vocabulary and regex engine as a `PlatformRule`; capture groups are allowed but ignored.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"signal_match"`. |
| `signal` | string | yes | Which probe signal the pattern matches against. Same values as a `PlatformRule`'s `signal`. |
| `pattern` | string | yes | Regex pattern. Validated when the classifier is built; a bad pattern is rejected before the scan starts. |
| `role` | string | yes | Role label assigned on match. |

`ports_open` matches when the record carries a `Signal::OpenPort(p)` for every `p` in `ports`. Extra open ports do not cause a mismatch; only the listed ones must all be present.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"ports_open"`. |
| `ports` | array of u16 | yes | Ports that must all appear as `OpenPort` signals. Must be non-empty; an empty list is rejected when the classifier is built. |
| `role` | string | yes | Role label assigned on match. |

```json
{
  "type": "rules",
  "merge_mode": "extend",
  "platform_rules": [
    {
      "signal": "snmp_sys_descr",
      "pattern": "^Cisco IOS Software.*Version (?P<version>15\\.\\d+)",
      "platform": "cisco_ios",
      "os_version_capture": "version"
    }
  ],
  "role_rules": [
    {"type": "sys_object_id_prefix", "prefix": "1.3.6.1.4.1.9.1", "role": "router"},
    {"type": "signal_match", "signal": "snmp_sys_name", "pattern": "-spine\\d+$", "role": "spine"},
    {"type": "ports_open", "ports": [22, 179], "role": "router"}
  ]
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

A fuller body with explicit scheduler knobs, fuser knobs, and a custom timeout. `max_concurrent` caps how many probes run at once; `probe_rate` caps how many start per second. `retries` splits the `timeout_ms` budget across `retries + 1` attempts for the connectionless probers. The `tcp_connect` prober shown here ignores it, since TCP handles its own retransmission:

```json
{
  "name": "lab scan",
  "max_concurrent": 64,
  "probe_rate": 50,
  "timeout_ms": 500,
  "retries": 1,
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
