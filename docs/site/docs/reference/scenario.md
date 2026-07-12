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
| `rate_limit` | integer \| null | `null` | Maximum number of in-flight probes. Maps to scheduler concurrency at runtime. |
| `timeout_ms` | integer \| null | `null` | Per-probe timeout in milliseconds. |
| `encoder` | object \| null | `null` (NDJSON) | Output encoding. See [Encoders](#encoders). |
| `fuser` | object \| null | `null` (Direct, baseline 0.1 / per-signal 0.1) | Signal-fusion strategy. See [Fusers](#fusers). |
| `classifier` | object \| null | `null` (Noop) | Platform / os_version / role classifier applied after fusion. See [Classifier](#classifier). |
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

The `probers` array contains internally-tagged objects (each carries a `type` field). Eleven probers are available today: `tcp_connect`, `http`, `dns`, `reverse_dns`, `udp`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, and `tls`. The `http`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, and `tls` variants are gated behind their matching Cargo features on `rastreo-core` (all bundled with the published binaries and Docker image); `tcp_connect`, `dns`, `reverse_dns`, and `udp` are always available.

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
| `dead_letter` | object | no | Optional quarantine topic for records the primary produce refused. Omit to preserve the pre-existing "return error, retain buffer" behavior on produce failure. |

```json
{
  "type": "kafka",
  "brokers": ["localhost:9092"],
  "topic": "rastreo.devices",
  "flush_mode": {"type": "batched", "threshold_bytes": 65536},
  "dead_letter": {"topic": "rastreo.devices.dlq", "include_error_metadata": true}
}
```

The `flush_mode` field is itself an internally-tagged object with two variants. `per_record` produces one Kafka message per `DeviceRecord` and prioritises freshness over throughput. `batched` accumulates NDJSON bytes in an internal buffer and produces a single Kafka message when the buffer reaches `threshold_bytes` (default 65536). Inside `batched`, `threshold_bytes` is optional and defaults to 64 KiB.

The `dead_letter` field carries two properties: `topic` (required, the DLQ Kafka topic name) and `include_error_metadata` (optional, default `true`). When enabled, DLQ messages carry three headers: `x-rastreo-source-topic`, `x-rastreo-error-class` (currently always `produce_failure`), and `x-rastreo-dlq-timestamp` (RFC 3339 UTC). See [Sinks · Dead-letter queue](../discover/sinks.md#dead-letter-queue) for the failure model and consumer guidance.

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
| `dead_letter` | object | no | Optional quarantine subject for records the primary publish or JetStream ack refused. Omit to preserve the pre-existing "return error, retain buffer/pending" behavior on failure. |

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

The `dead_letter` field carries three properties: `stream` (required, the DLQ JetStream stream name), `subject` (required, the DLQ subject), and `include_error_metadata` (optional, default `true`). When enabled, DLQ messages carry three headers: `x-rastreo-source-subject`, `x-rastreo-error-class` (either `publish_failure` for a synchronous `publish()` failure or `ack_rejection` when JetStream refused durable storage), and `x-rastreo-dlq-timestamp` (RFC 3339 UTC). The DLQ stream must exist on the same NATS cluster as the primary stream; construction fails fast if it is missing. See [Sinks · Dead-letter queue](../discover/sinks.md#dead-letter-queue_1) for the failure model, error-class taxonomy, and consumer guidance.

```json
{"stream": "rastreo-dlq", "subject": "rastreo.discovery.dlq", "include_error_metadata": true}
```

## Fusers

The `fuser` field is an internally-tagged object. Three fusers are available: `direct` (always), `oui_enrichment` (with the `oui` build feature), and `identity` (always). `oui_enrichment` and `identity` are wrapper fusers — they delegate to an inner fuser and add their own logic on top.

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

`oui_enrichment` and `identity` wrap an inner fuser. Set the flag on the `direct` fuser at the bottom of the chain.

```json
{
  "type": "identity",
  "inner": {
    "type": "direct",
    "include_unreachable": true
  }
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

## Classifier

The `classifier` field is an internally-tagged object. Two classifiers ship today: `noop` (pass-through) and `rules` (a platform phase for `platform` + `os_version` and a role phase for `role`, each with a baked-in default table). When the field is omitted, `noop` is used. See the [Classification page](../discover/classification.md) for what classification does and where in the pipeline it runs.

### noop

Pass-through classifier. Assigns nothing on the record; `platform`, `os_version`, and `role` stay at whatever the fuser set them to.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"noop"`. |

```json
{"type": "noop"}
```

### rules

Rules classifier. Runs a platform phase (regex patterns) and a role phase (signal-driven prefix and set-membership rules). First match per phase sets the corresponding field. See [Baked-in platform rules](../discover/classification.md#baked-in-platform-rules), [Baked-in role rules](../discover/classification.md#baked-in-role-rules), and [Extending the rule set](../discover/classification.md#extending-the-rule-set) for the shipped defaults and merge-mode semantics.

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"rules"`. |
| `merge_mode` | string | no | `"extend"` (default) prepends user rules to the baked-in lists for both phases. `"replace"` runs only user rules. Applies uniformly to `platform_rules` and `role_rules`. |
| `platform_rules` | array | no | User-supplied `PlatformRule` list. Empty array (or field omitted) is equivalent under `extend` to running the baked-in platform rules alone. |
| `role_rules` | array | no | User-supplied `RoleRule` list. Empty array (or field omitted) is equivalent under `extend` to running the baked-in role rules alone. |

Each `PlatformRule` has:

| Field | Type | Required | Notes |
|---|---|---|---|
| `signal` | string | yes | Which probe signal the pattern matches against. One of `snmp_sys_descr`, `snmp_sys_name`, `ssh_banner`, `http_banner`. |
| `pattern` | string | yes | Regex pattern. Validated when the classifier is built; a bad pattern is rejected before the scan starts. |
| `platform` | string | yes | Canonical platform label assigned on match (e.g. `cisco_ios`, `linux`, `nginx`). |
| `os_version_capture` | string \| null | no | Named regex capture group whose match populates `DeviceRecord.os_version`. When absent, `os_version` stays `null` even on a platform match. |

Each `RoleRule` is an internally-tagged object. Two variants exist.

`sys_object_id_prefix` matches when the record carries any `SnmpSysObjectId` signal whose dotted-string form starts with `prefix` (case-sensitive byte comparison).

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"sys_object_id_prefix"`. |
| `prefix` | string | yes | SNMP `sysObjectID` byte prefix (e.g. `"1.3.6.1.4.1.9.1"`). |
| `role` | string | yes | Role label assigned on match (e.g. `router`, `switch`). |

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
