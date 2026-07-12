---
description: The DNS prober — treats the target as a DNS server, sends queries for configured names, and emits each answer record as a DnsHost signal.
---

# DNS prober

The DNS prober treats every resolved target as a DNS server and sends queries against it. For each configured `query_name` and port, it issues a query of the configured type over UDP or TCP, captures the answer records, and emits each answer as a `DnsHost` signal. A target that responds — even with `NXDOMAIN` or `REFUSED` — is a DNS server. What zones it knows tells you what's behind it.

## Configuration

Add a `dns` entry to a scenario's `probers` array. Only `query_names` is mandatory; every other field has a default, so the minimum shape is `{"type": "dns", "query_names": ["example.com."]}`.

```yaml
probers:
  - type: dns
    ports: [53]
    query_names:
      - example.com.
      - internal.lab.
    query_type: a
    transport: udp
    recursion_desired: true
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"dns"`. |
| `ports` | array of u16 | no | `[53]` | Ports to probe. Sorted and deduplicated at construction. |
| `query_names` | array of string | yes | — | DNS names to query. Each name must have non-empty labels no longer than 63 bytes and a total length no greater than 253 bytes. |
| `query_type` | string | no | `a` | One of `a`, `aaaa`, `mx`, `txt`, `ptr`, `ns`, `cname`. See [Query types](#query-types). |
| `transport` | string | no | `udp` | One of `udp`, `tcp`. See [Transport](#transport). |
| `recursion_desired` | bool | no | `true` | Sets the RD bit on the outgoing query. Set to `false` when probing authoritative-only servers that will not follow the query. |

The prober issues one query per `(port, query_name)` combination — the total probe count per target is `len(ports) × len(query_names)`. A scenario with `ports: [53]` and `query_names: [a, b, c]` fires three queries per target IP.

## Query types

Each query type controls what the prober asks for and how the answer is formatted in the emitted signal.

| Query type | RR type | Signal format |
|---|---|---|
| `a` | `A` | `<name> -> <ipv4>` (e.g. `example.com. -> 93.184.216.34`) |
| `aaaa` | `AAAA` | `<name> -> <ipv6>` (e.g. `example.com. -> 2001:db8::1`) |
| `mx` | `MX` | `<name> -> <preference> <exchange>` (e.g. `example.com. -> 10 mail.example.com.`) |
| `txt` | `TXT` | `<name> -> "<text>"` — the character-strings in the answer are concatenated and wrapped in double quotes |
| `ptr` | `PTR` | `<name> -> <target>` (e.g. `1.0.0.127.in-addr.arpa. -> localhost.`) |
| `ns` | `NS` | `<name> -> <target>` (e.g. `example.com. -> ns1.example.com.`) |
| `cname` | `CNAME` | `<name> -> <target>` (e.g. `www.example.com. -> example.com.`) |

Answer names are emitted as the server returned them; DNS names are typically fully qualified with a trailing dot.

## Transport

`transport: udp` (the default) matches the wire protocol most resolvers speak on port 53. UDP responses can be truncated when they exceed 512 bytes (or the negotiated EDNS payload size); when the truncation flag is set, the hickory client does not automatically fall back to TCP inside a single probe. Set `transport: tcp` explicitly when querying zones whose responses are large — TCP has no per-message size limit.

Both transports honour the scenario-level `timeout_ms`. The prober owns the deadline via `tokio::time::timeout`; the hickory inner timeout is disabled so a per-query retry cannot exceed the configured probe timeout.

## Signals emitted

| Signal | When produced |
|---|---|
| `DnsHost(<value>)` | The server returned at least one answer record whose type matches the configured `query_type`. One signal is emitted per answer record. |

A response with zero matching answers (`NOERROR` with an empty answer section), an `NXDOMAIN` response, or a `REFUSED` response all mark the target as reachable but produce no signals for that `(port, query_name)` combination. The distinction between "server responded, no data" and "server unreachable" is what makes the DNS prober useful for discovery: reachability alone tells you the target speaks DNS.

A target that answers none of the `(port, query_name)` combinations — every query times out, is refused, or hits an unreachable network — is marked unreachable and contributes no signals. That is a normal discovery result, not an error. A transport failure that is neither a timeout nor a refusal (for example a resolver that cannot be built for the target) is a probe fault and does surface as an error. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The DNS prober is always available — no Cargo feature is required. The `hickory-resolver` dependency is already pulled in for target resolution, so the DNS prober adds no additional binary surface. It is present in every build of `rastreo-core`, including builds with `--no-default-features`.

## Example scenario

The following scenario probes a public resolver for the `A` record of `example.com`. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```json
{
  "targets": [{"Ip": "1.1.1.1"}],
  "probers": [
    {
      "type": "dns",
      "ports": [53],
      "query_names": ["example.com"],
      "query_type": "a"
    }
  ]
}
```

A record produced against CloudFlare's public resolver contains at least one `DnsHost` signal shaped like the following:

```json
{
  "signals": [{"DnsHost": "example.com. -> 93.184.216.34"}]
}
```

Probing an authoritative name server for the same zone would use `recursion_desired: false` to prevent the server from following the query on the client's behalf; the response then reflects only what that server holds locally.

## See also

- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the DNS prober from the CLI via `--file`.
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
