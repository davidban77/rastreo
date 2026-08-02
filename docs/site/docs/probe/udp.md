---
description: The UDP prober — speaks protocol-specific payloads over UDP (NTP, SIP OPTIONS, memcached stats, STUN Binding) and emits a typed signal per protocol.
---

# UDP prober

The UDP prober speaks one protocol at a time against configured ports on every resolved target. Unlike TCP, an unanswered UDP datagram cannot tell "port closed" apart from "packet lost", so a plain "did anything reply?" prober would produce noisy results. The prober therefore drives one of four services end-to-end: NTP, SIP, memcached, or STUN. Each builds its own request, parses its own response, and emits a typed signal with what the server reported.

**Use it when** you want to identify a specific UDP service — NTP, SIP, memcached, or STUN — and read its version or details.<br>
**You get** a typed signal naming the service and what it reported (clock quality, software version, or observed public address).

## What the four services are

The prober speaks one of four UDP services. Each runs on different gear, so the one you pick is also a guess about what kind of device you expect:

- **NTP** (Network Time Protocol) — keeps device clocks in sync. Common on routers, firewalls, switches, and domain controllers.
- **SIP** (Session Initiation Protocol) — sets up voice and video calls. Runs on VoIP phones, phone systems (PBXes), and SIP proxies.
- **memcached** — an in-memory cache that speeds up web applications. Runs on application and database servers.
- **STUN** (Session Traversal Utilities for NAT) — helps a device behind a NAT router learn its own public address. Runs on VoIP and video-conferencing infrastructure.

## Configuration

Add a `udp` entry to a scenario's `probers` array. It takes two required fields: `protocol` names which of the four services to speak, and `ports` lists the ports to send to. A scenario must set both. One entry speaks exactly one protocol, and the port a service listens on is a deployment choice.

```yaml
probers:
  - type: udp
    ports: [123]
    protocol: ntp
```

From the command line, `--probe udp --udp-protocol ntp` is enough. The protocol you name carries its own well-known port, so `--port` is optional here. Each protocol has its own: 123 for `ntp`, 5060 for `sip_options`, 11211 for `memcached_stats`, and 3478 for `stun_binding`. Pass `--port` to override them.

```console
$ rastreo discover --target 192.0.2.1 --probe udp --udp-protocol ntp --dry-run
[dry-run] would run 1 scenario
  scenario: discovery
    targets:
      192.0.2.1 → 192.0.2.1
    probers: udp (ports 123, protocol Ntp)
    fuser: direct (include_unreachable false, confidence_baseline 0.1, confidence_per_signal 0.1)
    classifier: rules (merge_mode extend, platform_rules 0, role_rules 0)
    encoder: table
    sink: stdout
    concurrency: 64
    rate: unlimited
    retries: 0
    timeout_ms: 1000
total probes: 1
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"udp"`. |
| `ports` | array of port numbers | yes | Ports to probe. Must not be empty; sorted and deduplicated at construction. |
| `protocol` | string | yes | One of `ntp`, `sip_options`, `memcached_stats`, `stun_binding`. See [Supported protocols](#supported-protocols). |

The prober issues one datagram per port. It uses an ephemeral UDP socket per port, sends the protocol's request, waits for a response until the scenario-level `timeout_ms` expires, and parses whatever came back. Datagrams received from a peer that isn't the target address are ignored — the prober keeps waiting until the target answers or the timeout fires.

## Supported protocols

| `protocol` | Typical port | Signal | What the prober extracts |
|---|---|---|---|
| `ntp` | 123 | `NtpBanner(stratum=<n> ref=<id>)` | The server's stratum and reference identifier from a 48-byte NTPv3 response. For stratum 0 or 1, the 4-character reference code (`GPS `, `PPS `, `LOCL`); for stratum 2+, the reference IP as a dotted quad. |
| `sip_options` | 5060 | `SipUserAgent(<value>)` | The `Server:` header (preferred) or `User-Agent:` header from the response to a `SIP/2.0 OPTIONS` request. Trimmed and capped at 256 bytes. |
| `memcached_stats` | 11211 | `MemcachedVersion(<value>)` | The value of the `STAT version` line in a memcached `stats` response. Capped at 64 bytes. |
| `stun_binding` | 3478 | `StunMappedAddress(<ip>:<port>)` | The `XOR-MAPPED-ADDRESS` attribute of a Binding Success Response. Emits IPv4 as `1.2.3.4:port` and IPv6 as `[::1]:port`. |

Only one protocol runs per prober entry. Add a second `udp` entry to a scenario when you want to probe more than one protocol against the same target.

## Signals emitted

| Signal | When produced |
|---|---|
| `NtpBanner(<value>)` | Valid 48-byte NTP server response (Mode=4) on an NTP prober. |
| `SipUserAgent(<value>)` | SIP response beginning with `SIP/2.0` that carries a `Server:` or `User-Agent:` header. |
| `MemcachedVersion(<value>)` | memcached response containing a `STAT version <value>` line. |
| `StunMappedAddress(<ip>:<port>)` | STUN Binding Success Response whose transaction ID matches the request and which carries `XOR-MAPPED-ADDRESS`. |

A response the parser doesn't recognise (garbage bytes, wrong magic cookie, missing header) still marks the target as reachable — a datagram came back — but produces no signal for that port. Distinguishing "server responded but we couldn't parse it" from "nothing came back" is what makes the UDP prober usable for discovery even when the responding service is a slightly nonstandard implementation.

A target that answers on no configured port — every port times out, is refused, or reports the host as unreachable — is marked unreachable and contributes no signals. That is a normal discovery result, not an error. An I/O failure that is neither a timeout nor a refusal (a socket that cannot be opened, for example) is a probe fault and does surface as an error, with the underlying cause in the message. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The UDP prober is always available — no build feature is required. It needs nothing beyond a plain UDP socket, so it is present in every build, including one with all optional features turned off.

## Example scenarios

Probe a public NTP pool for a stratum reading:

```json
{
  "targets": [{"DnsName": "pool.ntp.org"}],
  "probers": [
    {"type": "udp", "ports": [123], "protocol": "ntp"}
  ]
}
```

A record produced against a stratum-2 server contains one `NtpBanner` signal:

```json
{
  "signals": [{"NtpBanner": "stratum=2 ref=203.0.113.1"}]
}
```

Probe a Kamailio SIP proxy on port 5060:

```json
{
  "targets": [{"Ip": "10.50.0.20"}],
  "probers": [
    {"type": "udp", "ports": [5060], "protocol": "sip_options"}
  ]
}
```

The response's `Server:` header lands in a `SipUserAgent` signal:

```json
{
  "signals": [{"SipUserAgent": "Kamailio/5.6.5 (x86_64/linux)"}]
}
```

Probe a memcached instance on port 11211 for the running version:

```json
{
  "targets": [{"Ip": "10.50.0.30"}],
  "probers": [
    {"type": "udp", "ports": [11211], "protocol": "memcached_stats"}
  ]
}
```

The `STAT version` line is captured as `MemcachedVersion`:

```json
{
  "signals": [{"MemcachedVersion": "1.6.24"}]
}
```

Probe a STUN server to learn the observed public address of the probing host:

```json
{
  "targets": [{"DnsName": "stun.l.google.com"}],
  "probers": [
    {"type": "udp", "ports": [19302], "protocol": "stun_binding"}
  ]
}
```

The parsed `XOR-MAPPED-ADDRESS` attribute lands as `StunMappedAddress`:

```json
{
  "signals": [{"StunMappedAddress": "203.0.113.42:54321"}]
}
```

## See also

- [Scenario schema](../reference/scenario.md) — full prober configuration reference.
- [Probe index](index.md) — pointers to every prober.
- [Discover CLI](../discover/cli.md#choosing-probers) — `--probe udp --udp-protocol <protocol>` runs it from the command line.
