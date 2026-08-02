---
description: The ICMP prober — sends ICMP Echo Requests (IPv4 or IPv6, chosen by target family), records the minimum round-trip time as an IcmpEchoRttMicros signal, and marks the target reachable as soon as any reply arrives.
---

# ICMP prober

The ICMP prober sends ICMP Echo Requests to any reachable IP target and records the minimum round-trip time observed — how long a packet takes to reach the target and come back. This is the same check the `ping` command runs. It speaks ICMP (RFC 792) for IPv4 targets and ICMPv6 (RFC 4443) for IPv6 targets, waits for matching Echo Replies, and emits the result as an `IcmpEchoRttMicros(<microseconds>)` signal. Downstream reconcilers receive one canonical "device is X µs away" value alongside whatever fingerprinting signals the other probers produced.

**Use it when** you want a simple "is this host up?" answer, plus how far away it is. It works across the whole network.<br>
**You get** an `IcmpEchoRttMicros` signal — the round-trip time in microseconds — for any host that replies.

ICMP is a reachability probe that works across subnets, unlike ARP or NDP which only work on the local link. Routers forward it, most endpoints answer it, and many firewalls that drop everything else still permit it. It is a good baseline probe to attach to any scenario that needs a simple "is this device up?" answer.

The prober only sends Echo Requests and matches Echo Replies. It does NOT do traceroute, TTL walks, path MTU discovery, or any other ICMP-based diagnostic. It records one number per target: the minimum RTT across the send batch.

## Configuration

Add an `icmp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "icmp"}`.

```yaml
probers:
  - type: icmp
    count: 3
    interval_ms: 200
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"icmp"`. |
| `count` | integer | no | `3` | Number of Echo Requests to send. Minimum 1, maximum 1024 — validated at construction. |
| `interval_ms` | integer | no | `200` | Milliseconds between consecutive requests. Zero means send as fast as the kernel accepts. |

The prober does not take a `ports` field. ICMP has no port concept — the packet is delivered by IP protocol number (1 for ICMPv4, 58 for ICMPv6).

## Signals emitted

| Signal | When produced |
|---|---|
| `IcmpEchoRttMicros(<value>)` | At least one Echo Reply arrived that matched the identifier and one of the sent sequence numbers. `<value>` is the minimum RTT observed across all replies, expressed in unsigned integer microseconds (µs). |

The `<value>` is always microseconds. A same-host loopback probe typically returns tens to low hundreds of µs. A LAN probe typically returns hundreds of µs to a few ms (i.e. a few thousand µs). A wide-area probe typically returns tens of ms (tens of thousands of µs). Example: `IcmpEchoRttMicros(4237)` means the fastest round-trip was 4.237 ms.

A target that returns no reply within the scenario-level `timeout_ms` budget is marked unreachable and contributes no signal. The same applies when the network reports the host or the network as unreachable: that is absence, not a probe error. Partial success — for example two of three requests answered — still marks the target reachable and reports the minimum of the observed RTTs.

## Address families

Dispatch is by target IP family:

- IPv4 targets use ICMP (protocol 1).
- IPv6 targets use ICMPv6 (protocol 58).

Both paths share the same reply-matching logic and the same 32-byte payload: an 8-byte per-call random nonce, an 8-byte little-endian send-time offset in microseconds, and a 16-byte constant marker. Replies whose payload nonce does not match the nonce chosen for the current probe call — including in-transit pings from other processes on the same host, or replies destined for a different concurrent probe — are ignored. The prober does not filter on the ICMP identifier field, because the Linux `SOCK_DGRAM` "ping socket" rewrites that field to the kernel's own ephemeral port; matching on the nonce is portable across both the unprivileged and the raw-socket paths.

Link-local IPv6 targets (`fe80::/10`) are not supported today: the prober does not set `sin6_scope_id` on the destination address, so the kernel cannot pick an outgoing interface for such targets. Use a global unicast address instead.

## Privileges

The prober prefers an unprivileged path and falls back to a privileged one only when the kernel refuses it. Both are transparent to the caller: the resulting signal is the same, and no field in the outcome reveals which socket type was used.

- **macOS**: unprivileged `SOCK_DGRAM` ICMP always works. No setup required.
- **Linux (unprivileged path)**: the prober tries `SOCK_DGRAM` with `IPPROTO_ICMP` or `IPPROTO_ICMPV6` first. The kernel permits this only when the process's group ID falls inside the range in `/proc/sys/net/ipv4/ping_group_range`. Most distributions ship this as `1 0` — an empty range — which disables the unprivileged path for every user. Widen the range with `sysctl -w net.ipv4.ping_group_range="0 2147483647"` to open it up to everyone, or set a narrower range to a specific group.
- **Linux (privileged fallback)**: when the unprivileged path is refused with a permission-denied error, the prober falls back to a `SOCK_RAW` socket, which requires the [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw) capability — a Linux permission that lets a non-root process open low-level raw sockets. If neither path is available the probe returns a `permission_denied` fault (`"icmp: raw socket unavailable: ..."`).

The release image raises [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw) in-process on startup, so the `SOCK_RAW` fallback works without widening `ping_group_range` — the same in-process mechanism the [ARP prober](arp.md#build-feature) documents in full. For the fallback to open its socket the container still needs `NET_RAW` granted at runtime — pass `--cap-add=NET_RAW` (already set on the bundled `docker-compose.yml`).

| Runtime | How to grant | Notes |
|---|---|---|
| `docker run` | `--cap-add=NET_RAW` | The bundled `docker-compose.yml` already sets this on the `rastreo-server` service. |
| Kubernetes (Helm chart) | `--set podSecurity.netRaw=true` | Off by default because Pod Security Standards `restricted` disallows capability additions. Only enable in clusters that permit it. |
| Bare metal (Linux) | `sudo setcap cap_net_raw+p target/release/rastreo` | Grants the capability to the binary itself, which raises it to effective when the fallback opens its socket. Alternatives: run under `sudo`, or widen `net.ipv4.ping_group_range` and rely on the unprivileged `SOCK_DGRAM` path. |
| Bare metal (macOS) | none needed | Unprivileged `SOCK_DGRAM` ICMP always works. |

## Build feature

The ICMP prober is gated behind the `icmp` Cargo feature. The published release binaries, the Docker image, and the Helm chart all bundle `--features icmp`, so no extra step is needed when using them. Consumers building from source must opt in:

```bash
cargo build -p rastreo --features icmp
cargo build -p rastreo-server --features icmp
```

## Example scenario

Probe a single host with the default three-packet count and 200 ms spacing, then attach an ICMP baseline alongside TCP-connect fingerprinting:

```json
{
  "targets": [{"Ip": "10.50.0.10"}],
  "probers": [
    {"type": "icmp", "count": 3, "interval_ms": 200},
    {"type": "tcp_connect", "ports": [22, 80, 443]}
  ]
}
```

A record produced against a live host contains the RTT signal alongside whatever ports were open:

```json
{
  "signals": [
    {"IcmpEchoRttMicros": 4237},
    {"OpenPort": 22},
    {"OpenPort": 80}
  ]
}
```

Send five requests spaced 50 ms apart when a scenario needs a tighter reachability read (still bounded by the scenario-level `timeout_ms` budget):

```yaml
probers:
  - type: icmp
    count: 5
    interval_ms: 50
```

## See also

- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a silent target is not a probe error.
- [ARP prober](arp.md) — IPv4 link-layer discovery. Also uses `CAP_NET_RAW`, but without an unprivileged fallback.
- [NDP prober](ndp.md) — IPv6 link-layer discovery.
- [Discover CLI](../discover/cli.md#choosing-probers) — `icmp` is in the default probe set, and `--icmp-count` sets how many requests go out.
- [Scenario schema](../reference/scenario.md#icmp) — the full `icmp` field table.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
- [Probe index](index.md) — pointers to every prober.
