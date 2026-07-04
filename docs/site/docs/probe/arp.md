---
description: The ARP prober — sends a broadcast ARP Request on the local subnet and emits the target's MAC address as a Mac signal, enriching IPv4 targets with link-layer identity for vendor lookup.
---

# ARP prober

The ARP prober speaks Address Resolution Protocol (RFC 826) against IPv4 targets on the local subnet. It sends a broadcast ARP Request as a raw Ethernet frame, waits for the ARP Reply carrying the target's hardware address, and emits it as a `Mac(<address>)` signal. That MAC is the input to the OUI vendor lookup — the first two-and-a-half octets identify the manufacturer of the network interface — and is the strongest identity signal a discovery pipeline can gather without an application-layer handshake.

ARP is a link-layer protocol. Routers do not forward ARP frames. The prober only produces results for targets on the same broadcast domain as the interface used to send. Cross-subnet targets — anything reachable through a next-hop router — time out silently. This is a fundamental property of the protocol, not a limitation of the prober.

## Configuration

Add an `arp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "arp"}` — that auto-selects the interface for each target based on the target IP's subnet.

```yaml
probers:
  - type: arp
    interface: eth0
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"arp"`. |
| `interface` | string | no | `""` (auto-select) | Name of the network interface to send from. Empty string means auto-select based on the target IP's subnet. Validated at construction — an unknown interface name errors at scenario load. |

The prober does not take a `ports` field. ARP has no TCP/UDP port concept; the frame goes directly onto the wire with ethertype `0x0806`. There is one probe per target IP.

## Interface selection

When `interface` is empty, the prober picks an interface at probe time by walking `pnet_datalink::interfaces()` and matching the target IPv4 address against each interface's assigned IPv4 subnets. If more than one interface's subnet contains the target, the one with the smallest netmask (most specific prefix) wins. This is the same longest-prefix-match logic a routing table would apply for the directly-connected route.

Two failure modes surface when auto-selection cannot find a candidate:

- No local interface has a subnet containing the target IP: the probe returns `ProbeError::Other("no local interface reaches <ip>")`. The target is not on any locally-reachable L2 segment — most commonly, it is behind a router.
- The auto-selected interface exists but has no MAC address (loopback, `lo`) or no IPv4 address of its own: the probe returns `ProbeError::Other("interface <name> has no ipv4 address")`. Configure a subnet on the interface, or pin the prober to a different interface with `interface: eth1`.

When `interface` is set explicitly and the target IP is not on that interface's subnet, the prober still sends the request on that interface. ARP Replies from off-subnet targets will not arrive; the probe times out. Set the interface explicitly only when you know the target is reachable via it.

## Degenerate case: probing your own address

Probing the IP of one of your own interfaces returns `ProbeError::Other("arp target <ip> is a local interface address")`. This is caught at probe time rather than sending a broadcast for a MAC the kernel already knows. Configure a different target if you want to inspect your own interface's MAC — most operating systems expose it via `ip link show <iface>` or `ifconfig`.

## Signals emitted

| Signal | When produced |
|---|---|
| `Mac(<address>)` | The target answered with an ARP Reply whose `sender protocol address` matches the target IP. The `sender hardware address` is formatted as a lower-case colon-separated hex string (e.g. `00:11:22:aa:bb:cc`). |

Frames on the wire that are not ARP, or that are ARP Requests, or that carry an ARP Reply for a different sender IP, are silently discarded — the receive loop keeps waiting until the target answers or the scenario-level `timeout_ms` fires. On timeout, the probe returns `ProbeError::Timeout`. There is no `Unreachable` outcome for ARP: the kernel does not surface ICMP unreachable for L2 lookups, so silent timeout is the normal failure signature — the target either does not exist on the segment or has an ARP-blocking firewall between the prober's NIC and the target.

## Build feature

The ARP prober is gated behind the `arp` Cargo feature on `rastreo-core`. Enable it explicitly when building from source:

```bash
cargo build --features arp
cargo build --release --features arp,ndp,snmp,http,kafka
```

The published Docker image and release binaries bundle the `arp` feature by default. When the feature is disabled the prober module is not compiled and the `arp` variant of `ProberConfig` is not present — scenarios that reference `type: arp` will fail to deserialize with an unknown-variant error.

The feature pulls in `pnet_datalink` and `pnet_packet` from the libpnet family, plus `ipnetwork` for subnet arithmetic. On Linux the raw send/receive path uses `AF_PACKET` sockets directly — no libpcap dependency — so musl static builds work unchanged.

The published image ships both binaries with `cap_net_raw+ep` set as a file capability, so the non-root runtime user (`UID 65532`) can open `AF_PACKET` sockets without escalating. The container still needs `NET_RAW` in its bounding set — pass `--cap-add=NET_RAW` to `docker run` (standalone) or set `capabilities.add: [NET_RAW]` on the Kubernetes container (via the Helm chart's `podSecurity.netRaw`). Without a bounding-set entry, the file capability alone is not enough.

## Runtime privilege

Opening an `AF_PACKET` socket requires `CAP_NET_RAW`. Every runtime that hosts `rastreo-server` needs to grant it to the container or process:

| Runtime | How to grant | Notes |
|---|---|---|
| `docker run` | `--cap-add=NET_RAW` | The bundled `docker-compose.yml` already sets this on the `rastreo-server` service. |
| Kubernetes (Helm chart) | `--set podSecurity.netRaw=true` | Off by default because Pod Security Standards `restricted` disallows capability additions. Only enable in clusters that permit it. |
| Bare metal | `sudo setcap cap_net_raw+ep target/release/rastreo` | Grants the capability to the binary itself. Alternatively, run under `sudo`. |

Without `CAP_NET_RAW` the probe returns `ProbeError::Other("raw socket permission denied; ARP requires CAP_NET_RAW")`. This is a hard error, not a timeout — the socket call fails immediately.

## Security notes

An ARP Request is unauthenticated by design. Anyone on the same broadcast domain can send one and get an answer. Running the prober against a network you do not own or operate is indistinguishable from network reconnaissance and may violate acceptable-use policies. Use ARP probing on labs, internal segments, and networks you administer.

The prober does not send Gratuitous ARP, does not spoof source addresses, and does not attempt ARP cache poisoning. The source MAC is the interface's real MAC; the source IP is the interface's real IPv4 address. Passive listeners can identify the probing host from any request it sends.

## Example scenario

Probe a `/29` subnet on the local lab network and gather MAC addresses for OUI vendor enrichment downstream. Interface is auto-selected per target.

```json
{
  "targets": [{"Cidr": "10.50.0.0/29"}],
  "probers": [
    {"type": "arp"}
  ]
}
```

A record produced against a live host contains a single `Mac` signal:

```json
{
  "signals": [
    {"Mac": "00:11:22:aa:bb:cc"}
  ]
}
```

Pin the prober to a specific interface when a host has multiple L2-reachable networks and only one carries the targets of interest:

```yaml
targets:
  - Cidr: 192.168.1.0/24
probers:
  - type: arp
    interface: eth1
```

## See also

- [NDP prober](ndp.md) — the IPv6 equivalent of ARP.
- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Kubernetes deployment](../deploy/kubernetes.md#podsecuritynetraw-arp-and-ndp-probers) — the `podSecurity.netRaw` toggle for granting the capability in-cluster.
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
