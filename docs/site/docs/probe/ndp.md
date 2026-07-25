---
description: The NDP prober — sends an ICMPv6 Neighbor Solicitation on the local IPv6 subnet and emits the target's MAC address as a Mac signal, enriching IPv6 targets with link-layer identity for vendor lookup.
---

# NDP prober

The NDP prober speaks the Neighbor Discovery Protocol (RFC 4861) against IPv6 targets on the local subnet. It sends an ICMPv6 Neighbor Solicitation (type 135) to the target's Solicited-Node multicast address, waits for the Neighbor Advertisement (type 136) that carries the target's link-layer address in a Target Link-Layer Address option, and emits it as a `Mac(<address>)` signal. NDP is the IPv6 replacement for ARP — same purpose, different wire format — and produces the same signal shape for downstream OUI vendor enrichment.

**Use it when** you want the hardware (MAC) address of an IPv6 host on your local network. NDP is the IPv6 version of ARP.<br>
**You get** a `Mac` signal for each host that answers on the local segment. It works only on the local network, not across routers.

NDP is a link-layer discovery protocol. Routers do not forward Neighbor Solicitation frames off the local segment. The prober only produces results for targets reachable at Layer 2 — the hardware level, reached directly without going through a router — from the sending interface. Cross-subnet IPv6 targets time out silently.

## Configuration

Add an `ndp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "ndp"}` — that auto-selects the interface based on the target IPv6 address.

```yaml
probers:
  - type: ndp
    interface: eth0
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"ndp"`. |
| `interface` | string | no | `""` (auto-select) | Name of the network interface to send from. Empty string means auto-select based on the target IP's subnet and scope. Validated at construction — an unknown interface name errors at scenario load. |

There is no `ports` field. NDP runs directly over ICMPv6; there is no port concept at Layer 3 for it. One Neighbor Solicitation is sent per target.

## Interface selection

When `interface` is empty, the prober picks an interface at probe time by walking `pnet_datalink::interfaces()` and matching the target IPv6 address against each interface's assigned IPv6 subnets:

- If the target is a link-local address (`fe80::/10`), the prober prefers an interface that itself has a link-local address, so the scope IDs match.
- If the target is a global unicast address, the prober prefers a non-loopback interface with a matching IPv6 subnet.
- Among candidates, the interface with the smallest netmask (most specific prefix) wins.

Two failure modes surface when auto-selection cannot find a candidate:

- No local interface has an IPv6 subnet containing the target: the probe returns `ProbeError::Other("no local interface reaches <ip>")`. The target is not on any locally-reachable L2 segment.
- The selected interface has no MAC or no IPv6 address: the probe returns `ProbeError::Other("interface <name> has no ipv6 address")`. Assign an IPv6 address to the interface or pin the prober to a different one.

## Solicited-Node multicast

The Neighbor Solicitation is sent to the Solicited-Node multicast address `ff02:0:0:0:0:1:ff00::/104`. The low 24 bits of the multicast address are copied verbatim from the low 24 bits of the target IPv6 address, so each target has its own solicited-node group. See [RFC 4291 §2.7.1](https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1) for the derivation. The Ethernet destination is the matching multicast MAC (`33:33:ff:xx:xx:xx`, where the low three octets are the target's low three octets). Only nodes that have registered interest in the specific low-24-bit slot process the frame — the network handles filtering, and the target reliably sees a solicitation aimed at it without every host on the segment being interrupted.

The prober computes both addresses at send time from the target IPv6; there is no static routing table or configuration to keep in sync.

??? note "ICMPv6 checksum (implementation detail)"
    The ICMPv6 checksum is computed over the ICMPv6 payload plus an IPv6 pseudo-header (source, destination, ICMPv6 length, next-header=58) per RFC 4443 §2.3. The pseudo-header binds the checksum to the exact source and destination addresses used on the wire, so a bit-flipped or spoofed IPv6 header is detected at the receiver. The prober delegates checksum computation to `pnet_packet::icmpv6::checksum`, which does the same one's-complement sum required by every ICMPv6 sender.

## Degenerate case: probing your own address

Probing an IPv6 address that is assigned to one of your interfaces returns `ProbeError::Other("ndp target <ip> is a local interface address")`. Same rationale as ARP — the kernel already knows the MAC and would not answer its own multicast.

## Signals emitted

| Signal | When produced |
|---|---|
| `Mac(<address>)` | The target answered with a Neighbor Advertisement whose target address matches, and the response included a Target Link-Layer Address option. The MAC is formatted as a lower-case colon-separated hex string. |

Advertisements that lack the Target Link-Layer Address option are silently skipped — RFC 4861 §4.4 allows the option to be omitted when the sender's link-layer address is already known to the receiver, but a probing sender by definition does not know it yet, so an option-less advertisement produces no signal. Frames that are not ICMPv6 Neighbor Advertisements, or whose target address does not match the probe, are discarded and the receive loop continues.

A target that sends no Neighbor Advertisement before the timeout is marked unreachable and contributes no signal. That is a normal discovery result, not an error: the kernel does not surface ICMP unreachable for L2 solicitations, so a silent timeout is the only shape absence can take. Probe faults still surface as errors: no local interface reaches the target, the selected interface has no IPv6 address, the target is one of your own interface addresses, the target is an IPv4 address, or the process lacks [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw) — the Linux permission that lets a non-root process open the raw socket NDP needs. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The NDP prober is gated behind the `ndp` Cargo feature on `rastreo-core`. Enable it explicitly when building from source:

```bash
cargo build --features ndp
cargo build --release --features arp,ndp,snmp,http,kafka
```

The published Docker image and release binaries bundle the `ndp` feature by default. When the feature is disabled the prober module is not compiled and the `ndp` variant of `ProberConfig` is not present — scenarios that reference `type: ndp` will fail to deserialize with an unknown-variant error.

The feature pulls in `pnet_datalink` and `pnet_packet` from the libpnet family, plus `ipnetwork` for subnet arithmetic and `socket2` for sizing the socket receive buffer. The dependency graph is identical to the `arp` feature; enabling both incurs the same transitive compile cost as enabling either alone.

!!! note "Tuning the capture buffer for very large scans"
    All probes on one interface share one receive socket. A very large scan sends a burst of replies that must not overflow the kernel capture buffer. On Linux this is handled for you: rastreo requests an 8 MiB receive buffer, and the kernel caps it at `net.core.rmem_max`. On macOS the BPF capture buffer is capped by `debug.bpf_maxbufsize`, often around 512 KiB by default. That is fine for typical scans, but a very large scan can drop replies. Raise the cap before a huge local scan:

    ```bash
    sudo sysctl -w debug.bpf_maxbufsize=4194304
    ```

How the image raises [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw) in-process — so it execs cleanly under a hardened, non-root `securityContext` — is covered once under [ARP · Build feature](arp.md#build-feature). To actually open the socket the container still needs `NET_RAW` granted at runtime — pass `--cap-add=NET_RAW` to `docker run` (standalone) or set `capabilities.add: [NET_RAW]` on the Kubernetes container (via the Helm chart's `podSecurity.netRaw`).

## Runtime privilege

Same requirement as ARP: opening the `AF_PACKET` raw socket requires `CAP_NET_RAW`. See [ARP · Runtime privilege](arp.md#runtime-privilege) for per-runtime instructions covering Docker, Kubernetes (Helm chart), and bare metal.

## Security notes

Neighbor Solicitation is unauthenticated by design. Any node on the segment can send one and receive an answer. Use NDP probing on labs, internal segments, and networks you administer.

The prober does not send Router Solicitation, does not spoof source addresses, does not attempt Neighbor Advertisement spoofing, and does not participate in Secure Neighbor Discovery (SEND, RFC 3971). The source MAC and source IPv6 are the interface's real link-layer address and one of its real IPv6 addresses.

## Example scenario

Probe a `/126` IPv6 subnet on the local lab and gather MAC addresses:

```json
{
  "targets": [{"Cidr": "2001:db8:beef::0/126"}],
  "probers": [
    {"type": "ndp"}
  ]
}
```

Probe a link-local address on a specific interface — the interface name pins the scope ID:

```yaml
targets:
  - Ip: fe80::abcd:ef12:3456:789a
probers:
  - type: ndp
    interface: eth0
```

A successful probe emits a single `Mac` signal:

```json
{
  "signals": [
    {"Mac": "02:42:ac:11:00:03"}
  ]
}
```

## See also

- [ARP prober](arp.md) — the IPv4 equivalent of NDP.
- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the NDP prober from the CLI via `--file`.
- [Kubernetes deployment](../deploy/kubernetes.md#podsecuritynetraw-arp-and-ndp-probers) — the `podSecurity.netRaw` toggle for granting the capability in-cluster.
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
