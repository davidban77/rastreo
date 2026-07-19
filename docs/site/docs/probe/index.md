---
description: Reference for each prober. rastreo ships the TCP-connect, HTTP, DNS, reverse DNS, UDP, SNMP, ARP, NDP, SSH, ICMP, TLS, and gNMI probers, each with its own configuration schema, observable signals, and build feature.
---

# Probe

This section is the per-prober reference. Each prober has its own configuration, its own observable signals, and its own timing semantics. Thirteen probers ship today — TCP-connect for reachability, HTTP for `Server:` banner fingerprinting, DNS for authoritative-server discovery, reverse DNS for attaching a hostname to an unknown IP, UDP for protocol-specific fingerprints over NTP, SIP, memcached, and STUN, SNMP for MIB-II system-group vendor and identity fingerprinting, ARP + NDP for link-layer MAC-address discovery on IPv4 and IPv6 subnets respectively, SSH for banner and host-key identity fingerprinting, ICMP for baseline reachability plus a canonical RTT measurement, TLS for capturing the server certificate's Subject and Subject Alternative Names as an identity fingerprint, gNMI for reading a device's supported YANG models and configured state over gRPC, and LLDP for reading a device's link-layer neighbors into topology links.

| Prober | Signal | Build feature |
|---|---|---|
| [TCP-connect](../reference/scenario.md#probers) | `OpenPort(<port>)` | always available |
| [HTTP](http.md) | `OpenPort(<port>)`, `HttpBanner(<value>)` | `--features http` (bundled with release binaries) |
| [DNS](dns.md) | `DnsHost(<value>)` | always available |
| [Reverse DNS](reverse-dns.md) | `ReverseDnsName(<hostname>)` | always available |
| [UDP](udp.md) | `NtpBanner`, `SipUserAgent`, `MemcachedVersion`, `StunMappedAddress` | always available |
| [SNMP](snmp.md) | `SnmpSysDescr`, `SnmpSysObjectId`, `SnmpSysName` | `--features snmp` (bundled with release binaries) |
| [ARP](arp.md) | `Mac(<address>)` (IPv4 targets) | `--features arp` (bundled with release binaries; requires `CAP_NET_RAW`) |
| [NDP](ndp.md) | `Mac(<address>)` (IPv6 targets) | `--features ndp` (bundled with release binaries; requires `CAP_NET_RAW`) |
| [SSH](ssh.md) | `OpenPort(<port>)`, `SshBanner(<value>)`, `SshHostKey(<value>)` | `--features ssh` (bundled with release binaries) |
| [ICMP](icmp.md) | `IcmpEchoRttMicros(<value>)` | `--features icmp` (bundled with release binaries; unprivileged where `SOCK_DGRAM` ICMP is permitted, `CAP_NET_RAW` otherwise) |
| [TLS](tls.md) | `OpenPort(<port>)`, `TlsSubject(<value>)`, `TlsSanName(<value>)` | `--features tls` (bundled with release binaries) |
| [gNMI](gnmi.md) | `GnmiVersion`, `GnmiSupportedModel`, `GnmiSupportedEncoding`, `GnmiState` | `--features gnmi` (bundled with release binaries) |
| [LLDP](lldp.md) | topology links, not device signals — see [Topology](../discover/topology.md) | `--features lldp` (implies `snmp`; bundled with release binaries) |

Topics covered here include the configuration schema, observable signal shape, timeout semantics, and known limits for each prober. Where a prober has nontrivial tuning (HTTP TLS modes, DNS transport selection, UDP protocol selection, SNMP credentials, ARP or NDP interface selection, reverse DNS resolver selection), that surface lives on the prober's page rather than scattered across the scenario reference.

## Reachable, unreachable, and probe faults

Every prober reports one of three results for a target. The rules are the same for all thirteen.

| Result | What happened | Counted as an error? |
|---|---|---|
| Reachable | The target answered. The outcome carries `reachable: true` and any signals the prober could read. | No |
| Unreachable | Nothing answered before the timeout, the connection was refused, or the network reported the host as unreachable. The outcome carries `reachable: false` and no signals. | No |
| Probe fault | The probe itself broke, so it could read no signals. Examples: a missing `CAP_NET_RAW` capability, an ARP probe aimed at an IPv6 target, or a local socket failure such as descriptor exhaustion. | Yes |

A target that does not answer is a normal discovery result. Most addresses in a healthy subnet are unused, so most probes come back unreachable. Only probe faults appear in the scan summary's `error_counts` and raise `rastreo_server_probes_total{outcome="error"}` on the server. A sweep of a mostly empty `/24` therefore reports zero probe faults.

!!! tip "Lossy links can fake an unreachable result"
    On a congested or long-distance link, a dropped UDP, SNMP, or DNS packet can make a live host report as unreachable. The scenario-level `retries` knob resends the request to recover from that loss. See [Retries on lossy links](../discover/cli.md#retries-on-lossy-links).

Each fault carries a named kind, and the summary tallies faults by kind in `error_counts`. The kinds you will see are:

- `decode_failed` — the target answered, but the reply could not be parsed.
- `auth_failed` — the target answered but rejected the credentials, such as a gNMI endpoint probed with no or wrong credentials.
- `permission_denied` — the host refused a privileged operation, such as a raw socket without `CAP_NET_RAW`.
- `dns_failed` — a name lookup the probe needed did not resolve.
- `other` — a fault with no more specific kind.

The summary also carries `first_probe_error`, an object with two fields — `kind` (the fault kind) and `detail` (a sample detail string) — for the first fault of the scan.

One rule decides the third row: **a prober reports a fault only when the probe itself broke.** If it learned anything at all, it emits what it learned. A device that answers TCP on port 443 but refuses the TLS handshake still gives you an open port, so both the [HTTP](http.md) and [TLS](tls.md) probers emit a record carrying that open port rather than a fault. Discarding it would mean finding a device and then throwing it away — on exactly the legacy gear this tool exists to inventory.

!!! note "A reply it cannot read still proves the device is there"
    One fault keeps the device instead of dropping it. When a target answers on the port but the reply cannot be decoded, the device is reachable, so rastreo keeps it. The classic case is an SNMP agent that speaks a dialect rastreo does not parse. The record carries `reachable: true` and no signals, and the summary counts the fault as `decode_failed`. A silent target is different: nothing answered, so `reachable` is `false` and no fault is recorded.

!!! info "No answer, no record — unless you ask for one"
    When no prober reaches a target, the fuser drops it and the scan emits no `DeviceRecord` for that address. Set `include_unreachable: true` on the `direct` fuser to emit one record per probed address, silent ones included. See [Fusers](../reference/scenario.md#direct).

A record's `probe_kinds` lists only the probers that actually observed the device. A prober that ran against the address but got no answer does not appear. Scan a host with `tcp_connect` on an open port and `snmp` on a port no agent listens on, and the record carries `"probe_kinds": ["TcpConnect"]` alone. Read the field as provenance: it names the probers whose answers built the record.
