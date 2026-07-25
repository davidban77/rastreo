---
description: Reference for each prober. rastreo ships the TCP-connect, HTTP, DNS, reverse DNS, UDP, SNMP, ARP, NDP, SSH, ICMP, TLS, gNMI, and LLDP probers, each with its own configuration schema, observable signals, and build feature.
---

# Probe

This section is the per-prober reference. A **prober** sends traffic to a target and records what it observes. Each prober speaks one protocol, emits its own [signals](../reference/glossary.md#signal), and has its own configuration and timing. Thirteen ship today.

## Which prober do I need?

Start from the question you want answered:

- **Is anything listening on this port?** → [TCP-connect](tcp-connect.md). The default first probe. Confirms a port accepts a connection.
- **Is this host up at all?** → [ICMP](icmp.md). The `ping` probe. Works across routers, unlike ARP and NDP.
- **What web server is this?** → [HTTP](http.md). Reads the `Server:` banner (`nginx`, `Apache`, `Caddy`).
- **What SSH server is this, and is it the same box as another IP?** → [SSH](ssh.md). Reads the banner and a stable host key.
- **What TLS certificate does this service present?** → [TLS](tls.md). Reads the names the certificate claims.
- **What is this IP's hardware (MAC) address?** → [ARP](arp.md) on IPv4, [NDP](ndp.md) on IPv6. Local network only.
- **What is this IP's hostname?** → [Reverse DNS](reverse-dns.md). Or [DNS](dns.md) to treat the target itself as a DNS server.
- **What UDP service answers here?** → [UDP](udp.md). Fingerprints NTP, SIP, memcached, or STUN.
- **What vendor, model, and hostname is this network device?** → [SNMP](snmp.md) for existing or managed gear, [gNMI](gnmi.md) for modern network operating systems. See the note below.
- **What is cabled to what?** → [LLDP](lldp.md), or [gNMI](gnmi.md) with `lldp: true`. Builds topology links.

!!! tip "SNMP or gNMI?"
    Both read a device's vendor, model, and hostname. Choose by the gear:

    - **[SNMP](snmp.md)** — the long-established management protocol. Almost every router, switch, printer, and UPS speaks it, often with only a shared read password. Use it on mixed or older networks.
    - **[gNMI](gnmi.md)** — the modern equivalent on current network operating systems (Nokia SR Linux, Arista EOS, Cisco IOS-XR, Juniper). It needs a username and password and returns richer structured state. Use it when the gear is modern and you have credentials.

## Every prober at a glance

| Prober | What it tells you | Signal | Build feature |
|---|---|---|---|
| [TCP-connect](tcp-connect.md) | Whether a port accepts a connection. | `OpenPort(<port>)` | always available |
| [HTTP](http.md) | The web-server software behind a port. | `OpenPort(<port>)`, `HttpBanner(<value>)` | `--features http` (bundled with release binaries) |
| [DNS](dns.md) | What names a DNS server can resolve. | `DnsHost(<value>)` | always available |
| [Reverse DNS](reverse-dns.md) | The hostname registered for an IP. | `ReverseDnsName(<hostname>)` | always available |
| [UDP](udp.md) | Which UDP service answers, and its version. | `NtpBanner`, `SipUserAgent`, `MemcachedVersion`, `StunMappedAddress` | always available |
| [SNMP](snmp.md) | A device's vendor, model, and hostname. | `SnmpSysDescr`, `SnmpSysObjectId`, `SnmpSysName` | `--features snmp` (bundled with release binaries) |
| [ARP](arp.md) | An IPv4 host's MAC (hardware) address. | `Mac(<address>)` (IPv4 targets) | `--features arp` (bundled with release binaries; requires [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw)) |
| [NDP](ndp.md) | An IPv6 host's MAC (hardware) address. | `Mac(<address>)` (IPv6 targets) | `--features ndp` (bundled with release binaries; requires [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw)) |
| [SSH](ssh.md) | The SSH server software and a stable host-key identity. | `OpenPort(<port>)`, `SshBanner(<value>)`, `SshHostKey(<value>)` | `--features ssh` (bundled with release binaries) |
| [ICMP](icmp.md) | Whether a host is up, and how far away it is. | `IcmpEchoRttMicros(<value>)` | `--features icmp` (bundled with release binaries; unprivileged where `SOCK_DGRAM` ICMP is permitted, [`CAP_NET_RAW`](../reference/glossary.md#cap-net-raw) otherwise) |
| [TLS](tls.md) | The names on a service's TLS certificate. | `OpenPort(<port>)`, `TlsSubject(<value>)`, `TlsSanName(<value>)` | `--features tls` (bundled with release binaries) |
| [gNMI](gnmi.md) | A modern device's vendor, model, and live state (needs credentials). | `GnmiVersion`, `GnmiSupportedModel`, `GnmiSupportedEncoding`, `GnmiState`; topology links with `lldp: true` (see [Topology](../discover/topology.md)) | `--features gnmi` (bundled with release binaries) |
| [LLDP](lldp.md) | A device's directly cabled neighbors (topology links). | topology links, not device signals — see [Topology](../discover/topology.md) | `--features lldp` (implies `snmp`; bundled with release binaries) |

Each page covers the configuration schema, the signal shape, timeout behavior, and known limits. Where a prober has real tuning (HTTP TLS modes, DNS transport selection, UDP protocol selection, SNMP credentials, ARP or NDP interface selection, reverse DNS resolver selection), that surface lives on the prober's page rather than in the scenario reference.

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
