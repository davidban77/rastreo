---
description: Reference for each prober. rastreo ships the TCP-connect, HTTP, DNS, reverse DNS, UDP, SNMP, ARP, NDP, SSH, ICMP, and TLS probers, each with its own configuration schema, observable signals, and build feature.
---

# Probe

This section is the per-prober reference. Each prober has its own configuration, its own observable signals, and its own timing semantics. Eleven probers ship today — TCP-connect for reachability, HTTP for `Server:` banner fingerprinting, DNS for authoritative-server discovery, reverse DNS for attaching a hostname to an unknown IP, UDP for protocol-specific fingerprints over NTP, SIP, memcached, and STUN, SNMP for MIB-II system-group vendor and identity fingerprinting, ARP + NDP for link-layer MAC-address discovery on IPv4 and IPv6 subnets respectively, SSH for banner and host-key identity fingerprinting, ICMP for baseline reachability plus a canonical RTT measurement, and TLS for capturing the server certificate's Subject and Subject Alternative Names as an identity fingerprint.

| Prober | Signal | Build feature |
|---|---|---|
| [TCP-connect](../reference/scenario.md#probers) | `OpenPort(<port>)` | always available |
| [HTTP](http.md) | `HttpBanner(<value>)` | `--features http` (bundled with release binaries) |
| [DNS](dns.md) | `DnsHost(<value>)` | always available |
| [Reverse DNS](reverse-dns.md) | `ReverseDnsName(<hostname>)` | always available |
| [UDP](udp.md) | `NtpBanner`, `SipUserAgent`, `MemcachedVersion`, `StunMappedAddress` | always available |
| [SNMP](snmp.md) | `SnmpSysDescr`, `SnmpSysObjectId`, `SnmpSysName` | `--features snmp` (bundled with release binaries) |
| [ARP](arp.md) | `Mac(<address>)` (IPv4 targets) | `--features arp` (bundled with release binaries; requires `CAP_NET_RAW`) |
| [NDP](ndp.md) | `Mac(<address>)` (IPv6 targets) | `--features ndp` (bundled with release binaries; requires `CAP_NET_RAW`) |
| [SSH](ssh.md) | `SshBanner(<value>)`, `SshHostKey(<value>)` | `--features ssh` (bundled with release binaries) |
| [ICMP](icmp.md) | `IcmpEchoRttMicros(<value>)` | `--features icmp` (bundled with release binaries; unprivileged where `SOCK_DGRAM` ICMP is permitted, `CAP_NET_RAW` otherwise) |
| [TLS](tls.md) | `TlsSubject(<value>)`, `TlsSanName(<value>)` | `--features tls` (bundled with release binaries) |

Topics covered here include the configuration schema, observable signal shape, timeout semantics, and known limits for each prober. Where a prober has nontrivial tuning (HTTP TLS modes, DNS transport selection, UDP protocol selection, SNMP credentials, ARP or NDP interface selection, reverse DNS resolver selection), that surface lives on the prober's page rather than scattered across the scenario reference.
