---
description: Reference for each prober. rastreo currently ships the TCP-connect, HTTP, DNS, and UDP probers; SNMP and ARP are not yet implemented.
---

# Probe

This section is the per-prober reference. Each prober has its own configuration, its own observable signals, and its own timing semantics. Four probers ship today — TCP-connect for reachability, HTTP for `Server:` banner fingerprinting, DNS for authoritative-server discovery, and UDP for protocol-specific fingerprints over NTP, SIP, memcached, and STUN — and the surface here grows to cover SNMP and ARP as each one becomes available.

| Prober | Signal | Build feature |
|---|---|---|
| [TCP-connect](../reference/scenario.md#probers) | `OpenPort(<port>)` | always available |
| [HTTP](http.md) | `HttpBanner(<value>)` | `--features http` (bundled with release binaries) |
| [DNS](dns.md) | `DnsHost(<value>)` | always available |
| [UDP](udp.md) | `NtpBanner`, `SipUserAgent`, `MemcachedVersion`, `StunMappedAddress` | always available |

Topics covered here include the configuration schema, observable signal shape, timeout semantics, and known limits for each prober. Where a prober has nontrivial tuning (HTTP TLS modes, DNS transport selection, UDP protocol selection, SNMP credentials, ARP interface selection), that surface lives on the prober's page rather than scattered across the scenario reference.
