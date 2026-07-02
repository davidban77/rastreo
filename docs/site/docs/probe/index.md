---
description: Reference for each prober. rastreo currently ships the TCP-connect, HTTP, DNS, UDP, and SNMP probers; ARP is not yet implemented.
---

# Probe

This section is the per-prober reference. Each prober has its own configuration, its own observable signals, and its own timing semantics. Five probers ship today — TCP-connect for reachability, HTTP for `Server:` banner fingerprinting, DNS for authoritative-server discovery, UDP for protocol-specific fingerprints over NTP, SIP, memcached, and STUN, and SNMP for MIB-II system-group vendor and identity fingerprinting — and the surface here grows to cover ARP as it becomes available.

| Prober | Signal | Build feature |
|---|---|---|
| [TCP-connect](../reference/scenario.md#probers) | `OpenPort(<port>)` | always available |
| [HTTP](http.md) | `HttpBanner(<value>)` | `--features http` (bundled with release binaries) |
| [DNS](dns.md) | `DnsHost(<value>)` | always available |
| [UDP](udp.md) | `NtpBanner`, `SipUserAgent`, `MemcachedVersion`, `StunMappedAddress` | always available |
| [SNMP](snmp.md) | `SnmpSysDescr`, `SnmpSysObjectId`, `SnmpSysName` | `--features snmp` (bundled with release binaries) |

Topics covered here include the configuration schema, observable signal shape, timeout semantics, and known limits for each prober. Where a prober has nontrivial tuning (HTTP TLS modes, DNS transport selection, UDP protocol selection, SNMP credentials, ARP interface selection), that surface lives on the prober's page rather than scattered across the scenario reference.
