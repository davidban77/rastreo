---
description: Reference for each prober. rastreo currently ships the TCP-connect prober; UDP, HTTP, DNS, SNMP, and ARP are not yet implemented.
---

# Probe

This section is the per-prober reference. Each prober has its own configuration, its own observable signals, and its own timing semantics. rastreo currently ships the TCP-connect prober, and the surface here grows to cover UDP, HTTP, DNS, SNMP, and ARP as each one becomes available.

Topics covered here include the configuration schema, observable signal shape, timeout semantics, and known limits for each prober. Where a prober has nontrivial tuning (HTTP TLS modes, SNMP credentials, ARP interface selection), that surface lives on the prober's page rather than scattered across the scenario reference.
