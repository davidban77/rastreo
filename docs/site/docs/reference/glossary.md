---
description: Domain terms used across rastreo's docs and source code — networking acronyms, discovery-pipeline concepts, and record vocabulary.
---

# Glossary

This glossary defines the domain terms used across rastreo's documentation and source. Networking acronyms are also expanded as hover tooltips throughout the site via the abbreviation extension; the entries below add a sentence or two of context that does not fit in a tooltip.

## Networking

**OUI** — Organisationally Unique Identifier. The first 24 bits of a MAC address that map to the manufacturer that assigned it. rastreo fuses OUI vendor data with active probe signals to attach a `manufacturer` field to a `DeviceRecord` when the MAC is known.

**CIDR** — Classless Inter-Domain Routing. The notation for an IP prefix, written as `<address>/<prefix-length>` (for example, `10.0.0.0/24`). rastreo accepts CIDR blocks as `--target` values and the resolver expands them into the list of host addresses to probe. RFC 4632 defines the notation.

**NDJSON** — Newline-Delimited JSON. One JSON object per line, separated by `\n`. NDJSON is rastreo's universal wire format: every encoder writes NDJSON, every sink emits NDJSON. Downstream consumers parse one line at a time without buffering the whole stream.

**DNS** — Domain Name System. The protocol that resolves a hostname to one or more IP addresses. rastreo accepts DNS names as `--target` values and uses the system resolver (configured via `/etc/resolv.conf` on the scan host) unless the library caller installs a custom resolver.

**ARP** — Address Resolution Protocol. The link-layer mechanism that maps an IPv4 address to a MAC address inside a broadcast domain. rastreo declares an `arp` Cargo feature for a future ARP prober; the feature is not implemented today.

**SNMP** — Simple Network Management Protocol. A UDP-based device-management protocol used for vendor and interface fingerprinting. rastreo declares an `snmp` Cargo feature for a future SNMP prober; the feature is not implemented today.

**MAC address** — Media Access Control address. The link-layer hardware identifier on an interface, usually 48 bits, conventionally rendered as six colon-separated hex octets (`AA:BB:CC:DD:EE:FF`). When a probe surfaces a MAC, the fuser uses it as the `DeviceRecord` identity instead of the IP.

## Discovery

**Probe** — A single action that sends traffic to one target and observes the response. The current default prober opens a TCP connection to a list of ports; each `(target, port)` pair is one probe.

**Signal** — One observed property derived from a probe. Today the only signal kind emitted by `tcp_connect` is `OpenPort(<port>)`. The fuser collects signals across probes and uses them to compute confidence.

**Prober** — A component that performs probes of a specific protocol. Today only `tcp_connect` is available. Probers are pluggable trait objects in `rastreo-core`; new probers slot in without changes to the dispatcher.

**Scheduler** — The runtime that dispatches probes to probers under a concurrency cap. The default `BoundedScheduler` enforces `rate_limit` (the `--concurrency` flag on the CLI) as the maximum number of in-flight probes.

**Fuser** — The component that aggregates per-target signals into a `DeviceRecord` and assigns a confidence. Today only `DirectFuser` is available. The fuser groups outcomes by target IP, dedups signals, and emits one record per group.

**Encoder** — The component that serialises a `DeviceRecord` to bytes. Today only `NdjsonEncoder` is available, writing one JSON-per-line followed by `\n`.

**Sink** — The component that writes encoded bytes to a destination. The CLI today exposes `stdout`, `file`, and `kafka` (build feature). A `memory` sink also exists in the library and is used internally by `rastreo-server` to read records back into the `POST /scans` response. See [Sinks](../discover/sinks.md).

**Scenario** — The configuration object that drives a discovery scan: a list of targets, a list of probers, an optional encoder / fuser / sink, and concurrency / timeout knobs. The HTTP API accepts a scenario as the JSON body of `POST /scans`; the CLI builds an equivalent scenario in memory from flags. See [Scenario schema](scenario.md).

## Records

**DeviceRecord** — The deduplicated, classified emission of the discovery pipeline. One `DeviceRecord` per discovered device. The fields include `identity_key`, `mgmt_ip`, `mac`, `manufacturer`, `platform`, `role`, `confidence`, `last_seen`, and the full `signals` list. See [First scan](../get-started/first-scan.md) for an example.

**Identity key** — The stable string used to dedup `DeviceRecord` events. The fuser picks `mac:<address>` when a MAC signal is present, otherwise `ip:<address>`. The address portion is lowercased at construction, so a MAC `AA:BB:CC:DD:EE:FF` renders as `mac:aa:bb:cc:dd:ee:ff`. Downstream consumers use the identity key as the primary key when reconciling into a source of truth.

**Confidence** — A float in `[0.0, 1.0]` summarising how strong the fuser's classification is. The default `DirectFuser` computes `confidence_baseline + (signals_observed * confidence_per_signal)`, clamped at `1.0`. Defaults: `confidence_baseline = 0.1`, `confidence_per_signal = 0.1`.

## Integration

**Source of truth** (SoT) — The system of record for network inventory: NetBox, Nautobot, or Infrahub. rastreo does not reconcile into the SoT directly; downstream consumers subscribe to the Kafka topic (or read NDJSON files) and update the SoT on their own schedule. See [Source of truth](../integrate/source-of-truth.md).

**NetBox / Nautobot / Infrahub** — The three SoT systems rastreo targets. Each consumes the same NDJSON `DeviceRecord` shape and is responsible for its own merge / dedup / state-management logic.

**NDJSON wire format** — The contract between rastreo and downstream consumers. One `DeviceRecord` per line; the JSON keys are stable across CLI and HTTP outputs. See [Integrate](../integrate/index.md) for the contract details.

## See also

- [CLI reference](cli.md) — every flag for both binaries.
- [Scenario schema](scenario.md) — the JSON shape these terms appear in.
- [First scan](../get-started/first-scan.md) — see these concepts running end-to-end.
