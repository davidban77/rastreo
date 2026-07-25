---
description: Domain terms used across rastreo's docs and source — networking protocols, discovery-pipeline stages, record types, and integration vocabulary.
---

# Glossary

This glossary defines the terms used across rastreo's documentation and source. Networking acronyms are also expanded as hover tooltips throughout the site; the entries below add a sentence or two of context that does not fit in a tooltip.

## Networking and protocols

**OUI** — Organisationally Unique Identifier. The first 24 bits of a MAC address that identify the manufacturer that assigned it. The OUI enrichment fuser looks up this prefix to attach a `manufacturer` name to a `DeviceRecord`.

**MAC address** — Media Access Control address. The link-layer hardware identifier on an interface, usually 48 bits, written as six colon-separated hex octets (`AA:BB:CC:DD:EE:FF`). When a probe reveals a MAC, the fuser uses it as the device's identity key instead of the IP.

**CIDR** — Classless Inter-Domain Routing. The notation for an IP prefix, written as `<address>/<prefix-length>` such as `10.0.0.0/24`. rastreo accepts CIDR blocks as `--target` values and expands them into the list of host addresses to probe.

**DNS** — Domain Name System. The protocol that maps a hostname to one or more IP addresses. rastreo accepts DNS names as targets, and the DNS prober can query a resolver for records such as `A`, `AAAA`, and `MX`. See [DNS](../probe/dns.md).

**PTR record** — The reverse DNS record that maps an IP address back to a hostname. The reverse DNS prober issues a PTR lookup and emits the result as a `ReverseDnsName` signal. See [Reverse DNS](../probe/reverse-dns.md).

**ARP** — Address Resolution Protocol. The link-layer protocol that maps an IPv4 address to a MAC address inside one broadcast domain. rastreo's ARP prober sends requests on a chosen interface to learn a target's MAC. See [ARP](../probe/arp.md).

**NDP** — Neighbor Discovery Protocol. The IPv6 counterpart to ARP, used to map an IPv6 address to a MAC address on the local link. rastreo's NDP prober learns a target's MAC the way the ARP prober does for IPv4. See [NDP](../probe/ndp.md).

**ICMP** — Internet Control Message Protocol. The protocol behind `ping`, used to check whether a host is reachable. rastreo's ICMP prober measures the round-trip time and emits it as an `IcmpEchoRttMicros` signal. See [ICMP](../probe/icmp.md).

**RTT** — Round-Trip Time. The time a packet takes to reach a target and return. The ICMP prober records the minimum RTT it measured, in microseconds.

**SNMP** — Simple Network Management Protocol. A device-management protocol used to read vendor, model, and interface data from network gear. rastreo's SNMP prober reads MIB-II system-group values for fingerprinting. See [SNMP](../probe/snmp.md).

**OID** — Object Identifier. The dotted-number address of one value in an SNMP MIB, such as `1.3.6.1.2.1.1.1.0` for the system description. rastreo reads a small set of OIDs and can match a device's `sysObjectID` OID to a model.

**MIB** — Management Information Base. The tree of values an SNMP agent exposes, each addressed by an OID. rastreo reads the MIB-II system group and can enrich records from a `sysObjectID` lookup table. See [Enrichment](../discover/enrichment.md).

**USM** — User-based Security Model. The SNMPv3 scheme that authenticates and encrypts requests with a username, an authentication key, and a privacy key. rastreo's SNMP prober accepts USM credentials for v3 targets.

**LLDP** — Link Layer Discovery Protocol. The vendor-neutral protocol by which a device advertises its identity and its directly connected neighbors. rastreo reads LLDP neighbor tables to build topology links. See [LLDP](../probe/lldp.md).

**chassis-id** — The stable identifier a device advertises for itself over LLDP, usually a MAC address. rastreo pairs the chassis-ids of two neighbors to form and deduplicate a topology `LinkRecord`.

**gNMI** — gRPC Network Management Interface. A modern streaming protocol for reading and subscribing to device state and configuration. rastreo's gNMI prober reads a device's supported YANG models and selected state. See [gNMI](../probe/gnmi.md).

**YANG** — A data-modeling language that defines the structure of a device's configuration and operational state. rastreo reports which YANG models a gNMI target advertises, so downstream collectors can plan telemetry subscriptions.

**SSH** — Secure Shell. The protocol for encrypted remote login to network and server hosts. rastreo's SSH prober reads the server banner and host key for fingerprinting, and never authenticates. See [SSH](../probe/ssh.md).

**TLS** — Transport Layer Security. The protocol that encrypts connections such as HTTPS. rastreo's TLS prober completes a handshake and reads the server certificate's subject and names as an identity fingerprint, accepting any certificate. See [TLS](../probe/tls.md).

**SNI** — Server Name Indication. The hostname a TLS client sends so a server holding several certificates can present the right one. rastreo does not need SNI to fingerprint a certificate, since it reads whatever the server offers.

**SVI** — Switched Virtual Interface. A virtual IP interface on a switch that represents a whole VLAN rather than one physical port. An SVI often carries a switch's management IP, which is the address rastreo probes.

**VRRP** — Virtual Router Redundancy Protocol. A protocol that lets several routers share one virtual IP for gateway failover. rastreo tags an alternate IP that looks like such a shared address (VRRP, HSRP, or CARP) with a matching role hint on the `DeviceRecord`.

**CAP_NET_RAW**{ #cap-net-raw } — A Linux capability that lets a process open raw network sockets — the low-level sockets that send hand-built packets — without running as the root user. The ARP, NDP, and ICMP probers need it because they craft packets the operating system does not build for them. rastreo's published image grants it to the binary, so the probers work under a non-root container. See [ARP · Runtime privilege](../probe/arp.md#runtime-privilege).

## Discovery pipeline

**Probe** — A single action that sends traffic to one target and observes the reply. Each `(target, port)` pair, or each protocol exchange, is one probe.

**Signal**{ #signal } — One observed fact derived from a probe, such as an open port, a MAC address, or a certificate subject. The fuser collects signals across every prober that touched a device and stores them on the `DeviceRecord`. rastreo defines many signal kinds; each prober's page lists the ones it emits.

**Prober**{ #prober } — A component that runs probes for one protocol. rastreo includes probers for TCP, HTTP, DNS, SNMP, SSH, and more; see [Probe](../probe/index.md) for the current set. Probers are pluggable, so a new one slots in without changing the rest of the pipeline.

**Scheduler** — The runtime that paces probes under two limits. `max_concurrent`, set by `--concurrency`, caps how many probes run at once; `probe_rate`, set by `--rate`, caps how many start each second. When `probe_rate` is unset, probes start as fast as the concurrency cap allows.

**Fuser**{ #fuser } — The stage that groups a device's signals into one `DeviceRecord` and assigns a confidence score. rastreo includes four fusers: `direct`, `oui_enrichment`, `mib_enrichment`, and `identity`. See [Enrichment](../discover/enrichment.md) and [Identity](../discover/identity.md).

**Identity correlation** — The step where the identity fuser merges several records that describe the same physical device, matching on shared values such as MAC, SNMP system name, SSH host key, TLS subject, or reverse DNS name. The extra addresses become `alt_ips` on the surviving record. See [Identity](../discover/identity.md).

**Classifier** — The stage that assigns canonical `platform`, `os_version`, and `role` values to a `DeviceRecord` from its signals, using a table of rules. rastreo includes default rules and lets you add your own. See [Classification](../discover/classification.md).

**Encoder** — The stage that serialises a record to bytes. rastreo encodes records as NDJSON: one JSON object per line.

**Sink**{ #sink } — The destination that writes encoded records. rastreo includes five sinks: `stdout`, `file`, `memory`, `kafka`, and `nats`. See [Sinks](../discover/sinks.md).

**Scenario**{ #scenario } — The configuration object that drives one scan: the targets, the probers, and an optional fuser, classifier, encoder, and sink. The CLI builds a scenario from flags, the HTTP API accepts one as the JSON body of `POST /scans`, and a YAML file describes one on disk. See [Scenario schema](scenario.md).

**Catalog** — A directory of reusable scenario files that you reference by name with `@<name>` instead of a full path. rastreo searches the catalog directories in a fixed order and resolves the name to a file. See [Catalog](../discover/catalog.md).

**Dry-run** — A mode that resolves the targets and prints the scan plan without sending any probe or opening a sink. Use `discover --dry-run` to check a scenario before running it for real. See [Dry-run mode](../discover/cli.md#dry-run-mode).

**Checkpoint** — A small file that records how far a scan reached, so a long scan that is interrupted can continue later. rastreo writes it at a target-count cadence when you pass `--checkpoint`. See [Checkpoints](../discover/cli.md#checkpoints).

**Resume** — Continuing an interrupted scan from its checkpoint: skip the targets already written and probe the rest. rastreo refuses to resume when the target list or the destination changed. See [Resuming](../discover/cli.md#resuming).

**Resume fingerprint** — A hash stored in the checkpoint that ties it to one target list and one destination. rastreo compares the fingerprint before resuming and refuses when either changed, so a resumed run cannot append to the wrong destination.

**Probe fault**{ #probe-fault } — A result where the probe itself broke and could read nothing, such as a missing `CAP_NET_RAW` capability or an ARP probe aimed at an IPv6 target. A fault is recorded as data and counted in the summary, unlike a silent target that simply did not answer. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults).

**Second stream** — An extra output stream the pipeline emits beside the `DeviceRecord` stream, carrying `LinkRecord` topology edges or `CollectionProfileRecord` entries. Each stream is keyed separately at the sink and versioned on its own. See [Topology](../discover/topology.md).

## Records and formats

**DeviceRecord** — The deduplicated, classified output of the discovery pipeline: one record per discovered device. Fields include `identity_key`, `mgmt_ip`, `mac`, `manufacturer`, `platform`, `role`, `confidence`, `last_seen`, `signals`, and `probe_kinds`. See [DeviceRecord schema](schema/device-record.md).

**LinkRecord** — A topology edge between two devices, built from LLDP neighbor data and keyed by the unordered pair of chassis-ids. It travels on a second stream and maps to NetBox cables and Nautobot interface connections. See [Topology](../discover/topology.md).

**CollectionProfileRecord** — A description of how a downstream collector can stream telemetry from one gNMI endpoint, listing the device's advertised models and suggested subscriptions. rastreo emits one per gNMI endpoint that returned capability data, on a second stream. See [Collection profiles](../discover/collection-profile.md).

**Identity key** — The stable string used to deduplicate `DeviceRecord` events. The fuser picks `mac:<address>` when a MAC is known, otherwise `ip:<address>`, lowercased. Downstream consumers use it as the primary key when reconciling into a source of truth.

**Confidence** — A score in `[0.0, 1.0]` summarising how strong the evidence for a record is. The default fuser computes `baseline + signals_observed × per_signal`, clamped at `1.0`, so more signals raise confidence.

**NDJSON** — Newline-Delimited JSON. One JSON object per line, separated by `\n`. NDJSON is rastreo's wire format: every encoder writes it and every sink emits it, so a consumer can parse one line at a time without buffering the whole stream.

**ULID** — Universally Unique Lexicographically Sortable Identifier. A 26-character identifier that sorts by creation time. Each scan gets a ULID `scan_id`, so consumers can order and correlate the records from one scan.

## Integration and delivery

**Source of truth**{ #source-of-truth } (SoT) — The system of record for network inventory: NetBox, Nautobot, or Infrahub. rastreo does not write to the SoT directly; downstream consumers read the record stream and update the SoT on their own schedule. See [Source of truth](../integrate/source-of-truth.md).

**NetBox / Nautobot / Infrahub** — The three source-of-truth systems rastreo targets. Each consumes the same NDJSON `DeviceRecord` shape and owns its own merge and state logic.

**Kafka** — A distributed log used as the main delivery transport. The Kafka sink publishes each record to a topic that downstream consumers read. See [Kafka](../integrate/kafka.md).

**NATS / JetStream** — A lightweight messaging system; JetStream is its persistence layer that stores messages for at-least-once delivery. rastreo's NATS sink publishes each record to a JetStream subject. See [NATS](../integrate/nats.md).

**Dead-letter queue** (DLQ) — A separate destination for records that failed primary delivery. rastreo wraps a failed record in an envelope of `x-rastreo-*` headers plus the unmodified record, so you can triage failures without parsing the payload. See [DlqEnvelope schema](schema/dlq-envelope.md).

**OTLP** — OpenTelemetry Protocol. The standard transport for exporting traces, metrics, and logs to an observability backend. `rastreo-server` can export its own telemetry over OTLP. See [OTLP](otlp.md).

**NDJSON wire format** — The contract between rastreo and downstream consumers: one `DeviceRecord` per line, with JSON keys that stay stable across the CLI and HTTP outputs. See [Integrate](../integrate/index.md).

## See also

- [CLI reference](cli.md) — every flag for both binaries.
- [Scenario schema](scenario.md) — the JSON shape these terms appear in.
- [First scan](../get-started/first-scan.md) — see these concepts running end-to-end.
