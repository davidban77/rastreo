---
description: An open-source network discovery engine in Rust. Probes a network across multiple protocols, fuses OUI vendor data with active fingerprints into a deduplicated DeviceRecord, and emits each to a Kafka topic, NDJSON file, or stdout.
hide:
  - navigation
  - toc
---

<p align="center" markdown>
  ![rastreo banner](assets/rastreo-banner.png){ width="320" }
</p>

<p align="center" markdown>
  Enrichment-aware network discovery in Rust. Probes a network across TCP, UDP, HTTP, DNS, SNMP, and ARP, fuses OUI vendor data with active fingerprints into deduplicated `DeviceRecord` events, and emits each one to Kafka, an NDJSON file, or stdout. Reconciliation into NetBox, Nautobot, or Infrahub runs in independent topic consumers.
</p>

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **[Get started](get-started/index.md)**

    Install rastreo and run a first discovery scan against a local target.

-   :material-magnify-scan:{ .lg .middle } **[Discover](discover/index.md)**

    CLI flags, target syntax, scenario configuration, and sink options.

-   :material-relation-many-to-many:{ .lg .middle } **[Integrate](integrate/index.md)**

    Kafka consumers feeding NetBox, Nautobot, and Infrahub.

</div>

For the project README, the issue tracker, and contribution guidelines, see [github.com/davidban77/rastreo](https://github.com/davidban77/rastreo).
