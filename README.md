# rastreo

rastreo is an enrichment-aware network discovery engine written in Rust. It probes a network across TCP, UDP, HTTP, DNS, SNMP, and ARP, fuses OUI vendor data with active fingerprints into a deduplicated, classified `DeviceRecord`, and emits each record as a Kafka event (or NDJSON / CSV file, or stdout). Reconciliation into NetBox, Nautobot, or Infrahub is performed by independent topic consumers — out of core scope.

The **core library is the product**. The CLI and HTTP server are delivery mechanisms built on top of it.

The name "rastreo" is Spanish for "tracking" or "sweeping" — a sibling to "sonda" ("sounding probe").

## Workspace Structure

This is a Cargo workspace with three crates:

- **rastreo-core** — library crate: all discovery and enrichment logic (probers, fusion, classification, encoders, sinks).
- **rastreo** — binary crate: CLI (thin layer over core, clap + YAML config).
- **rastreo-server** — binary crate: HTTP control plane (axum).

No business logic lives outside `rastreo-core`. If the CLI or server needs new behavior, it goes in core.

## Install

Build from source:

```bash
cargo install --path rastreo
```

## Library usage

The discovery engine ships as a separate crate, `rastreo-core`. Heavy dependencies (HTTP, Kafka, SNMP, ARP) are gated behind Cargo feature flags so library consumers pay only for what they enable.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and the pull request process, or open an issue on [GitHub](https://github.com/davidban77/rastreo/issues).

## License

Licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)) at your option.
