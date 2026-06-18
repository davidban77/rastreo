# rastreo — Enrichment-aware Network Discovery

rastreo probes a network across TCP, UDP, HTTP, DNS, SNMP, and ARP, fuses OUI vendor data with active fingerprints into a deduplicated, classified `DeviceRecord`, and emits each record as a Kafka event (or NDJSON / CSV file, or stdout). Reconciliation into NetBox, Nautobot, or Infrahub is performed by independent topic consumers — out of core scope.

The **core library is the product**. The CLI and HTTP server are delivery mechanisms built on top of it.

## Workspace Structure

This is a Cargo workspace with three crates:

- **rastreo-core** — library crate: all domain logic (probers, fusion, classification, encoders, sinks).
- **rastreo** — binary crate: CLI (thin layer over core, clap + YAML config).
- **rastreo-server** — binary crate: HTTP API control plane (axum).

No business logic lives outside `rastreo-core`. If the CLI or server needs new behavior, it goes in core.

Each crate has its own `CLAUDE.md` with module layout, patterns, and conventions.

## Agent Workflow

Agent definitions and workflow rules live in the user's personal `~/.claude/` directory (agents, rules, skills). The orchestration rule at `~/.claude/rules/orchestration.md` defines the full pipeline. All code changes flow through it: implementer → reviewer + UAT + doc, on a feature branch, with the orchestrator owning git.

## Coding Conventions

- **Error handling**: `thiserror` in `rastreo-core`, `anyhow` in CLI and server. Never `unwrap()` in library code. `expect()` only with a clear message for truly unrecoverable cases.
- **Allocations**: minimize per-event allocations on hot paths. Pre-build invariant strings, reuse buffers, write into caller-provided `Vec<u8>`.
- **Testing**: every prober, encoder, and sink gets a unit test. Deterministic seeds for any randomized component. Tests in `#[cfg(test)] mod tests` within the same file; integration tests under `<crate>/tests/`.
- **Naming**: snake_case for modules/functions, PascalCase for types/traits. No abbreviations except widely understood ones (`tcp`, `udp`, `dns`, `snmp`, `arp`, `oui`).
- **Formatting**: `cargo fmt` before every commit. `cargo clippy -- -D warnings` must pass.
- **Docs**: public items in `rastreo-core` should carry a `///` doc comment when the name alone is not self-explanatory. Default to no comment when the signature is the doc.

## Quality Gates

Every commit must pass:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## How to Build

```bash
cargo build --workspace                                                # debug build
cargo build --release --target x86_64-unknown-linux-musl -p rastreo    # static musl binary
```

## Architecture

The headline choices are a Cargo workspace for parallel compilation and clean dep isolation, trait objects (`Box<dyn Trait>`) for probers / encoders / sinks so new implementations slot in without changing dispatch, YAML for all scenario configuration with CLI flags and env vars overriding, and a tokio-first runtime shared by the CLI and the server.

## Extension Points

To add a prober, encoder, or sink: implement the matching trait in `rastreo-core`, register the implementation in its factory, add unit tests with deterministic inputs, and update the per-crate `CLAUDE.md`. Skill guides under `.claude/skills/` (add-prober, add-encoder, add-sink) will document the exact steps.
