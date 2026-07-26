# rastreo — The CLI

This is the binary crate. It is a **thin layer** over `rastreo-core`. No business logic lives here.

## Responsibility

1. Parse CLI arguments using `clap` (derive API).
2. Load the YAML scenario file (file path or `@name` from a catalog directory).
3. Merge CLI flag overrides onto the loaded config.
4. Validate the merged config.
5. Instantiate probers, encoders, and sinks via `rastreo-core` factories.
6. Hand control to the `rastreo-core` runner.
7. Handle graceful shutdown on SIGINT / SIGTERM.

If you are tempted to put probing, fusion, classification, encoding, or sink logic here — stop. It belongs in `rastreo-core`.

## Module Layout

```
src/
├── main.rs   ← entrypoint: tokio::main, tracing init, ctrl-c handler
└── cli/
    ├── mod.rs       ← Cli struct + Command enum + clap dispatch
    ├── catalog.rs   ← @name resolution across catalog directories (feature = "config")
    ├── validate.rs  ← validate subcommand handler: offline config-shape + sink-config lint (feature = "config")
    ├── discover.rs  ← discover subcommand handler + arg parsing
    └── output/      ← human-facing terminal output, all of it on stderr
        ├── progress.rs  ← live progress line (TTY in-place redraw, plain lines otherwise)
        ├── summary.rs   ← end-of-scan summary line
        └── hints.rs     ← runtime probe hints, scan-error hints, feature-gate hints
```

## CLI Surface

| Subcommand      | Purpose                                                            |
|-----------------|--------------------------------------------------------------------|
| `discover`      | Probe one or more targets and emit DeviceRecord events to a sink   |
| `catalog list`  | List every `@name` catalog scenario with its resolved path (feature = "config") |
| `validate`      | Lint a scenario file offline: config shape + per-scenario sink config, no probing or connecting (feature = "config") |

### `rastreo discover`

Flags: `--target` (repeatable; IP / CIDR / range / DNS), `--port` (repeatable or comma-separated), `--file` / `-f` (YAML scenario file path or `@name` catalog reference; mutually exclusive with `--target` / `--port`), `--sink` (`stdout` | `file` | `kafka` with `--features kafka` | `nats` with `--features nats`), `--output` (file sink path), `--brokers` and `--topic` (kafka sink), `--concurrency` (default 64), `--timeout-ms` (default 1000), `--dry-run` (resolve targets and print the plan; no probes, no sink IO), `--dry-run-format` (`text` default or `json`; only meaningful with `--dry-run` — `json` emits an array of `DiscoveryPlan` objects, one per scenario), the global `-v` / `-q` verbosity flags, and the global `--log-format` flag (`text` or `json`, env var `RASTREO_LOG_FORMAT`, default `text`).

### `rastreo catalog list`

Lists every catalog scenario reachable via `@name` across the search path (`RASTREO_CATALOG_DIR` colon-separated, else `$XDG_CONFIG_HOME/rastreo/catalog/` — fallback `$HOME/.config/rastreo/catalog/` — then `/etc/rastreo/catalog/`), one `@name` per line with the exact path a run would load. Names are deduped and sorted; the resolved path follows the same precedence as an `@name` reference (first directory wins, `.yml` before `.yaml`). An empty search path prints a `no catalog scenarios found (searched: ...)` line to stderr and exits 0. Gated behind the `config` feature.

### `rastreo validate`

Lints a scenario file entirely offline — no DNS resolution, no probing, no broker connection. Takes one positional `<FILE>` argument: a path or an `@name` catalog reference, resolved via the same `resolve_scenario_source` / `load_scenario_file` front-end as `discover --file` (version/kind check, secret expansion, retired-field rejection). For each scenario it merges `defaults:` and then checks a non-empty `targets` list, a non-empty `probers` list, and — when a `sink` is set — `SinkConfig::validate()` (the same offline shape check `create_sink` runs at the config boundary: kafka/nats broker-server/topic-subject/stream non-empty, `tls.ca_cert` requires `verify: true`, CA PEM parses, DLQ topic/stream non-empty). Prints `scenario '<name>' (N of M): ok` (stdout) or `... : <reason>` (stderr) per scenario, then `N scenario(s) validated: all valid` on success. Exit 0 when all scenarios are valid, exit 1 when any is invalid or the file fails to parse. Gated behind the `config` feature. A `type: kafka` / `type: nats` sink only parses when the binary carries the matching build feature.

Two modes:

- **Flag-driven** (`--target` + `--port`): builds an in-memory `DiscoverScenarioConfig` that runs a single TCP-connect prober against the listed targets. Suitable for quick reachability sweeps.
- **YAML-driven** (`--file`): loads a `ScenarioFile` from disk, validates `version: 1` + `kind: discovery`, and executes each entry sequentially. This is the only CLI path to the HTTP, DNS, Reverse DNS, UDP, SNMP, ARP, NDP, SSH, ICMP, TLS, gNMI, and OUI-enrichment surface. Sink and per-scenario knob overrides via `--sink`, `--concurrency`, `--timeout-ms` follow the precedence rule below (CLI > YAML).

Catalog references (`@name`) resolve `--file` to a scenario file in `RASTREO_CATALOG_DIR` (colon-separated PATH-style) if set, otherwise `$XDG_CONFIG_HOME/rastreo/catalog/` (fallback `$HOME/.config/rastreo/catalog/`) then `/etc/rastreo/catalog/`. First hit wins, `.yml` before `.yaml` within each directory. Names may not contain path separators.

Output: one NDJSON `DeviceRecord` per line on the chosen sink. Tracing logs always go to stderr so a stdout sink stays clean for downstream `jq` / NDJSON consumers.

## Error Handling

- Use `anyhow` for top-level error reporting. The CLI is the error-presentation layer.
- Map `rastreo-core` `RastreoError` variants to user-friendly messages.
- Exit code 1 on any error. Print the error to stderr.
- Do not panic. Catch errors at the top level and format them.

## Config Precedence

From lowest to highest priority:

1. YAML scenario file.
2. CLI flags.

## Dependencies

| Crate                 | Purpose                                  |
|-----------------------|------------------------------------------|
| `rastreo-core`        | All discovery and emission logic         |
| `clap`                | CLI argument parsing (derive API)        |
| `anyhow`              | Top-level error handling                 |

This crate should NOT depend on `axum`, `hyper`, or any server-specific HTTP crate.
