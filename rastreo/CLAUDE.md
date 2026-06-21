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
    └── discover.rs  ← discover subcommand handler + arg parsing
```

## CLI Surface

| Subcommand | Purpose                                                            |
|------------|--------------------------------------------------------------------|
| `discover` | Probe one or more targets and emit DeviceRecord events to a sink   |

### `rastreo discover`

Flags: `--target` (repeatable; IP / CIDR / range / DNS), `--port` (repeatable or comma-separated), `--sink` (`stdout` | `file` | `kafka` with `--features kafka`), `--output` (file sink path), `--brokers` and `--topic` (kafka sink), `--concurrency` (default 64), `--timeout-ms` (default 1000), and the global `-v` / `-q` verbosity flags.

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
