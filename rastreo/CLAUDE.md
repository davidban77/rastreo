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
    ├── mod.rs         ← Cli struct + Command enum + clap dispatch
    ├── catalog.rs     ← @name resolution across catalog directories (feature = "config")
    ├── validate.rs    ← validate subcommand handler: offline config-shape + sink-config lint (feature = "config")
    ├── discover.rs    ← discover subcommand handler + arg parsing
    ├── probe_args.rs  ← clap ValueEnum mirrors of core prober enums + the --probe-ports value parser
    └── output/        ← human-facing terminal output, all of it on stderr
        ├── mod.rs       ← Verbosity (Quiet / Normal / Verbose) + re-exports
        ├── theme.rs     ← every colour, glyph, and escape-sequence decision; the only file allowed to call owo-colors
        ├── humanize.rs  ← duration / count / rate formatting; one home per formatter
        ├── banner.rs    ← start banner, completion banner, -v detail lines, scenario failure line, multi-scenario aggregate
        ├── progress.rs  ← live progress line (250ms TTY in-place redraw, 5s plain lines otherwise)
        ├── hints.rs     ← runtime probe hints, scan-error hints, feature-gate hints
        └── report.rs    ← plain result lines from the catalog and validate subcommands
```

## Terminal Output

All human-facing output goes to stderr; stdout carries records only. Every stderr write lives under `cli/output/` — a unit test walks `src/cli/` and fails on an `eprintln!` / `eprint!` anywhere else, so a new message cannot skip the theme and the `Verbosity` gate.

`theme.rs` owns colour. Roles are semantic (`label`, `value`, `name`, `ok`, `done`, `warn`, `err`, `sep`), never chromatic — adding a colour means adding a role, not calling `owo-colors` at the use site. Raw CSI escapes are owned there too (`theme::ERASE_LINE`). Two unit tests walk `src/` and fail if any file other than `theme.rs` mentions `owo_colors` / `if_supports_color` or embeds an `\x1b[` literal. Colour detection is entirely `owo-colors`' `supports-colors` feature (`NO_COLOR`, `CLICOLOR_FORCE`, `FORCE_COLOR`, `TERM`, TTY); there is no hand-rolled detection. Log lines share the same decision via `theme::stderr_supports_colour`, on both the plain and the OTLP build.

Glyphs come from `theme::glyphs()`, which picks the Unicode or ASCII table once per process from `RASTREO_ASCII` and the locale vars, so a terminal that cannot render `▶` still gets a readable banner.

`humanize.rs` is the single home for each formatter. The progress line and the completion banner both call `humanize::duration`, and a test in `output/mod.rs` pins that they agree on a fixed elapsed.

`Verbosity` gates the chrome: `Quiet` prints nothing on a successful run, `Normal` prints banners plus progress plus hints, `Verbose` adds the per-kind detail lines. Failure lines are the one exemption — `print_failed` takes no `Verbosity` because `-q` suppresses status output, not failures. The completion glyph turns yellow only on a scan-level problem (cancellation, quarantined records, a failed scenario in the multi-scenario aggregate) — never on probe faults, which are expected data on any real scan and are reported as `faults:`. The aggregate banner labels how many scenarios actually completed, so an interrupted or partly-failed file never reads as a clean run.

Integration tests build their command with `tests/common::rastreo()`, which scrubs every env var the binary reads (verbosity, locale, colour, catalog, OTLP) so a golden never inherits the developer's shell.

## CLI Surface

| Subcommand      | Purpose                                                            |
|-----------------|--------------------------------------------------------------------|
| `discover`      | Probe one or more targets and emit DeviceRecord events to a sink   |
| `catalog list`  | List every `@name` catalog scenario with its resolved path (feature = "config") |
| `validate`      | Lint a scenario file offline: config shape + per-scenario sink config, no probing or connecting (feature = "config") |

### `rastreo discover`

Flags: `--target` (repeatable; IP / CIDR / range / DNS), `--probe` (repeatable or comma-separated probe-kind names), `--port` (repeatable or comma-separated), `--probe-ports` (`<kind>=<port>[,<port>]`, repeatable), the per-prober parameters (`--udp-protocol`, `--dns-query`, `--dns-query-type`, `--snmp-community` (parsed into core's redacting `Community`, so a `{args:?}` render can never leak it; also read from env `RASTREO_SNMP_COMMUNITY`, and an empty value from either source means absent), `--snmp-version`, `--http-path`, `--icmp-count`, `--interface`), `--file` / `-f` (YAML scenario file path or `@name` catalog reference; mutually exclusive with every flag-driven scan argument), `--sink` (`stdout` | `file` | `kafka` with `--features kafka` | `nats` with `--features nats`), `--output` (file sink path), `--brokers` and `--topic` (kafka sink), `--concurrency` (default 64), `--timeout-ms` (default 1000), `--dry-run` (resolve targets and print the plan; no probes, no sink IO), `--dry-run-format` (`text` default or `json`; only meaningful with `--dry-run` — `json` emits an array of `DiscoveryPlan` objects, one per scenario), the global `-v` / `-q` verbosity flags, and the global `--log-format` flag (`text` or `json`, env var `RASTREO_LOG_FORMAT`, default `text`).

Probe selection is core's, not the CLI's. `discover.rs` parses `--probe` with `parse_probe_selection` (an absent flag is spelled `default`, so the two paths cannot diverge), runs the result through `apply_runnability_filter` with `IcmpProber::is_runnable` as the only precondition today, then calls `expand_probe_selection` with a `ProbeSelectionOptions` built from the per-prober flags. Selection errors come back as typed `ConfigError` variants and are matched by variant, never by string: `ProbeKindNotCompiled` gets the rebuild hint, `ProbeKindMissingParam` gets a hint naming the CLI flag core deliberately does not know about. A `--probe-ports` key naming a kind this build lacks is refused by `reject_uncompiled_probe_ports` with the same `ProbeKindNotCompiled` error `--probe <kind>` raises, so both routes give the same exit code and the same rebuild hint.

`probe_is_runnable` delegates to `runnability_check`, which returns the per-kind precondition as an `Option<fn() -> bool>` so a unit test can assert the ICMP arm exists rather than only that the filter is called. **Known gap**: the `_ => None` arm declares every other kind runnable, so when core grows a second precondition kind (ARP/NDP needing `CAP_NET_RAW` is the likely next one) the CLI will silently claim it is runnable and no test fails. `ProbeKind` is `#[non_exhaustive]`, so the wildcard cannot be removed. Closing it needs `has_runnability_precondition` made `pub` in `rastreo-core::prober::selection` plus a parity test walking `ProbeKind::all()` — a public-surface change on a core module, so it lands as its own architectural change, not as a drive-by.

Stderr notes accompany a flag-driven scan, all pure functions returning `Vec<String>` so they are unit-testable without capturing output. One rule governs them: **a flag whose only consumer is a kind absent from the final selection produces a note naming the kind and the flag that would select it.** `parameter_flags` is the single table — one `ParameterFlag { flag, consumers, supplied }` per per-prober parameter plus one synthesized per `--probe-ports` key — and `unused_parameter_notes` applies the predicate over it. Two tests keep the class closed: one walks `DiscoverArgs::command().get_arguments()` and fails when a per-prober argument is missing from the table, the other walks the table and asserts every entry yields its note. `--port` keeps two bespoke notes instead (given without `--probe`, naming which selected probers read it; and reaching no port-taking prober at all) because its remedy is `--probe-ports`, not `--probe`. A defaulted kind the runnability filter dropped gets its own note.

`probe_args.rs` holds `UdpProtocolArg` / `DnsQueryTypeArg` / `SnmpVersionArg` — thin `clap::ValueEnum` mirrors of the core enums with `From` impls, because core cannot depend on clap. `--probe` itself stays a `Vec<String>` rather than a `ValueEnum`, so a kind name that is valid but not compiled into this build reports its missing Cargo feature instead of clap's generic "invalid value", which would be indistinguishable from a typo. `PROBE_LONG_HELP` carries the kind list that a `ValueEnum` would have given completions for.

### `rastreo catalog list`

Lists every catalog scenario reachable via `@name` across the search path (`RASTREO_CATALOG_DIR` colon-separated, else `$XDG_CONFIG_HOME/rastreo/catalog/` — fallback `$HOME/.config/rastreo/catalog/` — then `/etc/rastreo/catalog/`), one `@name` per line with the exact path a run would load. Names are deduped and sorted; the resolved path follows the same precedence as an `@name` reference (first directory wins, `.yml` before `.yaml`). An empty search path prints a `no catalog scenarios found (searched: ...)` line to stderr and exits 0. Gated behind the `config` feature.

### `rastreo validate`

Lints a scenario file entirely offline — no DNS resolution, no probing, no broker connection. Takes one positional `<FILE>` argument: a path or an `@name` catalog reference, resolved via the same `resolve_scenario_source` / `load_scenario_file` front-end as `discover --file` (version/kind check, secret expansion, retired-field rejection). For each scenario it merges `defaults:` and then checks a non-empty `targets` list, a non-empty `probers` list, and — when a `sink` is set — `SinkConfig::validate()` (the same offline shape check `create_sink` runs at the config boundary: kafka/nats broker-server/topic-subject/stream non-empty, `tls.ca_cert` requires `verify: true`, CA PEM parses, DLQ topic/stream non-empty). Prints `scenario '<name>' (N of M): ok` (stdout) or `... : <reason>` (stderr) per scenario, then `N scenario(s) validated: all valid` on success. Exit 0 when all scenarios are valid, exit 1 when any is invalid or the file fails to parse. Gated behind the `config` feature. A `type: kafka` / `type: nats` sink only parses when the binary carries the matching build feature.

Two modes:

- **Flag-driven** (`--target`, optionally `--probe`): builds an in-memory `DiscoverScenarioConfig` from core's probe-selection API. Every prober compiled into the binary is reachable this way; only the parameters no flag exposes (SNMPv3 USM credentials, gNMI auth, per-prober TLS verification, custom reverse-DNS resolvers) require YAML.
- **YAML-driven** (`--file`): loads a `ScenarioFile` from disk, validates `version: 1` + `kind: discovery`, and executes each entry sequentially. This is the path for multi-scenario runs, full per-prober configuration, and the fuser / encoder / classifier surface. Sink and per-scenario knob overrides via `--sink`, `--concurrency`, `--timeout-ms` follow the precedence rule below (CLI > YAML).

Catalog references (`@name`) resolve `--file` to a scenario file in `RASTREO_CATALOG_DIR` (colon-separated PATH-style) if set, otherwise `$XDG_CONFIG_HOME/rastreo/catalog/` (fallback `$HOME/.config/rastreo/catalog/`) then `/etc/rastreo/catalog/`. First hit wins, `.yml` before `.yaml` within each directory. Names may not contain path separators.

Output: one NDJSON `DeviceRecord` per line on the chosen sink. Banners, the progress line, hints, and tracing logs all go to stderr so a stdout sink stays clean for downstream `jq` / NDJSON consumers. An explicit `-q` / `-v` beats an ambient `RUST_LOG`; with neither flag, `RUST_LOG` beats the built-in `info` default.

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
