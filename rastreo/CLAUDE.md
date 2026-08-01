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
        ├── mod.rs       ← Verbosity (Quiet / Normal / Verbose) + OutputMode + re-exports
        ├── theme.rs     ← every colour, glyph, and escape-sequence decision; the only file allowed to call owo-colors
        ├── humanize.rs  ← duration / count / rate formatting; one home per formatter
        ├── banner.rs    ← start banner, completion banner, -v detail lines, scenario failure line, multi-scenario aggregate
        ├── progress.rs  ← live progress line + ProgressStyle (in-place / whole lines / silent)
        ├── hints.rs     ← runtime probe hints, scan-error hints, feature-gate hints
        ├── report.rs    ← plain result lines from the catalog and validate subcommands
        └── width.rs     ← terminal width for the table encoder, measured off stdout
```

## Terminal Output

All human-facing output goes to stderr; stdout carries records only. Every stderr write lives under `cli/output/` — a unit test walks `src/cli/` and fails on an `eprintln!` / `eprint!` anywhere else, so a new message cannot skip the theme and the `Verbosity` gate.

`theme.rs` owns colour. Roles are semantic (`label`, `value`, `name`, `ok`, `done`, `warn`, `err`, `sep`), never chromatic — adding a colour means adding a role, not calling `owo-colors` at the use site. Raw CSI escapes are owned there too (`theme::ERASE_LINE`). Two unit tests walk `src/` and fail if any file other than `theme.rs` mentions `owo_colors` / `if_supports_color` or embeds an `\x1b[` literal. Colour detection is entirely `owo-colors`' `supports-colors` feature (`NO_COLOR`, `CLICOLOR_FORCE`, `FORCE_COLOR`, `TERM`, TTY); there is no hand-rolled detection. Log lines share the same decision via `theme::stderr_supports_colour`, on both the plain and the OTLP build.

Glyphs come from `theme::glyphs()`, which picks the Unicode or ASCII table once per process from `RASTREO_ASCII` and the locale vars, so a terminal that cannot render `▶` still gets a readable banner.

`humanize.rs` is the single home for each formatter. The progress line and the completion banner both call `humanize::duration`, and a test in `output/mod.rs` pins that they agree on a fixed elapsed.

`OutputMode` is the single gate every printer in `output/` takes. It pairs the flag-derived `Verbosity` with whether the user asked for machine output (`--format json`), and answers three questions: `prints_chrome` (banners, the progress line), `prints_detail` (the `-v` per-kind lines), and `prints_advisories` (hints, notes, scenario notices). The two axes are not the same gate: `-q` silences everything, while `--format json` drops the chrome and keeps the advisories, and `-v` restores the chrome under `--format json`.

**Which side a printer belongs on**: chrome decorates a result the operator can already see; an advisory *explains an otherwise-inexplicable result*. `--format json` drops the first and keeps the second, because an advisory on stderr cannot corrupt a stdout stream and is the most useful line to read when a scan returns nothing. That puts `print_notice` (`cancelled before scenario N of M`, `<label>: no probers configured, skipping`) with the hints and notes rather than with the banners: without it a `--format json` run of a prober-less scenario is empty stdout and empty stderr, with only the exit code to go on. A new printer picks its side by that question, not by where it lives in the file. Failure lines are the one exemption — `print_failed` takes no gate because `-q` suppresses status output, not failures.

**The progress line and the record stream must never share a terminal row.** A TTY redraw is an in-place paint with no trailing newline, so it owns the row it is on; a record written to the same terminal lands on that row and fuses with it. `progress::style_for` resolves the three cases from `stderr.is_terminal()`, `stdout.is_terminal()`, and whether the scenario's effective sink writes to stdout: `Silent` when records share the terminal, `InPlace` on a terminal stderr otherwise, `Lines` (whole newline-terminated lines every 5s) when stderr is redirected. `Silent` is not a weaker `Lines`: when records share the terminal, the rows appearing *are* the progress feedback, and a progress line between them breaks up the table the operator is reading. The condition is narrower than "stdout is a TTY": `--sink file` with a terminal stdout puts no records on that stream, and the progress line is both safe and useful there. Core never learns about the progress line; the CLI reads the merged `base.sink` and decides. `tests/progress_tty.rs` drives the binary through a real `openpty` and asserts no captured row carries both a chrome needle and a record needle — a piped `Command::output()` makes the collision structurally unreachable and cannot catch this.

`width.rs` measures **stdout**, not stderr, because it is sizing the record grid rather than the banners. A redirected stdout yields no width and no knowable consumer, so the table falls back to the encoder's fixed default and stays byte-identical between runs; the layout does the clamping, so a measured width is passed through untouched. The completion glyph turns yellow only on a scan-level problem (cancellation, quarantined records, a failed scenario in the multi-scenario aggregate) — never on probe faults, which are expected data on any real scan and are reported as `faults:`. The aggregate banner labels how many scenarios actually completed, so an interrupted or partly-failed file never reads as a clean run.

Integration tests build their command with `tests/common::rastreo()`, which spawns the binary with an **empty** environment: its only inputs are the flags and the variables the test set itself. A deny-list of the variables the binary reads is not enough, because the ones that move the output are read by dependencies rather than by any rastreo source file — `anyhow` turns an exported `RUST_BACKTRACE` into 70 lines of stderr under a failure assertion, and `owo-colors`' CI detection turns `CI` / `GITHUB_ACTIONS` into ANSI on a pty run. `tests/env_isolation.rs` pins both halves of the rule: an exported `RUST_BACKTRACE` never reaches the child, and no test file outside `tests/common/mod.rs` may name the binary-path macro, since a hand-built `Command` inherits the whole shell.

## CLI Surface

| Subcommand      | Purpose                                                            |
|-----------------|--------------------------------------------------------------------|
| `discover`      | Probe one or more targets and emit DeviceRecord events to a sink   |
| `catalog list`  | List every `@name` catalog scenario with its resolved path (feature = "config") |
| `validate`      | Lint a scenario file offline: config shape + per-scenario sink config, no probing or connecting (feature = "config") |

### `rastreo discover`

Flags: `--target` (repeatable; IP / CIDR / range / DNS), `--probe` (repeatable or comma-separated probe-kind names), `--port` (repeatable or comma-separated), `--probe-ports` (`<kind>=<port>[,<port>]`, repeatable), the per-prober parameters (`--udp-protocol`, `--dns-query`, `--dns-query-type`, `--snmp-community` (parsed into core's redacting `Community`, so a `{args:?}` render can never leak it; also read from env `RASTREO_SNMP_COMMUNITY`, and an empty value from either source means absent), `--snmp-version`, `--http-path`, `--icmp-count`, `--interface`), `--file` / `-f` (YAML scenario file path or `@name` catalog reference; mutually exclusive with every flag-driven scan argument), `--format` (`table` aliased `text`, or `json` aliased `ndjson`; env var `RASTREO_FORMAT`), `--sink` (`stdout` | `file` | `kafka` with `--features kafka`; a NATS sink is reachable only through a scenario file), `--output` (file sink path), `--brokers` and `--topic` (kafka sink, both `#[cfg(feature = "kafka")]`), `--concurrency` (default 64), `--timeout-ms` (default 1000), `--dry-run` (resolve targets and print the plan; no probes, no sink IO), the global `-v` / `-q` verbosity flags, and the global `--log-format` flag (`text` or `json`, env var `RASTREO_LOG_FORMAT`, default `text`).

`--format` is `Option<OutputFormat>` with no `default_value_t`, for the same reason `--concurrency` and `--timeout-ms` are: clap cannot distinguish a typed value from a filled-in default, and a filled-in default would stomp every scenario's `encoder:` on every `--file` run.

**`--dry-run` mirrors the run, not the linter.** The plan comes from `DiscoveryPlan::new`, which refuses to build one for a scenario `DiscoverScenarioConfig::validate` rejects. Both `--file` loops therefore have the same shape: a scenario that fails is named with its reason on stderr, the remaining scenarios still get their turn, and the command ends with the same `N of M scenario(s) failed` error and exit 1. A dry-run of a three-scenario file with one bad scenario prints two plans, not zero.

`validate` is not the whole of it, because a run refuses on more than the scenario alone. The offline refusals that read the request as well as the scenario are applied by both dry-run paths too: `--checkpoint` on a multi-scenario file, and, per scenario, core's `preflight_checkpoint_request` — the resume-safety verdict and, for a fresh request, the refusal to clobber a path that already holds a checkpoint. That last one reads a file on disk rather than the config, which is precisely why the rehearsal must apply it: an operator who is told the plan is runnable and then hits `a checkpoint already exists` has been told the wrong thing.

`ensure_checkpoint_is_single_scenario` fires on `args.checkpoint`, not on `args.resume`. One checkpoint path cannot represent several scenarios' progress, so the *write* is what is unrepresentable; refusing only the resume let a multi-scenario run finish, overwrite the same path once per scenario, and hand the operator a file that `--resume` then always refuses — the scan they wanted is already gone by the time they are told. Because `--resume` and `--checkpoint-interval` both carry clap's `requires = "checkpoint"`, the one condition covers the family.

The surfaces differ in two places. `rastreo validate` never resolves targets, so an unresolvable name or an over-cap CIDR passes the linter and refuses the dry-run and the run alike — the host cap belongs to the resolver instance, not to the scenario, so the linter is right to accept it. The other is a prober-less scenario sitting *beside* a runnable one: core refuses it like any other invalid scenario and `rastreo validate` reports that refusal, while the `discover --file` loops never ask core, because `skip_prober_less_scenario` checks `probers.is_empty()` first, prints a notice, and moves on — so the scenario is omitted from the plan set, uncounted in `would run N scenarios`, and both loops carry on with the rest of the file. That divergence remains a filed bug rather than a distinction. What is no longer divergent is the file with nothing left to run: `ensure_not_every_scenario_was_skipped` ends both loops with exit 1 once `skipped == total`, because a run that probed nothing did not succeed, and a rehearsal of it is not a runnable plan. The rule is narrower than "probed nothing → exit 1" on purpose: a null result is refused only when the exit code is the *sole* channel carrying it, and a cancelled run already reports itself through the notice, the completion glyph, and `aggregate.cancelled`, while the prober-less skip said nothing at all under `-q` or `--format json`. One skip predicate and one nothing-probed guard, each called from both loops, is what keeps the run and the rehearsal from drifting apart on either.

`--dry-run-format` was retired into `--format` but is still declared, hidden and untyped, so `ensure_no_retired_flags` can refuse it by name and give the value mapping (`text` → `--format table`, `json` → `--format json`). Deleting the argument instead would leave clap answering with `unexpected argument '--dry-run-format'` and a tip pointing at `--dry-run`, which the operator already passed — a real intent reported as a typo. Retiring a flag through a hidden stub is the CLI's counterpart to core's `ensure_no_retired_fields`.

**The destination decides the record format, on whichever surface the run came in through.** `record_encoder(format, writes_to_stdout, width)` is the one rule: an explicit format wins; absent, stdout gets the table and every other destination gets NDJSON — **only stdout is read by a person**. The flag-driven path applies it against the sink it just built. The YAML path applies it in `apply_cli_overrides`, *after* the sink override, against the merged `base.sink`, and only when the scenario set no `encoder` of its own — so `--file scan.yml --sink file` drops the table default even when the file said `sink: {type: stdout}`. `writes_to_stdout` counts an absent sink as stdout because that is what core defaults to. This is the one knob where the CLI introduces a default core lacks, which is why it cannot follow `timeout_ms` / `max_concurrent` / `probe_rate` / `retries`: for all four of those the CLI default *is* core's default, so the merge mechanics were never observable. Width follows the same boundary — the CLI measures the terminal only for a `Table` it materialised itself; a `Table` that came out of the file keeps the file's `width`. An explicit `--format table` on a broker sink is refused by core's `ensure_encoder_output_fits_sink`, which also means `RASTREO_FORMAT=table` exported in a shell fails every broker-sink scenario.

**A flag naming where records go, or how to reach that destination, is an error when the effective sink cannot consume it — never a silent discard.** `sink_flags` is the one table (`--output` → `file`; `--brokers`, `--topic`, `--kafka-flush-per-record`, `--kafka-batch-threshold` → `kafka`) and `ensure_sink_flags_reach_their_sink` refuses any supplied entry whose `--sink` was not selected. Two tests keep the class closed, mirroring `parameter_flags`: one walks `DiscoverArgs::command().get_arguments()` and fails when a sink-scoped argument is missing from the table, the other walks the table and asserts every entry yields its message. The rule is `args.sink == Some(flag.sink)` and nothing weaker, including under `--file`: these flags are only ever read through `build_sink_config_for_kind`, which only runs when `--sink` is given, so `--file scan.yml --output /tmp/x` never reaches any sink and is refused rather than dropped. This is deliberately stricter than the per-prober parameters, which produce *notes* — an unused `--snmp-community` means one prober did not run, which the banner already shows, whereas a discarded `--output` means the operator believes they have a file and does not. `--brokers` and `--topic` carry `#[cfg(feature = "kafka")]` alongside the two `--kafka-*` flags: on a build with no Kafka sink they can never be satisfied, so clap rejects them by name rather than the run failing at runtime.

Probe selection is core's, not the CLI's. `discover.rs` parses `--probe` with `parse_probe_selection` (an absent flag is spelled `default`, so the two paths cannot diverge), runs the result through `apply_runnability_filter` with `IcmpProber::is_runnable` as the only precondition today, then calls `expand_probe_selection` with a `ProbeSelectionOptions` built from the per-prober flags. Selection errors come back as typed `ConfigError` variants and are matched by variant, never by string: `ProbeKindNotCompiled` gets the rebuild hint, `ProbeKindMissingParam` gets a hint naming the CLI flag core deliberately does not know about. A `--probe-ports` key naming a kind this build lacks is refused by `reject_uncompiled_probe_ports` with the same `ProbeKindNotCompiled` error `--probe <kind>` raises, so both routes give the same exit code and the same rebuild hint.

`probe_is_runnable` delegates to `runnability_check`, which returns the per-kind precondition as an `Option<fn() -> bool>` so a unit test can assert the ICMP arm exists rather than only that the filter is called. **Known gap**: the `_ => None` arm declares every other kind runnable, so when core grows a second precondition kind (ARP/NDP needing `CAP_NET_RAW` is the likely next one) the CLI will silently claim it is runnable and no test fails. `ProbeKind` is `#[non_exhaustive]`, so the wildcard cannot be removed. Closing it needs `has_runnability_precondition` made `pub` in `rastreo-core::prober::selection` plus a parity test walking `ProbeKind::all()` — a public-surface change on a core module, so it lands as its own architectural change, not as a drive-by.

Stderr notes accompany a flag-driven scan, all pure functions returning `Vec<String>` so they are unit-testable without capturing output. One rule governs them: **a flag whose only consumer is a kind absent from the final selection produces a note naming the kind and the flag that would select it.** `parameter_flags` is the single table — one `ParameterFlag { flag, consumers, supplied }` per per-prober parameter plus one synthesized per `--probe-ports` key — and `unused_parameter_notes` applies the predicate over it. Two tests keep the class closed: one walks `DiscoverArgs::command().get_arguments()` and fails when a per-prober argument is missing from the table, the other walks the table and asserts every entry yields its note. `--port` keeps two bespoke notes instead (given without `--probe`, naming which selected probers read it; and reaching no port-taking prober at all) because its remedy is `--probe-ports`, not `--probe`. A defaulted kind the runnability filter dropped gets its own note.

`probe_args.rs` holds `UdpProtocolArg` / `DnsQueryTypeArg` / `SnmpVersionArg` — thin `clap::ValueEnum` mirrors of the core enums with `From` impls, because core cannot depend on clap. `--probe` itself stays a `Vec<String>` rather than a `ValueEnum`, so a kind name that is valid but not compiled into this build reports its missing Cargo feature instead of clap's generic "invalid value", which would be indistinguishable from a typo. `PROBE_LONG_HELP` carries the kind list that a `ValueEnum` would have given completions for.

### `rastreo catalog list`

Lists every catalog scenario reachable via `@name` across the search path (`RASTREO_CATALOG_DIR` colon-separated, else `$XDG_CONFIG_HOME/rastreo/catalog/` — fallback `$HOME/.config/rastreo/catalog/` — then `/etc/rastreo/catalog/`), one `@name` per line with the exact path a run would load. Names are deduped and sorted; the resolved path follows the same precedence as an `@name` reference (first directory wins, `.yml` before `.yaml`). An empty search path prints a `no catalog scenarios found (searched: ...)` line to stderr and exits 0. Gated behind the `config` feature.

### `rastreo validate`

Lints a scenario file entirely offline — no DNS resolution, no probing, no broker connection. Takes one positional `<FILE>` argument: a path or an `@name` catalog reference, resolved via the same `resolve_scenario_source` / `load_scenario_file` front-end as `discover --file` (version/kind check, secret expansion, retired-field rejection). For each scenario it merges `defaults:` and then calls core's `DiscoverScenarioConfig::validate` — the same check `--dry-run` and a real scan apply, so no surface carries its own opinion of what valid means. That check covers a non-empty `targets` list, a non-empty `probers` list, each target's own shape (a `Range` whose start exceeds its end, or whose ends straddle two address families), every prober / the effective fuser / the effective classifier built and dropped, and — when a `sink` is set — `SinkConfig::validate()` (the same offline shape check `create_sink` runs at the config boundary: kafka/nats broker-server/topic-subject/stream non-empty, `tls.ca_cert` requires `verify: true`, CA PEM parses, DLQ topic/stream non-empty), plus the encoder-against-sink check. Building the probers reads local state where a constructor does — `arp` / `ndp` enumerate the host's interfaces, `reverse_dns` reads the system resolver config — so the verdict is "would a run *on this host* refuse it", not "is this file well-formed". Still offline, but a scenario naming an interface that exists only on the scanner is refused when linted anywhere else. One file still gets two answers where a prober-less scenario sits beside a runnable one, and it is a bug rather than a distinction: core refuses the prober-less scenario and this linter reports that, while `discover --file` skips it before core is ever asked and carries on with the rest. The two agree once nothing is left to run — a file of nothing but prober-less scenarios exits 1 on every surface. Prints `scenario '<name>' (N of M): ok` (stdout) or `... : <reason>` (stderr) per scenario, then `N scenario(s) validated: all valid` on success. Exit 0 when all scenarios are valid, exit 1 when any is invalid or the file fails to parse. Gated behind the `config` feature. A `type: kafka` / `type: nats` sink only parses when the binary carries the matching build feature.

Two modes:

- **Flag-driven** (`--target`, optionally `--probe`): builds an in-memory `DiscoverScenarioConfig` from core's probe-selection API. Every prober compiled into the binary is reachable this way; only the parameters no flag exposes (SNMPv3 USM credentials, gNMI auth, per-prober TLS verification, custom reverse-DNS resolvers) require YAML.
- **YAML-driven** (`--file`): loads a `ScenarioFile` from disk, validates `version: 1` + `kind: discovery`, and executes each entry sequentially. This is the path for multi-scenario runs, full per-prober configuration, and the fuser / encoder / classifier surface. Sink and per-scenario knob overrides via `--sink`, `--concurrency`, `--timeout-ms` follow the precedence rule below (CLI > YAML).

Catalog references (`@name`) resolve `--file` to a scenario file in `RASTREO_CATALOG_DIR` (colon-separated PATH-style) if set, otherwise `$XDG_CONFIG_HOME/rastreo/catalog/` (fallback `$HOME/.config/rastreo/catalog/`) then `/etc/rastreo/catalog/`. First hit wins, `.yml` before `.yaml` within each directory. Names may not contain path separators.

Output: one `DeviceRecord` per line on the chosen sink, as a table row on stdout and as NDJSON everywhere else (`--format` overrides both, on both surfaces). Banners, hints, and tracing logs go to stderr so a stdout sink stays clean for downstream `jq` / NDJSON consumers; the progress line goes there too but only draws when records are not sharing the terminal. An explicit `-q` / `-v` beats an ambient `RUST_LOG`; with neither flag, `RUST_LOG` beats the built-in `info` default.

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
