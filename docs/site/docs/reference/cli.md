---
description: Every CLI flag for rastreo and rastreo-server, with defaults, accepted values, and environment-variable equivalents.
---

# CLI reference

This page lists every command-line flag for both binaries — the `rastreo` CLI and the `rastreo-server` HTTP control plane. For worked examples and walkthroughs, see [Discover · CLI](../discover/cli.md) and [Deploy · Server](../deploy/server.md). The structured tables below are the lookup form.

## Top-level flags (rastreo)

These flags apply to `rastreo` itself, before any subcommand. They are global — the verbosity flags also work when placed after the subcommand.

| Flag | Default | Notes |
|---|---|---|
| `-v`, `--verbose` | — | Increase log verbosity. Repeatable (`-vv`, `-vvv`). Logs always go to stderr. |
| `-q`, `--quiet` | — | Drop log level to `error`. Mutually exclusive in spirit with `-v`. |
| `--log-format <FORMAT>` | `text` | Log line format on stderr. Values: `text` (human-readable) or `json` (one JSON object per line). Env var: `RASTREO_LOG_FORMAT`. See [Logging](logging.md). |
| `-h`, `--help` | — | Print help and exit. |
| `-V`, `--version` | — | Print version and exit. |

The verbosity ladder is: no flag = `info`, `-v` = `debug`, `-vv` or more = `trace`. `--quiet` overrides `--verbose` and pins the level at `error`. The `RUST_LOG` environment variable, when set, takes precedence over the flag-derived default.

## rastreo discover

Probe one or more targets and emit `DeviceRecord` events to a sink. `--target` and `--port` are required; everything else has a default.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--target <TARGET>...` | string | — (required) | Target to probe. Accepts a single IP, a CIDR block (`10.0.0.0/24`), an IP range (`10.0.0.1-10.0.0.5`), or a DNS name. Repeatable; multiple values per flag accepted. See [Targets](../discover/targets.md). |
| `-p`, `--port <PORT>` | u16 | — (required) | TCP port to probe. Repeatable; comma-separated values accepted (`-p 22,80,443`). |
| `--sink <SINK>` | enum | `stdout` | Output destination. Values: `stdout`, `file`. `kafka` is available only when the binary is built with the `kafka` Cargo feature. See [Sinks](../discover/sinks.md). |
| `--output <PATH>` | path | — | File path for `--sink file`. Required when the file sink is selected; rejected before any probe runs if missing. |
| `--brokers <BROKERS>` | string list | — | Comma-separated Kafka brokers for `--sink kafka`. Requires the `kafka` build feature. |
| `--topic <TOPIC>` | string | — | Kafka topic for `--sink kafka`. Requires the `kafka` build feature. |
| `--kafka-flush-per-record` | flag | — | Flush every `DeviceRecord` as a separate Kafka message. Mutually exclusive with `--kafka-batch-threshold`. Requires the `kafka` build feature. |
| `--kafka-batch-threshold <BYTES>` | usize | `65536` | Bytes accumulated in the sink buffer before one produce request goes out, carrying one message per record. Minimum 1. Requires the `kafka` build feature. |
| `--concurrency <N>` | u32 | `64` | Maximum number of probes in flight at once. Minimum 1. |
| `--rate <N>` | u32 | unset | Maximum number of probes started per second. Minimum 1. Unset means probes start as fast as concurrency allows. |
| `--retries <N>` | u32 | `0` | Retransmit attempts for the connectionless probers — UDP, SNMP, DNS, and reverse DNS. `0` is single-shot (default). Range 0–1024. It divides `--timeout-ms` across attempts, so the total time per probe is unchanged. TCP-based probers (`tcp_connect`, `http`, `ssh`, `tls`) and ICMP ignore it. With `--file`, it overrides the scenario `retries`. See [Discover · CLI](../discover/cli.md#retries-on-lossy-links). |
| `--timeout-ms <MS>` | u64 | `1000` | Per-probe TCP-connect timeout in milliseconds. Minimum 1. |
| `-v`, `--verbose` | counter | — | See top-level flags above. |
| `-q`, `--quiet` | flag | — | See top-level flags above. |

The `--kafka-flush-per-record` and `--kafka-batch-threshold` flags are only present in the help output and the parser when the binary was built with `--features kafka`. The default build omits them entirely.

## rastreo validate

Lint a scenario file offline: check the config shape and every scenario's sink config with no DNS, no probing, and no broker connection. Takes one positional argument. Requires the `config` build feature (on by default). For a walkthrough with worked examples, see [Discover · Validate](../discover/validate.md).

| Argument | Type | Default | Notes |
|---|---|---|---|
| `<FILE>` | path | — (required) | Scenario file to validate. Accepts a path, or an `@name` catalog reference resolved the same way as `discover --file`. See [Catalog](../discover/catalog.md). |

It exits `0` when every scenario in the file is valid and `1` when any scenario is invalid or the file itself cannot be parsed. It prints one `ok` or error line per scenario plus a final summary line — see [Discover · Validate](../discover/validate.md#reading-the-output). A `type: kafka` sink is only recognized with the `kafka` build feature, and `type: nats` with the `nats` feature; validate the file with the same build you plan to run it with.

## rastreo-server

Run the HTTP control plane. Every flag has both a CLI form and an environment-variable form; the CLI form overrides the environment when both are set.

| Flag | Type | Default | Env var | Notes |
|---|---|---|---|---|
| `--bind <BIND>` | IP address | `0.0.0.0` | `RASTREO_SERVER_BIND` | Address the HTTP listener binds to. Accepts IPv4 or IPv6. |
| `--port <PORT>` | u16 | `8080` | `RASTREO_SERVER_PORT` | TCP port the HTTP listener binds to. |
| `--request-timeout-ms <MS>` | u64 | `60000` | `RASTREO_SERVER_REQUEST_TIMEOUT_MS` | Per-request timeout. Requests that exceed this return `503 Service Unavailable`. Minimum 1. |
| `--log-format <FORMAT>` | enum | `text` | `RASTREO_LOG_FORMAT` | Log line format on stderr. Values: `text` (human-readable) or `json` (one JSON object per line). See [Logging](logging.md). |
| `-h`, `--help` | flag | — | — | Print help and exit. |
| `-V`, `--version` | flag | — | — | Print version and exit. |

`rastreo-server` does not have `-v` / `-q` flags. Log level is controlled by the `RUST_LOG` environment variable (`RUST_LOG=debug rastreo-server ...`); the default is `info`. Logs are emitted to stderr.

## Env-var precedence

For both binaries, the precedence from lowest to highest is: built-in default, then environment variable, then CLI flag. A flag value always wins over an environment-variable value. Variables only apply to flags that declare an env mapping in the table above.

## Build features

Several CLI surfaces appear conditionally based on which Cargo features were enabled at build time. The `rastreo-core` library declares the features below; the `rastreo` and `rastreo-server` binaries inherit them via their dependency on the core crate.

| Feature | Default | Effect on CLI |
|---|---|---|
| `config` | yes | Enables YAML scenario-file parsing. Required for `rastreo discover --file <path>`. Without it, `--target` / `--port` remain the only discovery entry point. |
| `kafka` | no | Adds `kafka` as a valid value for `--sink`, plus the `--kafka-flush-per-record` and `--kafka-batch-threshold` flags. The default build does not include it; build with `cargo build --features kafka` to enable. |
| `nats` | no | Enables the NATS JetStream sink. Configured only through YAML scenarios loaded via `--file` or the `POST /scans` body (`type: nats`); no dedicated CLI flags. Also available via `POST /scans`. |
| `http` | no | Enables the HTTP prober. Accepted as `type: http` in YAML scenarios loaded via `--file`. Also available via `POST /scans`. |
| `snmp` | no | Enables the SNMP prober (v1 / v2c / v3 with USM). Accepted as `type: snmp` in YAML scenarios loaded via `--file`. Also available via `POST /scans`. |
| `arp` | no | Enables the ARP prober for IPv4 link-layer neighbor discovery. Requires `CAP_NET_RAW` at runtime. Accepted as `type: arp` in YAML scenarios loaded via `--file`. |
| `ndp` | no | Enables the NDP prober for IPv6 link-layer neighbor discovery. Requires `CAP_NET_RAW` at runtime. Accepted as `type: ndp` in YAML scenarios loaded via `--file`. |
| `oui` | no | Enables the OUI vendor enrichment fuser. Accepted as `type: oui_enrichment` in the `fuser` block of YAML scenarios loaded via `--file`. |
| `ssh` | no | Enables the SSH prober. Accepted as `type: ssh` in YAML scenarios loaded via `--file`. Also available via `POST /scans`. |
| `icmp` | no | Enables the ICMP Echo prober. Prefers unprivileged `SOCK_DGRAM` and falls back to `SOCK_RAW` (requires `CAP_NET_RAW`). Accepted as `type: icmp` in YAML scenarios loaded via `--file`. Also available via `POST /scans`. |
| `tls` | no | Enables the TLS handshake prober. Opens a TLS connection to each configured port, accepts any certificate (fingerprinting, not authentication), and emits the leaf certificate's Subject CN and Subject Alternative Names as `TlsSubject` / `TlsSanName` signals. Accepted as `type: tls` in YAML scenarios loaded via `--file`. Also available via `POST /scans`. |

## Exit codes

Both binaries exit `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors — missing required flags, mutually-exclusive flags set together, file-sink without `--output` — fail before any probe runs or any HTTP request is accepted.

## See also

- [Discover · CLI](../discover/cli.md) — walkthrough with worked examples.
- [Scenario schema](scenario.md) — the JSON shape `rastreo-server` accepts.
- [Error reference](errors.md) — what each error means and how to fix it.
