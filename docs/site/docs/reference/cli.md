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
| `--kafka-batch-threshold <BYTES>` | usize | `65536` | Bytes accumulated in the sink buffer before a single Kafka message is produced. Minimum 1. Requires the `kafka` build feature. |
| `--concurrency <N>` | u32 | `64` | Maximum number of in-flight probes. Minimum 1. |
| `--timeout-ms <MS>` | u64 | `1000` | Per-probe TCP-connect timeout in milliseconds. Minimum 1. |
| `-v`, `--verbose` | counter | — | See top-level flags above. |
| `-q`, `--quiet` | flag | — | See top-level flags above. |

The `--kafka-flush-per-record` and `--kafka-batch-threshold` flags are only present in the help output and the parser when the binary was built with `--features kafka`. The default build omits them entirely.

## rastreo-server

Run the HTTP control plane. Every flag has both a CLI form and an environment-variable form; the CLI form overrides the environment when both are set.

| Flag | Type | Default | Env var | Notes |
|---|---|---|---|---|
| `--bind <BIND>` | IP address | `0.0.0.0` | `RASTREO_SERVER_BIND` | Address the HTTP listener binds to. Accepts IPv4 or IPv6. |
| `--port <PORT>` | u16 | `8080` | `RASTREO_SERVER_PORT` | TCP port the HTTP listener binds to. |
| `--request-timeout-ms <MS>` | u64 | `60000` | `RASTREO_SERVER_REQUEST_TIMEOUT_MS` | Per-request timeout. Requests that exceed this return `503 Service Unavailable`. Minimum 1. |
| `-h`, `--help` | flag | — | — | Print help and exit. |
| `-V`, `--version` | flag | — | — | Print version and exit. |

`rastreo-server` does not have `-v` / `-q` flags. Log level is controlled by the `RUST_LOG` environment variable (`RUST_LOG=debug rastreo-server ...`); the default is `info`. Logs are emitted to stderr.

## Env-var precedence

For both binaries, the precedence from lowest to highest is: built-in default, then environment variable, then CLI flag. A flag value always wins over an environment-variable value. Variables only apply to flags that declare an env mapping in the table above.

## Build features

Several CLI surfaces appear conditionally based on which Cargo features were enabled at build time. The `rastreo-core` library declares the features below; the `rastreo` and `rastreo-server` binaries inherit them via their dependency on the core crate.

| Feature | Default | Effect on CLI |
|---|---|---|
| `config` | yes | Enables YAML scenario-file parsing in `rastreo-core`. No direct CLI surface today — the `rastreo` CLI does not load YAML files. Library and HTTP-API consumers benefit. |
| `kafka` | no | Adds `kafka` as a valid value for `--sink`, plus the `--kafka-flush-per-record` and `--kafka-batch-threshold` flags. The default build does not include it; build with `cargo build --features kafka` to enable. |
| `http` | no | Declared but not implemented. Reserved for a future HTTP prober. |
| `snmp` | no | Declared but not implemented. Reserved for a future SNMP prober. |
| `arp` | no | Declared but not implemented. Reserved for a future ARP prober. |

## Exit codes

Both binaries exit `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors — missing required flags, mutually-exclusive flags set together, file-sink without `--output` — fail before any probe runs or any HTTP request is accepted.

## See also

- [Discover · CLI](../discover/cli.md) — walkthrough with worked examples.
- [Scenario schema](scenario.md) — the JSON shape `rastreo-server` accepts.
- [Error reference](errors.md) — what each error means and how to fix it.
