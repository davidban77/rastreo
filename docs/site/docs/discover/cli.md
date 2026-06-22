---
description: Reference for the rastreo discover subcommand — required flags, optional flags, worked examples, exit codes.
---

# CLI

`rastreo discover` is the entry point for one-shot discovery scans. It is flag-driven — there is no config file flag on the CLI today. The command probes each target on each port using the TCP-connect prober and emits one NDJSON `DeviceRecord` per discovered device to the chosen sink.

## Usage

```text
rastreo discover [OPTIONS] --target <TARGET>... --port <PORT>
```

## Required flags

`--target` is the target to probe. It accepts a single IP, a CIDR block, an IP range, or a DNS name; the form is detected from the string shape. Repeat the flag to add more targets, or pass several values after one `--target`. See [Targets](targets.md) for the exact detection rules.

```bash
rastreo discover --target 10.0.0.1 --target 192.0.2.0/29 --port 80
```

`--port` (`-p`) is the TCP port to probe. Repeat the flag or comma-separate the values to probe more than one port per target.

```bash
rastreo discover --target 1.1.1.1 --port 22,80,443
```

## Optional flags

| Flag | Default | Notes |
|---|---|---|
| `--sink <SINK>` | `stdout` | Where records are emitted. Possible values: `stdout`, `file`. `kafka` is available when the binary is built with `--features kafka`. See [Sinks](sinks.md). |
| `--output <PATH>` | — | Output file path for `--sink file`. Required when the file sink is selected. |
| `--brokers <BROKERS>` | — | Comma-separated Kafka brokers for `--sink kafka`. Requires the `kafka` build feature. |
| `--topic <TOPIC>` | — | Kafka topic for `--sink kafka`. Requires the `kafka` build feature. |
| `--concurrency <N>` | `64` | Maximum number of in-flight probes. Minimum value is 1. |
| `--timeout-ms <MS>` | `1000` | Per-probe TCP-connect timeout in milliseconds. Minimum value is 1. |
| `-v`, `--verbose` | info | Increase log verbosity. `-v` is debug, `-vv` (or more) is trace. Logs go to stderr. |
| `-q`, `--quiet` | — | Drop the log level to `error`. Mutually exclusive in spirit with `-v`. |

## Examples

A minimum-flags scan against one host and one port. Stdout receives one NDJSON record per discovered device; stderr receives the summary line.

```bash
rastreo discover --target 1.1.1.1 --port 443
```

A scan across many targets and many ports. Each `--target` is expanded independently and the combined set is scheduled with up to `--concurrency` probes in flight.

```bash
rastreo discover \
  --target 10.0.0.0/24 \
  --target router-1.lab \
  --port 22,80,443
```

Persist results to an NDJSON file instead of stdout. The file is opened in append mode, so repeated runs accumulate rather than overwrite.

```bash
rastreo discover \
  --target 192.0.2.0/24 \
  --port 80 \
  --sink file \
  --output /tmp/scan.ndjson
```

Send records to a Kafka topic:

!!! warning "Requires the `kafka` build feature"
    The `kafka` value for `--sink` only exists when the binary is built with `cargo build --workspace --features kafka` (or `cargo install --path rastreo --features kafka`). The default build does not include it.

```bash
rastreo discover \
  --target 192.0.2.0/24 \
  --port 80 \
  --sink kafka \
  --brokers localhost:9092 \
  --topic rastreo.devices
```

## Exit codes

`rastreo discover` exits `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors (for example, `--sink file` without `--output`) fail before any probe runs.

## See also

- [Targets](targets.md) — the four target forms and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output in depth.
