---
description: Reference for the rastreo discover subcommand — required flags, optional flags, worked examples, exit codes.
---

# CLI

`rastreo discover` is the entry point for one-shot discovery scans. It runs in two modes: **flag-driven** (`--target` + `--port`) for a quick TCP-connect sweep, or **YAML-driven** (`--file`) to execute a full `ScenarioFile` — the only CLI path that reaches the HTTP, DNS, UDP, SNMP, ARP, NDP probers and the OUI-enrichment fuser. Both modes emit one NDJSON `DeviceRecord` per discovered device to the chosen sink.

## Usage

```text
rastreo discover [OPTIONS] --target <TARGET>... --port <PORT>
rastreo discover [OPTIONS] --file <SCENARIO.yml>
```

`--target` / `--port` and `--file` are mutually exclusive. Exactly one of the two modes must be selected — clap rejects the command otherwise.

## Flag-driven mode

`--target` is the target to probe. It accepts a single IP, a CIDR block, an IP range, or a DNS name; the form is detected from the string shape. Repeat the flag to add more targets, or pass several values after one `--target`. See [Targets](targets.md) for the exact detection rules.

```bash
rastreo discover --target 10.0.0.1 --target 192.0.2.0/29 --port 80
```

`--port` (`-p`) is the TCP port to probe. Repeat the flag or comma-separate the values to probe more than one port per target.

```bash
rastreo discover --target 1.1.1.1 --port 22,80,443
```

Flag-driven mode always uses the TCP-connect prober. To reach the HTTP, DNS, UDP, SNMP, ARP, or NDP probers from the CLI, use `--file` with a scenario YAML.

## YAML-driven mode

`--file <PATH>` (`-f <PATH>`) loads a `ScenarioFile` and runs every scenario entry in order. The file must set `version: 1` and `kind: discovery`; other values are rejected. See [Scenario schema](../reference/scenario.md) for the full field list. `@name` catalog references are not supported yet — only file paths.

A single-scenario file that probes an HTTP target and a DNS resolver:

```yaml
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: web-and-dns
    timeout_ms: 500
    sink:
      type: stdout
    targets:
      - Ip: "192.0.2.10"
      - Ip: "1.1.1.1"
    probers:
      - type: http
        ports: [80, 443]
      - type: dns
        query_names: ["example.com"]
```

```bash
rastreo discover --file /etc/rastreo/scan.yml
```

A multi-scenario file that runs two independent probes sequentially. The `defaults:` block applies to every scenario unless the scenario re-declares the field.

```yaml
version: 1
kind: discovery
defaults:
  timeout_ms: 1000
  sink:
    type: file
    path: /var/log/rastreo.ndjson
scenarios:
  - signal_type: discover
    name: routers
    targets:
      - Cidr: "10.0.0.0/29"
    probers:
      - type: snmp
        ports: [161]
        version: v2c
        community: public
  - signal_type: discover
    name: web-tier
    rate_limit: 32
    targets:
      - Cidr: "10.1.0.0/28"
    probers:
      - type: http
        ports: [80, 443]
```

Each scenario prints its own status line to stderr. If ANY single scenario fails, the CLI continues to the next; the process exits non-zero only when the file itself is invalid, or when every scenario fails.

## Optional flags

| Flag | Default | Notes |
|---|---|---|
| `--sink <SINK>` | `stdout` (flag-driven) / YAML `sink` (YAML-driven) | Where records are emitted. Possible values: `stdout`, `file`. `kafka` is available when the binary is built with `--features kafka`. In YAML-driven mode, setting `--sink` overrides the sink configured in the file. See [Sinks](sinks.md). |
| `--output <PATH>` | — | Output file path for `--sink file`. Required when the file sink is selected. |
| `--brokers <BROKERS>` | — | Comma-separated Kafka brokers for `--sink kafka`. Requires the `kafka` build feature. |
| `--topic <TOPIC>` | — | Kafka topic for `--sink kafka`. Requires the `kafka` build feature. |
| `--kafka-flush-per-record` | — | Flush every `DeviceRecord` to Kafka as a separate message. Mutually exclusive with `--kafka-batch-threshold`. Only meaningful with `--sink kafka`. |
| `--kafka-batch-threshold <BYTES>` | `65536` (64 KiB) | Batch threshold in bytes. Records accumulate until the buffer reaches this size, then flush as a single Kafka message. Minimum 1. Only meaningful with `--sink kafka`. |
| `--concurrency <N>` | `64` (flag-driven) / YAML `rate_limit` (YAML-driven) | Maximum number of in-flight probes. Minimum value is 1. In YAML-driven mode, setting `--concurrency` overrides the scenario's `rate_limit`. |
| `--timeout-ms <MS>` | `1000` (flag-driven) / YAML `timeout_ms` (YAML-driven) | Per-probe timeout in milliseconds. Minimum value is 1. In YAML-driven mode, setting `--timeout-ms` overrides the scenario's `timeout_ms`. |
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

## Override precedence in YAML-driven mode

CLI flags override YAML values. Merge order per scenario, lowest to highest:

1. `defaults:` block in the scenario file.
2. Per-scenario fields (`rate_limit`, `timeout_ms`, `sink`, `encoder`, `fuser`, `name`).
3. CLI flags (`--concurrency`, `--timeout-ms`, `--sink` + `--output` / Kafka flags).

Only fields the CLI flag was explicitly set for are overridden. `rastreo discover --file scan.yml --concurrency 32` overrides the YAML `rate_limit`, but leaves the sink and timeout untouched. Omitting a flag entirely lets the YAML value win.

## Cancellation

On `SIGINT` (ctrl-c) or `SIGTERM`, `rastreo discover` finishes any in-flight probes that have already started, fuses the outcomes collected so far, emits the resulting records to the sink, and flushes the sink before exiting. The summary line on stderr reads `discovery cancelled:` instead of `discovery complete:` when this path runs. The exit code is still `0` for a clean shutdown — non-zero is reserved for errors.

Records that hadn't been emitted yet at the moment of cancellation are still written if they came from outcomes the pipeline had already gathered. Records from probers that hadn't started yet are not produced — `--target 10.0.0.0/24 --port 22,80,443 ...` cancelled after the `22` sweep gives you records for port 22 only.

## Exit codes

`rastreo discover` exits `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors (for example, `--sink file` without `--output`) fail before any probe runs.

## See also

- [Scenario schema](../reference/scenario.md) — the full YAML shape accepted by `--file`.
- [Targets](targets.md) — the four target forms and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output in depth.
