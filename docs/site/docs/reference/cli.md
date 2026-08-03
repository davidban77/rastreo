---
description: Every CLI flag for rastreo and rastreo-server, with defaults, accepted values, and environment-variable equivalents.
---

# CLI reference

This page lists every command-line flag for both binaries — the `rastreo` CLI and the `rastreo-server` HTTP control plane. For worked examples and walkthroughs, see [Discover · CLI](../discover/cli.md) and [Deploy · Server](../deploy/server.md). The structured tables below are the lookup form.

## Top-level flags (rastreo)

These flags apply to `rastreo` itself, before any subcommand. They are global — the verbosity flags also work when placed after the subcommand.

| Flag | Default | Notes |
|---|---|---|
| `-v`, `--verbose` | — | Show the per-kind detail lines under the completion banner and raise the log level. Repeatable (`-vv`, `-vvv`). Logs always go to stderr. |
| `-q`, `--quiet` | — | Suppress banners, the progress line, hints, and all logs below `error`. Wins over `--verbose`. |
| `--log-format <FORMAT>` | `text` | Log line format on stderr. Values: `text` (human-readable) or `json` (one JSON object per line). Env var: `RASTREO_LOG_FORMAT`. See [Logging](logging.md). |
| `-h`, `--help` | — | Print help and exit. |
| `-V`, `--version` | — | Print version and exit. |

### What each verbosity level shows

Everything in this table goes to **stderr**. Records always go to the sink (stdout by default) and are never affected by verbosity.

| | start banner | progress line | completion banner | detail lines | hints | log level |
|---|---|---|---|---|---|---|
| `-q` | no | no | no | no | no | `error` |
| *(no flag)* | yes | yes | yes | no | yes | `info` |
| `-v` | yes | yes | yes | yes | yes | `debug` |
| `-vv` and up | yes | yes | yes | yes | yes | `trace` |

A successful `-q` run writes nothing at all to stderr, which makes it the right choice for a cron job or a pipeline step. Errors still print — `-q` suppresses status output, not failures.

`--format json` cuts the same rows as `-q` except hints, which stay: they go to stderr, and they are the most useful thing to read when a scan comes back empty. `-v` brings the banners back.

| | start banner | progress line | completion banner | detail lines | hints |
|---|---|---|---|---|---|
| `--format json` | no | no | no | no | yes |
| `--format json -v` | yes | yes | yes | yes | yes |
| `--format json -q` | no | no | no | no | no |
| `--format json` with stderr merged into stdout | no | no | no | no | only on a refusal |

The last row is the case where a hint *could* reach the record stream: `> scan.json 2>&1` and `2>&1 | jq` give both streams one destination, and a `hint:` line there is a line the consumer has to parse. Records win while the scan is producing them, on `-v` too. They stop winning the moment the run refuses: the error prints, and so does the hint that explains it, because an error whose remedy was suppressed leaves you an exit code and nothing to act on. **A merged capture that exits 0 is nothing but records; one that exits 1 carries the diagnosis.** Give stderr a destination of its own (`2> scan.log`) and every row above applies again.

Which records land on stdout is read per scenario. `--file scan.yml` with a `sink: {type: file}` writes no records to stdout, so a merged capture there keeps every row above even under `--format json` — the merge rule only fires where the records actually are.

The progress line has a second condition on top of these. It is dropped whenever the records land where it would paint — your terminal on the default stdout sink, or the file or pipe both streams were merged into. Redirect stdout on its own, redirect stderr on its own, or use `--sink file` and it comes back. See [Progress](../discover/cli.md#progress).

### Log-level precedence

An explicit `-q` or `-v` typed on the invocation wins over `RUST_LOG`. With neither flag given, `RUST_LOG` wins over the built-in `info` default. So `RUST_LOG=debug rastreo discover -q ...` is silent, while `RUST_LOG=debug rastreo discover ...` logs at debug.

### Colour and glyphs

Colour is enabled when stderr is a terminal that reports colour support, and disabled when it is redirected to a file or a pipe — so `2>scan.log` never contains escape sequences. The standard overrides apply: `NO_COLOR` (any value but `0`) turns colour off, and `CLICOLOR_FORCE=1` or `FORCE_COLOR=1` turns it on even when the output is piped. Log lines follow the same decision as the banners. This is the `rastreo` CLI's behaviour: `rastreo-server` colours its log lines whenever stderr is a terminal and does not consult `NO_COLOR`, `CLICOLOR_FORCE`, or `FORCE_COLOR`.

Banners use the Unicode glyphs `▶`, `■`, `⚠`, `•`, and `→`. They fall back to the ASCII `>`, `#`, `!`, `*`, and `->` when `LC_ALL` / `LC_CTYPE` / `LANG` names a non-UTF-8 locale, or when you set `RASTREO_ASCII` to any non-empty value other than `0`.

The completion glyph is blue on a clean run and turns yellow when the run covered less ground than you asked for — it was cancelled, records were quarantined to a dead-letter destination, a target resolved to no addresses, or a scenario in a multi-scenario file failed or was skipped. Probe faults alone do not tint it; they are expected on any real scan and are counted in the `faults:` field.

| Env var | Effect |
|---|---|
| `RUST_LOG` | Tracing filter directive. Overridden by an explicit `-q` / `-v`. |
| `RASTREO_FORMAT` | Record format, same values as `--format`. Overridden by the flag. Because it is an explicit statement, it also overrides a scenario's `encoder` — `RASTREO_FORMAT=table` left exported in a shell will refuse every scenario with a Kafka or NATS sink, which cannot carry an aligned grid. |
| `NO_COLOR` | Any value but `0` disables colour on stderr. |
| `CLICOLOR_FORCE`, `FORCE_COLOR` | Force colour on even when stderr is not a terminal. |
| `RASTREO_ASCII` | Any non-empty value other than `0` forces the ASCII glyph table. |

## rastreo discover

Probe one or more targets and emit `DeviceRecord` events to a sink. `--target` is required unless `--file` is set; everything else has a default.

| Flag | Type | Default | Notes |
|---|---|---|---|
| `-f`, `--file <PATH>` | path | — | Load a YAML scenario file instead of building the scan from flags. Accepts a filesystem path, or an `@name` [catalog](../discover/catalog.md) reference resolved via the catalog search path. Mutually exclusive with every flag-driven scan argument (`--target`, `--port`, `--probe`, `--probe-ports`, and the per-prober parameters). Requires the `config` build feature (on by default). See [Discover · CLI](../discover/cli.md#yaml-driven-mode). |
| `--target <TARGET>...` | string | — (required) | Target to probe. Accepts a single IP, a CIDR block (`10.0.0.0/24`), an IP range (`10.0.0.1-10.0.0.5`), or a DNS name. Repeatable; multiple values per flag accepted. See [Targets](../discover/targets.md). |
| `--probe <KIND>` | string list | the default set | Probe kinds to run. Repeatable; comma-separated values accepted (`--probe icmp,snmp`). Accepts any kind name, the `tcp` alias for `tcp_connect`, and the `default` keyword. Omit it to run the default set. See [Choosing probers](../discover/cli.md#choosing-probers). |
| `-p`, `--port <PORT>` | port number | per-prober defaults | Ports for the probers that have no well-known port: `tcp_connect`, `http`, and `udp`. Repeatable; comma-separated values accepted (`-p 22,80,443`). Probers with a protocol port (`dns` 53, `snmp` 161, `ssh` 22, `tls` 443, `gnmi` 57400) ignore it — retarget those with `--probe-ports`. |
| `--probe-ports <KIND>=<PORT>` | string | — | Port list for one prober, overriding both `--port` and the prober's own default. Repeatable, one prober per flag (`--probe-ports snmp=1161 --probe-ports http=8080,8443`). Repeating it for the *same* prober is last-wins; put every port in one comma-separated value instead. |
| `--udp-protocol <PROTOCOL>` | enum | — | UDP service to fingerprint. Required when `udp` is selected. Values: `ntp`, `sip_options`, `memcached_stats`, `stun_binding`. See [UDP](../probe/udp.md). |
| `--dns-query <NAME>` | string list | — | Name to look up against each target. Required when `dns` is selected. Repeatable; comma-separated values accepted. See [DNS](../probe/dns.md). |
| `--dns-query-type <TYPE>` | enum | `a` | Record type for `--dns-query`. Values: `a`, `aaaa`, `mx`, `txt`, `ptr`, `ns`, `cname`. |
| `--snmp-community <COMMUNITY>` | string | `public` | SNMP read community for the flag-driven scan. Env var: `RASTREO_SNMP_COMMUNITY` — prefer it, because a flag value is visible to anyone who can run `ps`. Neither form affects a `--file` run, which takes the community from the scenario's `community:` field. Requires the `snmp` build feature. |
| `--snmp-version <VERSION>` | enum | `v2c` | SNMP protocol version. Values: `v1`, `v2c`, `v3`. Requires the `snmp` build feature. |
| `--http-path <PATH>` | string | `/` | Request path for the HTTP prober. Requires the `http` build feature. |
| `--icmp-count <N>` | integer | `3` | Echo requests per target for the ICMP prober. Minimum 1. Requires the `icmp` build feature. |
| `--interface <NAME>` | string | auto-select | Interface the ARP and NDP probers send from. Unset means auto-select per target from the local subnets. Requires the `arp` or `ndp` build feature. See [ARP](../probe/arp.md) and [NDP](../probe/ndp.md). |
| `--format <FORMAT>` | enum | `table` on stdout, `json` elsewhere | Record format. Values: `table` (aliased `text`) for the aligned triage grid, `json` (aliased `ndjson`) for one JSON object per line. Env var: `RASTREO_FORMAT`. Unset, the destination decides: a `--file` scenario with a stdout sink and no `encoder:` renders the table too. An explicit value overrides the scenario's `encoder`. See [Record format](../discover/cli.md#record-format). |
| `--sink <SINK>` | enum | `stdout`, or the scenario's `sink` under `--file` | Output destination. Values: `stdout`, `file`. `kafka` is available only when the binary is built with the `kafka` Cargo feature. Setting it under `--file` overrides the scenario's own `sink`. See [Sinks](../discover/sinks.md). |
| `--output <PATH>` | path | — | File path for `--sink file`. Required when the file sink is selected, and rejected before any probe runs otherwise — `--output` without `--sink file` is an error, not a silent no-op, on the flag-driven and the `--file` surface alike. See [Destination flags](../discover/cli.md#destination-flags). |
| `--brokers <BROKERS>` | string list | — | Comma-separated Kafka brokers. Requires `--sink kafka`, and rejected before any probe runs without it. Requires the `kafka` build feature. |
| `--topic <TOPIC>` | string | — | Kafka topic. Requires `--sink kafka`, and rejected before any probe runs without it. Requires the `kafka` build feature. |
| `--kafka-flush-per-record` | flag | — | Flush every `DeviceRecord` as a separate Kafka message. Mutually exclusive with `--kafka-batch-threshold`. Requires `--sink kafka` and the `kafka` build feature. |
| `--kafka-batch-threshold <BYTES>` | integer | `65536` | Bytes accumulated in the sink buffer before one produce request goes out, carrying one message per record. Minimum 1. Requires `--sink kafka` and the `kafka` build feature. |
| `--concurrency <N>` | integer | `64` | Maximum number of probes in flight at once. Minimum 1. |
| `--rate <N>` | integer | unset | Maximum number of probes started per second. Minimum 1. Unset means probes start as fast as concurrency allows. |
| `--retries <N>` | integer | `0` | Retransmit attempts for the connectionless probers — UDP, SNMP, DNS, and reverse DNS. `0` is single-shot (default). Range 0–1024. It divides `--timeout-ms` across attempts, so the total time per probe is unchanged. TCP-based probers (`tcp_connect`, `http`, `ssh`, `tls`) and ICMP ignore it. With `--file`, it overrides the scenario `retries`. See [Discover · CLI](../discover/cli.md#retries-on-lossy-links). |
| `--timeout-ms <MS>` | integer | `1000` | Per-probe TCP-connect timeout in milliseconds. Minimum 1. |
| `--dry-run` | flag | — | Resolve targets and print the plan without probing or opening a sink. Applies the same refusals a run applies, including the `--checkpoint` and `--resume` checks. With `--format json` the plan is a JSON array instead of the text plan. See [Discover · CLI](../discover/cli.md#dry-run-mode). |
| `--checkpoint <PATH>` | path | — | Write a resume checkpoint to this file during the scan. The scenario must be resume-safe — a durable sink (`file`, `kafka`, `nats`), no `identity` fuser, no `lldp` / `gnmi` prober — or the scan is refused before probing. Removed on success, kept on cancellation. See [Discover · CLI](../discover/cli.md#checkpoints). |
| `--checkpoint-interval <N>` | integer | `5000` | Number of targets between checkpoint writes. Minimum 1. Ignored unless `--checkpoint` is set. |
| `--resume` | flag | — | Resume from the checkpoint at `--checkpoint <PATH>`: skip the already-flushed targets, restore the original scan identity, and continue. The checkpoint must exist and still match the scenario's targets and sink destination, or the resume is refused before probing. Single-scenario runs only. Requires `--checkpoint`. See [Discover · CLI](../discover/cli.md#resuming). |
| `-v`, `--verbose` | counter | — | See top-level flags above. |
| `-q`, `--quiet` | flag | — | See top-level flags above. |

The `--brokers`, `--topic`, `--kafka-flush-per-record`, and `--kafka-batch-threshold` flags are only present in the help output and the parser when the binary was built with `--features kafka`. The default build omits them entirely, because it carries no sink that could consume them. The same holds for the per-prober parameters: `--snmp-community` and `--snmp-version` need `--features snmp`, `--http-path` needs `http`, `--icmp-count` needs `icmp`, and `--interface` needs `arp` or `ndp`.

`--probe` and `--probe-ports` always accept every kind name, whatever the build. Naming a kind this binary was not built with fails with a message that says which Cargo feature is missing, so a typo and a missing feature never look the same:

```text
Error: probe kind 'gnmi' requires the 'gnmi' Cargo feature, which this binary was not built with
```

Run `rastreo discover --help` for the full kind list with each kind's feature annotation.

`--probe-ports` and each per-prober parameter configure specific probers. Supply one for a prober the run does not select and rastreo prints a note on stderr naming the flag, the kind, and the `--probe` value that would select it, rather than discarding the value in silence. See [Per-prober parameters](../discover/cli.md#per-prober-parameters).

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
| `--port <PORT>` | port number | `8080` | `RASTREO_SERVER_PORT` | TCP port the HTTP listener binds to. |
| `--request-timeout-ms <MS>` | integer | `60000` | `RASTREO_SERVER_REQUEST_TIMEOUT_MS` | Per-request timeout. Requests that exceed this return `503 Service Unavailable`. Minimum 1. |
| `--log-format <FORMAT>` | enum | `text` | `RASTREO_LOG_FORMAT` | Log line format on stderr. Values: `text` (human-readable) or `json` (one JSON object per line). See [Logging](logging.md). |
| `-h`, `--help` | flag | — | — | Print help and exit. |
| `-V`, `--version` | flag | — | — | Print version and exit. |

`rastreo-server` does not have `-v` / `-q` flags. Log level is controlled by the `RUST_LOG` environment variable (`RUST_LOG=debug rastreo-server ...`); the default is `info`. Logs are emitted to stderr.

## Env-var precedence

For both binaries, the precedence from lowest to highest is: built-in default, then environment variable, then CLI flag. A flag value always wins over an environment-variable value. Variables only apply to flags that declare an env mapping in the table above. `RUST_LOG` follows the same rule: it beats the built-in default but loses to an explicit `-q` / `-v`.

## Build features

Some flags and flag values only exist when the matching Cargo feature was enabled at build time. The features below apply to `rastreo` and `rastreo-server` alike.

| Feature | Default | Effect on CLI |
|---|---|---|
| `config` | yes | Enables YAML scenario-file parsing. Required for `rastreo discover --file <path>`. Without it, the flag-driven form (`--target` + `--probe`) remains the only discovery entry point. |
| `kafka` | no | Adds `kafka` as a valid value for `--sink`, plus the `--kafka-flush-per-record` and `--kafka-batch-threshold` flags. The default build does not include it; build with `cargo build --features kafka` to enable. |
| `nats` | no | Enables the NATS JetStream sink. Configured only through YAML scenarios loaded via `--file` or the `POST /scans` body (`type: nats`); no dedicated CLI flags. Also available via `POST /scans`. |
| `http` | no | Enables the HTTP prober. Selected with `--probe http`, or as `type: http` in a YAML scenario. Also available via `POST /scans`. |
| `snmp` | no | Enables the SNMP prober (v1 / v2c / v3 with USM), plus the `--snmp-community` and `--snmp-version` flags. Selected with `--probe snmp`, or as `type: snmp` in a YAML scenario. Also available via `POST /scans`. |
| `arp` | no | Enables the ARP prober for IPv4 link-layer neighbor discovery, plus the `--interface` flag. Requires `CAP_NET_RAW` at runtime. Selected with `--probe arp`, or as `type: arp` in a YAML scenario. |
| `ndp` | no | Enables the NDP prober for IPv6 link-layer neighbor discovery, plus the `--interface` flag. Requires `CAP_NET_RAW` at runtime. Selected with `--probe ndp`, or as `type: ndp` in a YAML scenario. |
| `ssh` | no | Enables the SSH prober. Selected with `--probe ssh`, or as `type: ssh` in a YAML scenario. Also available via `POST /scans`. |
| `icmp` | no | Enables the ICMP Echo prober, plus the `--icmp-count` flag. Prefers unprivileged `SOCK_DGRAM` and falls back to `SOCK_RAW` (requires `CAP_NET_RAW`). Selected with `--probe icmp`, or as `type: icmp` in a YAML scenario. Also available via `POST /scans`. |
| `tls` | no | Enables the TLS handshake prober. Opens a TLS connection to each configured port, accepts any certificate (fingerprinting, not authentication), and emits the leaf certificate's Subject CN and Subject Alternative Names as `TlsSubject` / `TlsSanName` signals. Selected with `--probe tls`, or as `type: tls` in a YAML scenario. Also available via `POST /scans`. |
| `gnmi` | no | Enables the gNMI prober for gRPC/gNMI device fingerprinting. Selected with `--probe gnmi`, or as `type: gnmi` in a YAML scenario. Credentials are YAML-only. Also available via `POST /scans`. |

## Exit codes

Both binaries exit `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors — missing required flags, mutually-exclusive flags set together, file-sink without `--output` — fail before any probe runs or any HTTP request is accepted.

A target that resolved to no addresses is not an error while any other target was probed: the run exits `0`, the completion banner counts it as `unresolvable: N`, and `-v` names which targets. Like every other fact the completion banner carries — probe faults, quarantined records, a cancelled run — `-q` silences it, so pair `-q` with `--dry-run --format json` if you need the answer without the banner: each target carries its own `"resolution"`, and `unresolvable` is one of the three states. It becomes exit `1` only when **every** target resolved to no addresses, because then the scan probed nothing at all. See [Names with no addresses](../discover/targets.md#names-with-no-addresses).

A scenario with no probers reads the same way one level up. `rastreo discover --file` skips it, probes the rest of the file, and exits `0`, and the aggregate banner reports the shortfall twice over: the label counts only the scenarios that ran (`1 of 2 scenarios`), a `skipped: N` field counts the ones that did not, and the `■` turns yellow. A notice on stderr names each skipped scenario as the run reaches it. `-q` silences all of it, as it does for an unresolvable target. It becomes exit `1` only when **every** scenario in the file was skipped. See [Discover · a scenario with no probers](../discover/cli.md#a-scenario-rastreo-cannot-build-gets-no-plan).

## See also

- [Discover · CLI](../discover/cli.md) — walkthrough with worked examples.
- [Scenario schema](scenario.md) — the JSON shape `rastreo-server` accepts.
- [Error reference](errors.md) — what each error means and how to fix it.
