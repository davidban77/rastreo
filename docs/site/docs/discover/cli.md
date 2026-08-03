---
description: Reference for the rastreo discover subcommand — required flags, optional flags, worked examples, exit codes.
---

# CLI

`rastreo discover` is the entry point for one-shot discovery scans. It runs in two modes: **flag-driven** (`--target`, plus `--probe` to pick the probers) for a scan you type in one line, or **YAML-driven** (`--file`) to execute a full `ScenarioFile` when you want a scan committed to version control. Both modes emit one `DeviceRecord` per discovered device to the chosen sink. [`--format`](#record-format) decides whether that record leaves as a table row or as JSON; unset, the destination decides for you.

## Usage

```text
rastreo discover [OPTIONS] --target <TARGET>...
rastreo discover [OPTIONS] --file <SCENARIO.yml>
```

`--file` is mutually exclusive with every flag-driven scan argument. Exactly one of the two modes must be selected — the CLI rejects the command otherwise.

## Flag-driven mode

`--target` is the target to probe. It accepts a single IP, a CIDR block, an IP range, or a DNS name; the form is detected from the string shape. Repeat the flag to add more targets, or pass several values after one `--target`. See [Targets](targets.md) for the exact detection rules.

Nothing else is required. With `--target` alone, rastreo runs the default probe set:

```bash
rastreo discover --target 10.0.0.1 --target 192.0.2.0/29
```

### Choosing probers

`--probe` picks which probers run. Repeat it or comma-separate the values:

```bash
rastreo discover --target 10.0.0.1 --probe icmp,snmp
```

Omit `--probe` and rastreo runs the **default set**: every prober this binary carries that needs no extra parameter, is not link-layer, and produces no second output stream. On a release binary that is `icmp`, `tcp_connect`, `http`, `ssh`, `tls`, `snmp`, and `reverse_dns`. Writing `--probe default` selects exactly the same set, so you can extend it rather than replace it:

```bash
rastreo discover --target 10.0.0.0/24 --probe default,arp --interface eth0
```

Some kinds are never in the default set, each for a reason:

- `udp` and `dns` need a parameter you have to supply (`--udp-protocol`, `--dns-query`). There is no sensible guess.
- `arp` and `ndp` only work on the local segment and need an interface, so they would fault on every routed target.
- `lldp` and `gnmi` write a second output stream — a [topology](topology.md) or a [collection profile](collection-profile.md) — rather than only `DeviceRecord` rows.

Every one of them is still selectable by name. `--probe lldp` shares the SNMP prober's transport, so `--snmp-community` and `--snmp-version` reach it and a v1 or v2c walk runs entirely from flags; only its SNMPv3 USM credentials need a scenario file. `--probe gnmi` runs, but no flag carries a gNMI username or password, so a real gNMI scan needs `--file`.

A prober whose runtime precondition fails is dropped from the *default* set and reported, rather than faulting on every target. On a host where rastreo cannot open an ICMP socket:

```text
• note: icmp dropped from the default set — cannot open an ICMP socket here. Run with --probe icmp to attempt it anyway.
```

Naming a kind explicitly always wins over that filter. `--probe icmp` attempts the socket anyway and reports the fault, which is what you want when you are diagnosing why ICMP is unavailable.

A kind your binary was not built with is a different error from a typo. Naming a real kind the build omits tells you which feature to rebuild with:

```console
$ rastreo discover --target 10.0.0.1 --probe gnmi
⚠ hint: 'gnmi' requires the 'gnmi' Cargo feature. Rebuild with --features gnmi or use the release Docker image which bundles kafka, http, snmp, arp, ndp, nats, ssh, icmp, tls, gnmi, lldp.
Error: probe kind 'gnmi' requires the 'gnmi' Cargo feature, which this binary was not built with
```

A misspelling gets no hint. Instead it lists every kind the running binary does carry, so you can spot the name you meant. On a release binary that is all thirteen:

```console
$ rastreo discover --target 10.0.0.1 --probe gnnmi
Error: unknown probe kind 'gnnmi'; available in this build: tcp_connect, udp, http, dns, snmp, arp, ndp, ssh, icmp, tls, reverse_dns, gnmi, lldp, default, tcp
```

Run `rastreo discover --help` for the full kind list annotated with the feature each one needs, and `--dry-run` to see exactly which probers and ports a command would use before it sends anything.

### Ports

Only three probers have no well-known port: `tcp_connect`, `http`, and `udp`. `--port` (`-p`) sets the port list for those, and for those only.

```bash
rastreo discover --target 1.1.1.1 --probe tcp_connect --port 22,80,443
```

Every other prober keeps its protocol port — DNS on 53, SNMP on 161, SSH on 22, TLS on 443, gNMI on 57400 — no matter what `--port` says. `--probe-ports <kind>=<port>[,<port>...]` retargets one prober, and beats both `--port` and the prober's own default:

```bash
rastreo discover --target 10.0.0.1 --probe snmp --probe-ports snmp=1161
```

Repeat `--probe-ports` once per prober. Repeating it for the *same* prober is last-wins — `--probe-ports dns=53 --probe-ports dns=5353` queries 5353 only. Put every port for one prober in a single comma-separated value instead: `--probe-ports dns=53,5353`.

When `--port` is given without `--probe`, rastreo says which probers it reached, because a port list on the default set is not the port-only scan it looks like:

```text
• note: --port applies to tcp_connect, http; the default probe set also runs icmp, ssh, tls, snmp, reverse_dns. Use --probe tcp_connect for a port-only scan.
```

And when `--port` reaches nothing in the selection at all, rastreo says so instead of silently ignoring it:

```text
• note: --port had no effect — none of the selected probes (snmp) read a shared port list. Use --probe-ports <kind>=<port> to retarget one.
```

Both notes go to stderr at the normal verbosity level and are suppressed by `-q`.

### Per-prober parameters

Probers that need a parameter take it from a dedicated flag. Each flag exists only in a build carrying the matching prober.

Every one of these flags configures specific probers and nothing else, so rastreo tells you when the prober it feeds is not in the run rather than discarding the value in silence:

```console
$ rastreo discover --target 10.0.0.1 --dns-query example.com
• note: --dns-query had no effect — no dns probe in this run. Add --probe dns.

$ rastreo discover --target 10.0.0.1 --probe tcp_connect --http-path /health
• note: --http-path had no effect — no http probe in this run. Add --probe http.
```

The same note covers `--probe-ports` for a prober you did not select (`--probe-ports dns=5353 had no effect — no dns probe in this run.`). Like the `--port` notes, these go to stderr and are suppressed by `-q`.

| Flag | Prober | Default | Notes |
|---|---|---|---|
| `--udp-protocol <PROTOCOL>` | `udp` | — (required) | `ntp`, `sip_options`, `memcached_stats`, or `stun_binding`. |
| `--dns-query <NAME>` | `dns` | — (required) | Repeatable or comma-separated. |
| `--dns-query-type <TYPE>` | `dns` | `a` | `a`, `aaaa`, `mx`, `txt`, `ptr`, `ns`, `cname`. |
| `--snmp-community <COMMUNITY>` | `snmp` | `public` | Also reads `RASTREO_SNMP_COMMUNITY`. |
| `--snmp-version <VERSION>` | `snmp` | `v2c` | `v1`, `v2c`, or `v3`. |
| `--http-path <PATH>` | `http` | `/` | |
| `--icmp-count <N>` | `icmp` | `3` | Echo requests per target. Minimum 1. |
| `--interface <NAME>` | `arp`, `ndp` | auto-select | Interface the request frame is sent from. Unset means auto-select per target from the local subnets. |

!!! warning "Pass the SNMP community through the environment"
    A value typed as a flag is visible in `ps` output to every user on the box. `--snmp-community` also reads `RASTREO_SNMP_COMMUNITY`, which is not:

    ```bash
    RASTREO_SNMP_COMMUNITY=lab-ro rastreo discover --target 10.0.0.0/24 --probe snmp
    ```

    The variable only feeds a flag-driven scan. Exporting it in your shell is safe: a `--file` run ignores it and takes the community from the scenario's `community:` field, where [secret expansion](../reference/secrets.md) applies.

Anything past these flags — SNMPv3 USM credentials, gNMI usernames, per-prober TLS verification, custom reverse-DNS resolvers — belongs in a scenario file. See [Scenario schema](../reference/scenario.md).

## YAML-driven mode

`--file <PATH>` (`-f <PATH>`) loads a `ScenarioFile` and runs every scenario entry in order. The file must set `version: 1` and `kind: discovery`; other values are rejected. See [Scenario schema](../reference/scenario.md) for the full field list. The argument also accepts a `@name` catalog reference that resolves to a scenario file in `~/.config/rastreo/catalog/` or `/etc/rastreo/catalog/` — see [Catalog](catalog.md) for the search order and setup.

Use a scenario file when the scan needs more than the flags expose — SNMPv3 credentials, gNMI authentication, several scenarios in one run, or a scan you want reviewed and committed.

A single-scenario file that probes an HTTP target and a DNS resolver. The numbered markers explain each part — click one to expand it:

``` { .yaml .annotate }
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1 # (1)!
kind: discovery # (2)!
scenarios: # (3)!
  - signal_type: discover
    name: web-and-dns
    timeout_ms: 500
    sink: # (4)!
      type: stdout
    targets: # (5)!
      - Ip: "192.0.2.10"
      - Ip: "1.1.1.1"
    probers: # (6)!
      - type: http
        ports: [80, 443]
      - type: dns
        query_names: ["example.com"]
```

1.  **`version`** — the scenario file format version. Always `1` today.
2.  **`kind`** — declares the file as a discovery run. Always `discovery`.
3.  **`scenarios`** — the list of runs. Each entry is one independent scan, and the CLI runs them in order.
4.  **`sink`** — where records go. Here, one table row per device on stdout. See [Sinks](sinks.md).
5.  **`targets`** — what to probe. Two single IPs here. See [Targets](targets.md) for CIDR, range, and DNS forms.
6.  **`probers`** — how to probe each target. This scan runs the HTTP and DNS probers against every target.

```bash
rastreo discover --file /etc/rastreo/scan.yml
```

A multi-scenario file that runs two independent probes sequentially. The `defaults:` block applies to every scenario unless the scenario re-declares the field.

Two scheduler knobs pace a scan. `max_concurrent` caps how many probes run at the same time. `probe_rate` caps how many probes start each second. The `web-tier` scenario below sets both: up to 64 probes in flight, and no more than 50 new probes started per second.

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
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
    max_concurrent: 64
    probe_rate: 50
    targets:
      - Cidr: "10.1.0.0/28"
    probers:
      - type: http
        ports: [80, 443]
```

Each scenario prints its own status line to stderr, and the CLI runs every scenario in the file even if one fails. The process exits non-zero if the file itself is invalid or if **any** scenario fails — a partial failure (some scenarios succeed, some fail) is a non-zero exit, so a CI wrapper checking the exit code catches it. The final stderr line reads `N of M scenario(s) failed`. A scenario that completes but finds no reachable hosts is a success, not a failure.

## Optional flags

| Flag | Default | Notes |
|---|---|---|
| `--probe <KIND>` | the default set | Which probers run. Repeatable or comma-separated. See [Choosing probers](#choosing-probers). |
| `-p`, `--port <PORT>` | per-prober defaults | Ports for `tcp_connect`, `http`, and `udp`. Repeatable or comma-separated. See [Ports](#ports). |
| `--probe-ports <KIND>=<PORT>` | — | Port list for one prober, beating both `--port` and the prober's own default. See [Ports](#ports). |
| `--udp-protocol`, `--dns-query`, `--dns-query-type`, `--snmp-community`, `--snmp-version`, `--http-path`, `--icmp-count`, `--interface` | see below | Per-prober parameters. See [Per-prober parameters](#per-prober-parameters). |
| `--format <table\|json>` | `table` on stdout, `json` everywhere else | How each record is rendered. `table` (alias `text`) is the aligned triage grid; `json` (alias `ndjson`) is one JSON object per line. Env var `RASTREO_FORMAT`. Overrides the scenario's `encoder` in YAML-driven mode. See [Record format](#record-format). |
| `--sink <SINK>` | `stdout` (flag-driven) / YAML `sink` (YAML-driven) | Where records are emitted. Possible values: `stdout`, `file`. `kafka` is available when the binary is built with `--features kafka`. In YAML-driven mode, setting `--sink` overrides the sink configured in the file. See [Sinks](sinks.md). |
| `--output <PATH>` | — | Output file path. Required by `--sink file`, and refused without it. See [Destination flags](#destination-flags). |
| `--brokers <BROKERS>` | — | Comma-separated Kafka brokers. Requires `--sink kafka` and the `kafka` build feature. |
| `--topic <TOPIC>` | — | Kafka topic. Requires `--sink kafka` and the `kafka` build feature. |
| `--kafka-flush-per-record` | — | Flush every `DeviceRecord` to Kafka as a separate message. Mutually exclusive with `--kafka-batch-threshold`. Requires `--sink kafka`. |
| `--kafka-batch-threshold <BYTES>` | `65536` (64 KiB) | Batch threshold in bytes. Records accumulate until the buffer reaches this size, then flush in one produce request that carries one message per record. Minimum 1. Requires `--sink kafka`. |
| `--concurrency <N>` | `64` (flag-driven) / YAML `max_concurrent` (YAML-driven) | Maximum number of probes in flight at once. Minimum value is 1. In YAML-driven mode, setting `--concurrency` overrides the scenario's `max_concurrent`. |
| `--rate <N>` | unset — no pacing (flag-driven) / YAML `probe_rate` (YAML-driven) | Maximum number of probes started per second. Minimum value is 1. When unset, probes start as fast as concurrency allows. In YAML-driven mode, setting `--rate` overrides the scenario's `probe_rate`. |
| `--retries <N>` | `0` (flag-driven) / YAML `retries` (YAML-driven) | Retransmit attempts for the connectionless probers (UDP, SNMP, DNS, reverse DNS). Range 0–1024; `0` is single-shot. In YAML-driven mode, setting `--retries` overrides the scenario's `retries`. See [Retries on lossy links](#retries-on-lossy-links). |
| `--timeout-ms <MS>` | `1000` (flag-driven) / YAML `timeout_ms` (YAML-driven) | Per-probe timeout in milliseconds. Minimum value is 1. In YAML-driven mode, setting `--timeout-ms` overrides the scenario's `timeout_ms`. |
| `--dry-run` | off | Validate the scenario, resolve targets, print the expansion to stdout, and exit without probing or opening a sink. A scenario rastreo cannot build gets no plan. Useful before running against production. See [Dry-run mode](#dry-run-mode) below. |
| `--checkpoint <PATH>` | — | Write a resume checkpoint to this file during the scan, so a scan that dies can be resumed later. The scenario must be resume-safe or the scan is refused before probing. See [Checkpoints](#checkpoints). |
| `--checkpoint-interval <N>` | `5000` | Number of targets between checkpoint writes. Minimum 1. Ignored unless `--checkpoint` is set. See [Checkpoints](#checkpoints). |
| `--resume` | off | Continue an interrupted scan from the checkpoint at `--checkpoint <PATH>`: skip the targets already written and probe the rest. Requires `--checkpoint`. Works for a single scenario only. See [Resuming](#resuming). |
| `-v`, `--verbose` | — | Show the per-kind detail lines under the completion banner and raise the log level: `-v` is debug, `-vv` (or more) is trace. Everything goes to stderr. See [What each verbosity level shows](../reference/cli.md#what-each-verbosity-level-shows). |
| `-q`, `--quiet` | — | Suppress the banners, the progress line, hints, and all logs below `error`. A successful `-q` run writes nothing to stderr; failures still print. Wins over `-v`. |

!!! info "Concurrency vs rate"
    These are two different limits. `--concurrency` (YAML `max_concurrent`) sets how many probes run at the same time. `--rate` (YAML `probe_rate`) sets how many probes start each second. They compose: with `--concurrency 64 --rate 50`, up to 64 probes run at once, but no more than 50 start per second. The rate bounds the scan whenever it is the tighter limit. Leave `--rate` unset to let probes start as fast as concurrency allows — useful to be gentle on a fragile network.

## Record format

A flag-driven scan writes to stdout by default, and stdout is read by a person, so the default there is the table:

```text
ADDRESS                      NAME                      PLATFORM              PORTS
10.0.0.1                     core-sw-1                 Cisco IOS             22,80,443
10.0.0.2                     -                         -                     443
```

Four columns of triage, not the whole record: the management address (or the identity key when there is no address), the device's own name — its SNMP `sysName`, else its PTR record — the [classifier](classification.md)'s platform, and the open ports. A `-` means the scan learned nothing for that column. A value too wide for its column is truncated with `…`. `PORTS` is the exception: it runs past the line rather than dropping a port, because no column follows it. Links and collection profiles have no row shape and are not rendered. A scan that emits them needs `--format json`.

`--format json` writes one `DeviceRecord` per line as compact JSON — the wire format every sink and every consumer speaks:

```bash
rastreo discover --target 10.0.0.0/24 --format json | jq -r '.mgmt_ip'
```

`json` also drops the banners and the progress line, so stdout is a clean stream and stderr is quiet. Hints survive on stderr, where they cannot corrupt the record stream and where they are the most useful thing to read when a scan comes back empty. `-v` brings the banners back alongside the JSON.

That holds while the two streams stay apart. Merge them — `> scan.json 2>&1`, or `2>&1 | jq` — and one destination carries both, so a `hint:` line lands between the records and `jq` stops on it. Under `--format json` rastreo detects the merge and prints nothing but records there for as long as the scan is producing them; the hints and banners come back the moment stderr has a destination of its own. A run that refuses is the exception: the error and the hint that explains it go into the capture together, because an error whose remedy was suppressed is worse than a line to skip. So `exit 0` means the capture is nothing but records, and `exit 1` means it carries the diagnosis. Send the two somewhere useful instead:

```bash
rastreo discover --target 10.0.0.0/24 --format json > scan.json 2> scan.log
rastreo discover --target 10.0.0.0/24 --format json 2> scan.log | jq -r '.mgmt_ip'
```

Each value accepts a second spelling: `text` for `table`, and `ndjson` for `json`. Both spellings do the same thing.

### Where the default comes from

**The destination decides, whether you typed flags or loaded a scenario file.** Ask for no format and the sink the records are headed for picks one:

| Destination | Default format | Why |
|---|---|---|
| stdout | `table` | A person is reading it. |
| a file | `json` | A file is an artifact something else will parse. |
| Kafka or NATS | `json` | Broker consumers read one structured record per message; the table is refused outright. |

The rule is the same for `rastreo discover --target ...` and for `rastreo discover --file scenario.yml`. A scenario whose `sink:` is `stdout` and which sets no `encoder:` gets the table, exactly as the flag-driven form does; one that writes to a file or a broker gets NDJSON. A scenario that *does* set `encoder:` keeps it — including its own `width:`, which is never re-measured.

An explicit `--format` beats all of these, including the scenario's `encoder`. Ask for `--format table` on a Kafka or NATS sink and the run is refused before it connects — aligned text is not something a broker's consumers can parse.

`RASTREO_FORMAT` sets the same value from the environment, which makes it a per-shell or per-pipeline default:

```bash
export RASTREO_FORMAT=json
```

Because the environment is an explicit statement of intent, `RASTREO_FORMAT` overrides a scenario's `encoder` exactly as the flag does — including on a scenario the value cannot work for. `RASTREO_FORMAT=table` exported in your shell will refuse every scenario with a broker sink until you unset it or pass `--format json` on that run.

### Terminal width

The table is laid out to the width of your terminal, measured from stdout, and clamps to the range the grid supports — narrower than 55 columns renders at 55, wider than 153 renders at 153. When stdout is a pipe or a file there is no width to read and no way to know what will consume it, so the table renders at a fixed 100 columns and stays byte-identical between runs. A scenario file's `encoder: {type: table, width: N}` is never re-measured: the file said what it wanted.

## Destination flags

`--output`, `--brokers`, `--topic`, and the two `--kafka-*` tuning flags each belong to exactly one sink. Give one without selecting its sink and the run is refused before any probe:

```console
$ rastreo discover --target 1.1.1.1 --output /tmp/scan.ndjson
Error: --output only applies to --sink file, and this run writes to stdout. Add --sink file, or drop --output.
```

That is deliberately stricter than the per-prober parameters, which only print a note. An unused `--snmp-community` means one prober did not run, which the banner already shows. A discarded `--output` means you believe you have a file and do not.

The same holds under `--file`: a scenario file names its own sink, and these flags are only ever read through `--sink`. Pair them — `--file scan.yml --sink file --output /tmp/scan.ndjson` overrides the scenario's destination and works.

On a build without the `kafka` feature there is no Kafka sink to reach, so `--brokers`, `--topic`, and the `--kafka-*` flags do not exist at all and the parser rejects them by name.

## Retries on lossy links

On a clean LAN, one UDP, SNMP, or DNS request reaches the target and one reply comes back. On a congested or long-distance link, either the request or the reply can be dropped. A single dropped packet makes a live host look unreachable — a false negative. The `retries` knob tells a connectionless prober to resend the request before giving up. The default `0` sends one request and never resends. On a clean LAN (packet loss under 0.1%) one request almost always arrives, so `retries` stays off by default and is rarely needed.

Set it two ways:

- **Scenario field** `retries: N` — at the `defaults:` level or on one scenario, alongside `timeout_ms`.
- **CLI flag** `--retries N` — with `--file`, this overrides the scenario `retries`.

Only the connectionless probers that lack their own retransmission honor `retries`:

- **UDP** service probers — memcached, NTP, SIP, and STUN.
- **SNMP** — v1, v2c, and v3.
- **DNS** and **reverse DNS**.

TCP-based probers (`tcp_connect`, `http`, `ssh`, `tls`) ignore `retries`, because TCP already resends at the transport layer. ICMP has its own `count` knob instead, which defaults to 3 echoes. ARP and NDP do not honor `retries` yet. In flag-driven mode, `--retries` only changes anything when the selection includes one of the connectionless probers — `--probe snmp` or `--probe dns --dns-query <name>`, for example.

!!! note "Retries split the timeout — they do not extend it"
    `retries` divides the existing `timeout_ms` budget across attempts. Each attempt gets about `timeout_ms / (retries + 1)` milliseconds, floored at 1 ms. The total time per probe stays the same no matter how many retries you set. A retry recovers a dropped packet inside the same deadline, instead of adding scan time. On a high-latency link, size `timeout_ms` for `RTT × (retries + 1)` so each attempt still has room for one round trip.

A WAN SNMP sweep that resends a dropped request twice. The `timeout_ms` of 1500 ms is split into three attempts of about 500 ms each:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: wan-snmp
    timeout_ms: 1500
    retries: 2
    targets:
      - Cidr: "10.20.0.0/24"
    probers:
      - type: snmp
        ports: [161]
        version: v2c
        community: public
```

Override the file's `retries` from the command line without editing the YAML:

```bash
rastreo discover --file wan-snmp.yml --retries 3
```

`retries` accepts `0` through `1024`. A larger value is rejected before any probe runs.

## Examples

A minimum-flags scan against one host, running the default probe set. Stdout receives a table row per discovered device; stderr receives the start and completion banners.

```bash
rastreo discover --target 1.1.1.1
```

The same scan as a machine-readable stream, ready to pipe:

```bash
rastreo discover --target 1.1.1.1 --format json | jq .
```

A port sweep across many targets. Each `--target` is expanded independently and the combined set is scheduled with up to `--concurrency` probes in flight.

```bash
rastreo discover \
  --target 10.0.0.0/24 \
  --target router-1.lab \
  --probe tcp_connect \
  --port 22,80,443
```

An SNMP inventory sweep on a non-standard agent port, with the community read from the environment.

```bash
RASTREO_SNMP_COMMUNITY=lab-ro rastreo discover \
  --target 10.0.0.0/24 \
  --probe snmp \
  --probe-ports snmp=1161
```

Persist results to an NDJSON file instead of stdout. A file sink defaults to JSON, so no `--format` is needed. The file is opened in append mode, so repeated runs accumulate rather than overwrite.

```bash
rastreo discover \
  --target 192.0.2.0/24 \
  --probe tcp_connect \
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
  --probe tcp_connect \
  --port 80 \
  --sink kafka \
  --brokers localhost:9092 \
  --topic rastreo.devices
```

## Dry-run mode

`--dry-run` validates the scenario, resolves targets (DNS lookups run for real), prints the expanded plan to stdout, and exits without probing anything or opening a sink. It works in both flag-driven and YAML-driven mode. CLI overrides (`--sink`, `--concurrency`, `--retries`, `--timeout-ms`) are applied to the plan, and the `probers:` line lists every selected prober with the port list it resolved to — what you see is what would run. This is the fastest way to confirm a `--probe` / `--port` / `--probe-ports` combination before sending traffic.

The output shows one block per scenario. Each block lists:

- each target's DNS / CIDR / range expansion
- the configured probers with their parameters
- the [fuser](../reference/glossary.md#fuser) chain that would merge probe results into device records, outermost layer first
- the [classifier](classification.md) that would derive the canonical `platform`, `role`, and version fields
- the [record format](#record-format) each record would be written in — `table` or `ndjson`
- the sink kind and destination
- the effective concurrency, probe rate, and per-probe timeout

The rate line reads `unlimited` when no pacing is set. A bottom line reports the total probe count — the addresses the scan would probe, multiplied by the probers. It is the number of probes the scan performs, including an address covered by two targets, which is probed once for each of them. See [Overlapping targets](targets.md#overlapping-targets).

CIDRs and ranges that expand to more than six addresses are truncated with an ellipsis and a count. A target that does not resolve is listed with its reason in place of the addresses. The plan covers every target you configured, resolved or not.

The exit code is `1` when any target fails to resolve, and `0` when they all resolve. A real scan stops at the first target it cannot resolve, so a plan with a failing target describes a scan that would not start: its total probe count reads `0`, even where other targets resolved. The dry-run lists every failing target; a real scan reports only the first.

Kafka, NATS, and file sinks are described from the configured values only. `--dry-run` never opens a network connection to the sink or writes to the output file, so a bogus broker address in `--brokers` completes in milliseconds instead of hanging.

```bash
rastreo discover --target 10.0.0.0/24 --probe tcp_connect --port 22,80 --dry-run
```

```text
[dry-run] would run 1 scenario
  scenario: discovery
    targets:
      10.0.0.0/24 → 10.0.0.1, 10.0.0.2, 10.0.0.3, ... (254 addresses)
    probers: tcp_connect (ports 22, 80)
    fuser: direct (include_unreachable false, confidence_baseline 0.1, confidence_per_signal 0.1)
    classifier: rules (merge_mode extend, platform_rules 0, role_rules 0)
    encoder: table
    sink: stdout
    concurrency: 64
    rate: unlimited
    retries: 0
    timeout_ms: 1000
total probes: 254
```

The `fuser` and `classifier` lines show the stages that would run after probing, with the settings they would use. A scenario that names neither gets the pipeline defaults you see above: `direct` fusion, and the `rules` classifier over the tables built into rastreo. The `platform_rules` and `role_rules` counts cover only the rules the scenario added, so `0` means those built-in tables run on their own.

The `encoder` line is the last stage before the sink: it names the format each record is written in, after [the destination has decided](#where-the-default-comes-from) and any `--format` has been applied. Add `--sink file --output scan.ndjson` to the command above and the line reads `encoder: ndjson`. Check it before a production run to confirm the consumer on the other end gets what it expects. The line names the format only — a table's column width is measured from your terminal at run time, so it is left out to keep one scenario from printing two different plans.

!!! tip "Safe to log or share"
    The plan strips inline credentials from a sink URL. A NATS server written as `nats://user:pass@host` renders as `nats://host`.

A plan with failing targets still prints in full, then exits `1`:

```bash
rastreo discover --target nx.invalid --target 10.0.0.0/8 --probe tcp_connect --port 22 --dry-run
```

```text
[dry-run] would run 1 scenario
  scenario: discovery
    targets:
      nx.invalid → <error: DNS lookup failed for nx.invalid>
      10.0.0.0/8 → <error: CIDR 10.0.0.0/8 expands to 16777214 hosts; exceeds the configured limit of 65536>
    probers: tcp_connect (ports 22)
    fuser: direct (include_unreachable false, confidence_baseline 0.1, confidence_per_signal 0.1)
    classifier: rules (merge_mode extend, platform_rules 0, role_rules 0)
    encoder: table
    sink: stdout
    concurrency: 64
    rate: unlimited
    retries: 0
    timeout_ms: 1000
total probes: 0
⚠ hint: DNS resolution failed for the target. Check the resolver configuration or the target's hostname.
Error: DNS lookup failed for nx.invalid: no records found for Query { name: Name("nx.invalid."), query_type: AAAA, query_class: IN }
```

### A scenario rastreo cannot build gets no plan

A dry-run applies the same validity checks `rastreo discover` applies before it probes, in both flag-driven and YAML-driven mode. A scenario that fails one of them is not rendered as a plan at all. The command names the scenario and the reason, then exits `1`. Below, the scenario named `office` sets a fuser confidence score outside the allowed range:

```text
■ 'office' (1 of 1)  failed → confidence_baseline must be finite and in [0.0, 1.0], got 5
[dry-run] would run 0 scenarios
total probes: 0
Error: 1 of 1 scenario(s) failed; see individual errors above
```

The same refusal covers a prober rastreo cannot build, a classifier rule that will not compile, and a malformed target range. [`rastreo validate`](validate.md#what-it-checks) lists every check and shows the message each one produces.

!!! note "A target that fails to resolve is a different case"
    An unresolvable target leaves the scenario itself valid. rastreo still renders the plan, marks the target that failed, and exits `1`. See [Dry-run mode](#dry-run-mode).

A scenario with an empty `probers:` list is not refused on its own, because a real run does not refuse it either. The run skips that scenario and carries on with the rest of the file, and the dry-run predicts that: the scenario is left out of the plan and a notice says why. Here the second scenario in a two-scenario file, `placeholder`, has no probers, and the run still exits `0` because the first scenario probed:

```text
• 'placeholder' (2 of 2): no probers configured, skipping
```

**A skipped scenario is not a clean run, even though it exits `0`.** The real run says so on its aggregate banner: the label counts only the scenarios that ran, a `skipped:` field counts the ones that did not, and the `■` turns yellow.

```text
■ scenario 'edge' (1 of 2)  completed in 2ms | hosts: 1 | records: 0 | probes: 1 | faults: 0 | sink: stdout

• scenario 'placeholder' (2 of 2): no probers configured, skipping

■ 1 of 2 scenarios  completed in 2ms | hosts: 1 | records: 0 | probes: 1 | faults: 0 | skipped: 1
```

The exit code stays `0` because everything that could be probed was probed — the same reading a [target that resolved to no addresses](targets.md#names-with-no-addresses) gets one level down. `-q` silences the notice and the banner alike.

**A file whose every scenario is skipped probes nothing, and exits `1`.** A run that reported success there would be indistinguishable from a scan that found nothing, which is the one result you most need to tell apart. The dry-run refuses it on the same terms:

```text
• 'placeholder' (1 of 1): no probers configured, skipping
[dry-run] would run 0 scenarios
total probes: 0
Error: every scenario in 'scan.yml' was skipped for having no probers; there is nothing to probe
```

[`rastreo validate`](validate.md) judges the same file more strictly still. It calls *any* scenario with no probers invalid, even one sitting beside a scenario that would run, because a scenario that runs nothing is a mistake in the file. See [How it differs from a dry-run](validate.md#how-it-differs-from-a-dry-run).

### Checkpoint and resume checks

A run refuses more than a bad scenario. It also refuses a *request* it cannot accept — a `--checkpoint` or `--resume` that does not fit the scenario. A dry-run applies those refusals too, so it never reports a plan the run would then reject. Three checks apply when you pass `--checkpoint` or `--resume` with `--dry-run`:

- **The scenario must be resume-safe.** See [Which scans can checkpoint](#which-scans-can-checkpoint) for the fuser, prober, and sink rules.
- **The `--checkpoint` path must be free.** A path that already holds a checkpoint is refused, not overwritten.
- **`--checkpoint` needs a single scenario.** A `--file` holding several scenarios is refused, because one checkpoint path cannot record several scenarios' progress. The refusal lands on the `--checkpoint` that would write it, not only on the `--resume` that would read it back.

The second check is why a dry-run reads the disk. Here a checkpoint from an earlier run is still at that path:

```bash
rastreo discover --file scan.yml --checkpoint scan.checkpoint --dry-run
```

```text
■ 'office' (1 of 1)  failed → a checkpoint already exists at scan.checkpoint; remove it to start a fresh scan
[dry-run] would run 0 scenarios
total probes: 0
Error: 1 of 1 scenario(s) failed; see individual errors above
```

Without `--dry-run`, the run refuses the same request, with the same message and the same exit code `1`.

A dry-run reads the checkpoint path but never writes to it. An existing checkpoint keeps its contents. No new checkpoint file appears, and no sink is opened.

### Machine-readable output

`--format` chooses how the plan is printed. `table` gives the human-readable plan shown above, unchanged; `json` emits a plan you can pipe to `jq` or store as an artifact. Like the text plan, `json` resolves targets only — it never probes a host or opens a sink.

```bash
rastreo discover --file @lab --dry-run --format json
```

!!! note "One flag, two shapes"
    `--format json` means "a JSON array of plans" under `--dry-run` and "one JSON record per line" without it. The flag names the encoding; `--dry-run` decides what is being encoded.

The output is a JSON array with one object per scenario. Each object carries these fields:

- `scenario` — the scenario name. This is the plain name, the same value the HTTP server reports for a dry-run scan.
- `targets` — one entry per configured target. Each has the original `target` string and a `resolution` that is either `{"resolved": {"total": N, "sample": [ip, ...]}}` or `{"error": "..."}`. `total` is every address the scan would probe for that target; `sample` holds the first six of them, so a plan for a `/16` is the same size as a plan for a single host.
- `probers` — the probers that would run, with their ports.
- `fuser` — the fuser chain that would merge probe results into device records, outermost layer first.
- `classifier` — the classifier that would derive the canonical `platform`, `role`, and version fields, with the number of rules the scenario added.
- `encoder` — the format each record would be written in: `ndjson` or `table`. A table's column width is not carried, because it is measured from the terminal at run time. It reads `ndjson` in the plan below because `--format json` set the record format too, not only the plan's.
- `sink` — the destination, rendered from what the scenario configured. A scenario that names no `sink:` at all reads `stdout (default)` instead.
- `max_concurrent` — probes allowed in flight at once.
- `probe_rate` — probes started per second, or `null` when no pacing is set.
- `retries` — retransmit attempts for the connectionless probers.
- `timeout_ms` — per-probe timeout in milliseconds.
- `total_probes` — the addresses the scan would probe × probers. `0` when the scan would abort before probing, which is any plan carrying a `refusal`.
- `refusal` — the error the scan would abort on before its first probe. Absent when every target resolved.

The `lab` scenario behind the plan below declares `sink: {type: stdout}`, one `/30` target, and one TCP-connect prober on port 22:

```json
[
  {
    "scenario": "lab",
    "targets": [
      {
        "target": "10.0.0.0/30",
        "resolution": {
          "resolved": {
            "total": 2,
            "sample": [
              "10.0.0.1",
              "10.0.0.2"
            ]
          }
        }
      }
    ],
    "probers": [
      "tcp_connect (ports 22)"
    ],
    "fuser": "direct (include_unreachable false, confidence_baseline 0.1, confidence_per_signal 0.1)",
    "classifier": "rules (merge_mode extend, platform_rules 0, role_rules 0)",
    "encoder": "ndjson",
    "sink": "stdout",
    "max_concurrent": 64,
    "probe_rate": null,
    "retries": 0,
    "timeout_ms": 1000,
    "total_probes": 2
  }
]
```

A `--file` with several scenarios produces one array element per scenario, in file order. When a target fails to resolve, its `resolution` holds an `error` string instead of the address list. Every other target still appears. The exit code follows the text plan's rule: `1` when any target fails to resolve, `0` when they all resolve. The plan goes to stdout and the error message to stderr, so `jq` still reads a plan that exits `1`.

The plan validates against [`discovery-plan-v2.json`](../reference/schema/discovery-plan.md). Before `v2`, `resolution.resolved` was a bare array of addresses, so a `jq` expression written against the old shape — `.[].targets[].resolution.resolved[]` — now reads `.[].targets[].resolution.resolved.sample[]`.

## Override precedence in YAML-driven mode

CLI flags override YAML values. Merge order per scenario, lowest to highest:

1. `defaults:` block in the scenario file.
2. Per-scenario fields (`max_concurrent`, `probe_rate`, `retries`, `timeout_ms`, `sink`, `encoder`, `fuser`, `name`).
3. CLI flags (`--concurrency`, `--rate`, `--retries`, `--timeout-ms`, `--format`, `--sink` + `--output` / Kafka flags).

Only fields you passed a flag for are overridden. `rastreo discover --file scan.yml --concurrency 32` overrides the YAML `max_concurrent` and leaves the rate, sink, and timeout untouched. Omitting a flag lets the YAML value win.

`encoder` has one extra step, because it is the only field the CLI fills in when the scenario left it out. Omitting `--format` keeps the scenario's `encoder` when the scenario set one. When it set none, the [destination decides](#where-the-default-comes-from): the table for a stdout sink, NDJSON everywhere else. That choice is made after `--sink` is applied. So `--file scan.yml --sink file --output scan.ndjson` writes NDJSON, even when the file said `sink: {type: stdout}`.

## Progress

A scan prints a live progress line to stderr while it runs. It shows how far the scan has reached and how much is left, so you can see it is still working. The line carries:

- `hosts: N/M (X%)` — targets finished (`N`) out of the total to probe (`M`), and the percentage that represents.
- `records: R` — `DeviceRecord` events emitted so far.
- `rate: N/s` — targets finished per second, averaged over the whole run.
- `elapsed: T` — how long the scan has been running.
- `eta: T` — estimated time left. It appears once at least three targets have finished, so the estimate uses real timing, and it drops off at `100%`.

On a terminal the line redraws in place four times a second and clears when the scan ends; the completion banner prints next.

When stderr is not a terminal, each update prints as a new line every five seconds instead. Piping stderr to another program or redirecting it to a file keeps the full history in order.

Progress goes to stderr, never stdout. An in-place redraw owns the terminal row it paints, and a periodic update owns the line it takes, so rastreo only draws one when the records are landing somewhere else. **On the default stdout sink the records go to the same screen, so the progress line is dropped.** Otherwise a table row and a redraw would end up on the same row and overwrite each other. Merging the two streams into one file or one pipe — `> scan.txt 2>&1`, `2>&1 | jq` — gives the records and the line one destination again, so a run writing records to stdout drops the line there too. A run whose sink is a file or a broker puts nothing on stdout, and the line draws whatever the streams are wired to.

Three ways to get it back. Each one gives the records a destination of their own:

- Redirect stdout: `> scan.txt`, `| jq`, `| tee`, with stderr left where it is. Records leave the terminal and the line redraws in place.
- Use `--sink file`. Same result, and the records are kept.
- Redirect stderr: `2> scan.log`. The line is written to the file as whole lines every five seconds.

A long scan usually runs in one of these shapes anyway, and that is where progress helps most.

```bash
rastreo discover --target 192.0.2.0/24 --probe tcp_connect --port 80 --concurrency 8 2> scan.log
```

The `2> scan.log` above redirects stderr, so the progress updates are written to `scan.log` as periodic lines:

```text
▶ discover  targets: 1 | probes: tcp_connect (ports 80) | concurrency: 8 | timeout: 1000ms | sink: stdout
  hosts: 42/254 (16%) | records: 0 | rate: 8.4/s | elapsed: 5.0s | eta: 25.2s
  hosts: 83/254 (32%) | records: 0 | rate: 8.3/s | elapsed: 10.0s | eta: 20.6s
  hosts: 241/254 (94%) | records: 0 | rate: 8.0/s | elapsed: 30.0s | eta: 1.6s
■ discover  completed in 31.8s | hosts: 254 | records: 0 | probes: 254 | faults: 0 | sink: stdout
```

The last line is the completion banner; [Runtime hints](#runtime-hints) explains its fields. In YAML-driven mode each scenario gets its own start and completion banner, followed by one aggregate banner for the whole file. The aggregate counts only the scenarios that ran to completion — a file where one of three scenarios failed reads `1 of 3 scenarios`, and its `■` turns yellow. A scenario [skipped for having no probers](#a-scenario-rastreo-cannot-build-gets-no-plan) counts the same way, and adds a `skipped: N` field, so a file that only partly ran never looks like one that ran clean.

!!! note "A fast scan may show no progress line"
    On a terminal the line redraws in place four times a second. When stderr is redirected to a file or a pipe it is written as a whole line every five seconds instead, so a scan that finishes sooner shows only the two banners. Progress is for the long scans where it helps — a wide CIDR, a slow link, or a low concurrency setting.

## Cancellation

On `SIGINT` (ctrl-c) or `SIGTERM`, `rastreo discover` finishes any in-flight probes that have already started, fuses the outcomes collected so far, emits the resulting records to the sink, and flushes the sink before exiting. The completion banner on stderr reads `cancelled after` instead of `completed in` when this path runs, and its `■` turns yellow. The exit code is still `0` for a clean shutdown — non-zero is reserved for errors.

Records that hadn't been emitted yet at the moment of cancellation are still written if they came from outcomes the pipeline had already gathered. Records from probers that hadn't started yet are not produced — `--target 10.0.0.0/24 --probe tcp_connect --port 22,80,443 ...` cancelled after the `22` sweep gives you records for port 22 only.

## Checkpoints

A wide scan can run for hours. A crash, a scan timeout, or a `SIGKILL` can stop the process partway. Without a checkpoint, you lose all progress and the next run starts from zero. `--checkpoint <PATH>` writes a small file that records how far the scan reached. A later run can continue from that point instead of scanning everything again.

```bash
rastreo discover \
  --target 10.0.0.0/16 \
  --probe tcp_connect \
  --port 22,443 \
  --sink file \
  --output /var/log/scan.ndjson \
  --checkpoint /var/log/scan.checkpoint
```

rastreo writes the checkpoint every 5000 targets by default. `--checkpoint-interval <N>` sets how many targets pass between writes. A smaller number checkpoints more often and loses less work on a crash. A larger number writes less often. The minimum is 1.

!!! tip "Check the request before you start the scan"
    Add `--dry-run` to any `--checkpoint` or `--resume` command to find out whether it would be accepted. A dry-run applies the same three refusals a run applies, and writes nothing. See [Checkpoint and resume checks](#checkpoint-and-resume-checks).

### Resuming

`--resume` continues a scan from its checkpoint. Point it at the same `--checkpoint <PATH>` the interrupted run wrote. rastreo skips the targets already written to the sink and probes only the rest.

```bash
rastreo discover \
  --target 10.0.0.0/16 \
  --probe tcp_connect \
  --port 22,443 \
  --sink file \
  --output /var/log/scan.ndjson \
  --checkpoint /var/log/scan.checkpoint \
  --resume
```

The resumed run keeps the original scan's id, so records from both runs group under one logical scan. The progress line continues from where the last run stopped. A scan interrupted at 2 of 14 targets resumes at `hosts: 2/14`, not `0/12`. When the resumed scan finishes, rastreo removes the checkpoint, exactly as a fresh scan does on completion.

The eligibility rules in [Which scans can checkpoint](#which-scans-can-checkpoint) still apply. `--resume` re-checks them and refuses an ineligible scenario before probing.

**The checkpoint must match the scan.** A checkpoint is tied to two things: the ordered target list and the sink destination. rastreo refuses to resume when either changed, because the new records would describe a different scan or reach the wrong destination:

```text
Error: checkpoint does not match the current scenario: the target sequence or append destination changed, so resuming would produce a different scan or append to the wrong destination
```

Changing only a performance knob is allowed. `--concurrency`, `--rate`, `--timeout-ms`, and `--retries` do not change which targets are scanned or where their records go. A resume with a different value for one of them warns, then continues.

**A missing checkpoint is an error.** `--resume` needs an existing checkpoint to continue from. When the file is absent, rastreo refuses rather than start over from zero:

```text
⚠ hint: --resume continues a checkpoint an earlier --checkpoint run wrote. Drop --resume to scan from zero.
Error: no checkpoint to resume at /var/log/scan.checkpoint; resuming continues a checkpoint an earlier run wrote to this path
```

!!! info "One target may be scanned twice"
    Resume restarts at the last checkpointed target, not the one after it. So exactly one target — the boundary — may be scanned in both runs. Its record is a harmless duplicate that a consumer keying on [`identity_key`](identity.md) collapses. This is deliberate. It guarantees no scanned target is ever skipped, even if the process died while writing that target's record.

!!! note "Checkpointing runs one scenario at a time"
    A checkpoint covers a single-scenario run: the flag-driven form, or a `--file` with exactly one scenario. A multi-scenario file is refused, because one checkpoint path cannot record several scenarios' progress. The refusal comes at `--checkpoint`, before the scan, rather than at the `--resume` that would later find the file unusable.

    ```text
    Error: --checkpoint supports a single-scenario run; 'scan.yml' has 2 scenarios. One checkpoint path cannot record several scenarios' progress, so a checkpoint written here could not be resumed.
    ```

### Which scans can checkpoint

A checkpoint is only offered for a scan that can be resumed correctly. rastreo checks three things before probing and refuses the scan if any fails:

| Part | Eligible | Not eligible |
|---|---|---|
| [Fuser](enrichment.md) | `direct`, `mib_enrichment` | `identity` |
| [Probers](../probe/index.md) | every prober except the two on the right | `lldp`, `gnmi` |
| [Sink](sinks.md) | `file`, `kafka`, `nats` | `stdout`, `memory` |

Each rule guards against a resume that would produce a different result:

- **Fuser** — the [`identity`](identity.md) fuser correlates records across the whole scan to merge one device seen on several addresses. A resume replays only the targets left, so it cannot rebuild that whole-scan state. The `direct` and `mib_enrichment` fusers emit each record on its own and resume cleanly.
- **Probers** — the [`lldp`](../probe/lldp.md) and [`gnmi`](../probe/gnmi.md) probers build a second output stream — [topology links](topology.md) or [collection profiles](collection-profile.md) — from whole-scan state a checkpoint cannot replay.
- **Sink** — a resume appends new records where the previous run stopped. The `file`, `kafka`, and `nats` sinks have a durable destination to append to. The `stdout` and `memory` sinks do not.

An ineligible scenario is refused before any probe runs, with an error naming the reason:

```text
Error: scenario is not resume-safe: the stdout sink has no durable append destination to resume into
```

### What a checkpoint protects against

Before each checkpoint write, rastreo flushes the sink. Every record up to that point leaves the process and reaches the operating system first. The checkpoint then records that position. Because the flush happens first, the checkpoint never claims more progress than the sink actually holds.

This protects against the process dying: a crash, a scan timeout, or `Ctrl-C`. The records are safe with the operating system, and the checkpoint matches them.

!!! warning "Not protected: power loss and kernel panic"
    The flush hands records to the operating system, not all the way to the physical disk. A sudden power loss or a kernel panic can still lose records the system had buffered but not yet written to disk. A checkpoint protects against a process dying, not against the machine dying.

### It will not overwrite an existing checkpoint

If a file already exists at the `--checkpoint` path, the scan refuses to start and leaves the file untouched. This protects a checkpoint from an earlier run you may still want. To continue that run instead of starting over, resume it with [`--resume`](#resuming). Remove the file to start fresh:

```text
Error: a checkpoint already exists at /var/log/scan.checkpoint; remove it to start a fresh scan
```

A file at the path that is not a valid checkpoint is refused the same way, with a `corrupt` message. rastreo never overwrites it.

A dry-run refuses the same path, so you can check before the scan starts. See [Checkpoint and resume checks](#checkpoint-and-resume-checks).

### Lifecycle

- The scan **removes** the checkpoint when it finishes successfully. A completed scan has nothing left to resume, and a leftover file would block the next run.
- The scan **keeps** the checkpoint when it is cancelled or killed. That file is the record of how far the scan got.

## Runtime hints

The CLI prints one `⚠ hint:` line to stderr under the completion banner. It appears when a probe faulted, or when a scan without a fault emitted zero records. Hints are suppressed when the run was cancelled, when `--dry-run` was used, and under `-q`.

One case is a scan that reached nothing. Nobody answered, `faults` stays at `0`, and you get the generic hint:

```text
■ discover  completed in 1ms | hosts: 1 | records: 0 | probes: 1 | faults: 0 | sink: stdout
⚠ hint: 0 records emitted — no probe reached an open port. Check target reachability and port list.
```

When `faults` is above `0`, a probe hit a fault. Run with `-v` to see the `faults by kind` and `first fault` breakdown under the banner. The CLI derives the hint from the fault's typed kind, not from the wording of the error. The same fault always gives the same advice. The fault hint prints whenever a fault occurred, even when the scan also produced records. An SNMP agent that answers with a reply rastreo cannot decode keeps the device and emits a record. The CLI still prints the `decode_failed` hint under that banner. A probe blocked by a missing `CAP_NET_RAW` capability gets a `permission_denied` fault. The hint then tells you to grant the capability or check local egress policy. A probe that needed a name lookup gets a `dns_failed` fault when the lookup did not resolve, and the hint points at the resolver. A fault kind with no specific remedy (`other`) prints no hint. Only one hint is printed per scan.

An SNMP probe blocked by a local firewall REJECT in the OUTPUT chain also surfaces as `permission_denied` and gets the same egress-policy hint.

The same hints run when the scan itself fails — a target name that does not resolve, for example. The CLI prints the error on stderr and adds the hint next to it.

## Exit codes

`rastreo discover` exits `0` on success and `1` on any error. Errors are written to stderr as a single line. Validation errors (for example, `--sink file` without `--output`) fail before any probe runs.

## See also

- [Scenario schema](../reference/scenario.md) — the full YAML shape accepted by `--file`.
- [Validate](validate.md) — lint a scenario file offline before you run it, including secured sink configs with no broker.
- [Catalog](catalog.md) — `@name` references and the catalog directory search order.
- [Targets](targets.md) — the four target forms and how the CLI detects each one.
- [Sinks](sinks.md) — stdout, file, and Kafka output in depth.
