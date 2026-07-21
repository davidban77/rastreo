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

`--file <PATH>` (`-f <PATH>`) loads a `ScenarioFile` and runs every scenario entry in order. The file must set `version: 1` and `kind: discovery`; other values are rejected. See [Scenario schema](../reference/scenario.md) for the full field list. The argument also accepts a `@name` catalog reference that resolves to a scenario file in `~/.config/rastreo/catalog/` or `/etc/rastreo/catalog/` — see [Catalog](catalog.md) for the search order and setup.

A single-scenario file that probes an HTTP target and a DNS resolver:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
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
| `--sink <SINK>` | `stdout` (flag-driven) / YAML `sink` (YAML-driven) | Where records are emitted. Possible values: `stdout`, `file`. `kafka` is available when the binary is built with `--features kafka`. In YAML-driven mode, setting `--sink` overrides the sink configured in the file. See [Sinks](sinks.md). |
| `--output <PATH>` | — | Output file path for `--sink file`. Required when the file sink is selected. |
| `--brokers <BROKERS>` | — | Comma-separated Kafka brokers for `--sink kafka`. Requires the `kafka` build feature. |
| `--topic <TOPIC>` | — | Kafka topic for `--sink kafka`. Requires the `kafka` build feature. |
| `--kafka-flush-per-record` | — | Flush every `DeviceRecord` to Kafka as a separate message. Mutually exclusive with `--kafka-batch-threshold`. Only meaningful with `--sink kafka`. |
| `--kafka-batch-threshold <BYTES>` | `65536` (64 KiB) | Batch threshold in bytes. Records accumulate until the buffer reaches this size, then flush in one produce request that carries one message per record. Minimum 1. Only meaningful with `--sink kafka`. |
| `--concurrency <N>` | `64` (flag-driven) / YAML `max_concurrent` (YAML-driven) | Maximum number of probes in flight at once. Minimum value is 1. In YAML-driven mode, setting `--concurrency` overrides the scenario's `max_concurrent`. |
| `--rate <N>` | unset — no pacing (flag-driven) / YAML `probe_rate` (YAML-driven) | Maximum number of probes started per second. Minimum value is 1. When unset, probes start as fast as concurrency allows. In YAML-driven mode, setting `--rate` overrides the scenario's `probe_rate`. |
| `--retries <N>` | `0` (flag-driven) / YAML `retries` (YAML-driven) | Retransmit attempts for the connectionless probers (UDP, SNMP, DNS, reverse DNS). Range 0–1024; `0` is single-shot. In YAML-driven mode, setting `--retries` overrides the scenario's `retries`. See [Retries on lossy links](#retries-on-lossy-links). |
| `--timeout-ms <MS>` | `1000` (flag-driven) / YAML `timeout_ms` (YAML-driven) | Per-probe timeout in milliseconds. Minimum value is 1. In YAML-driven mode, setting `--timeout-ms` overrides the scenario's `timeout_ms`. |
| `--dry-run` | off | Validate the scenario, resolve targets, print the expansion to stdout, and exit without probing or opening a sink. Useful before running against production. See [Dry-run mode](#dry-run-mode) below. |
| `--dry-run-format <text\|json>` | `text` | Output format for `--dry-run`. `text` is the human-readable plan. `json` emits a machine-readable JSON array of plan objects, one per scenario, ready to pipe to `jq`. Only meaningful with `--dry-run`. See [Machine-readable output](#machine-readable-output) below. |
| `--checkpoint <PATH>` | — | Write a resume checkpoint to this file during the scan, so a scan that dies can be resumed later. The scenario must be resume-safe or the scan is refused before probing. See [Checkpoints](#checkpoints). |
| `--checkpoint-interval <N>` | `5000` | Number of targets between checkpoint writes. Minimum 1. Ignored unless `--checkpoint` is set. See [Checkpoints](#checkpoints). |
| `--resume` | off | Continue an interrupted scan from the checkpoint at `--checkpoint <PATH>`: skip the targets already written and probe the rest. Requires `--checkpoint`. Works for a single scenario only. See [Resuming](#resuming). |
| `-v`, `--verbose` | info | Increase log verbosity. `-v` is debug, `-vv` (or more) is trace. Logs go to stderr. |
| `-q`, `--quiet` | — | Drop the log level to `error`. Mutually exclusive in spirit with `-v`. |

!!! info "Concurrency vs rate"
    These are two different limits. `--concurrency` (YAML `max_concurrent`) sets how many probes run at the same time. `--rate` (YAML `probe_rate`) sets how many probes start each second. They compose: with `--concurrency 64 --rate 50`, up to 64 probes run at once, but no more than 50 start per second. The rate bounds the scan whenever it is the tighter limit. Leave `--rate` unset to let probes start as fast as concurrency allows — useful to be gentle on a fragile network.

## Retries on lossy links

On a clean LAN, one UDP, SNMP, or DNS request reaches the target and one reply comes back. On a congested or long-distance link, either the request or the reply can be dropped. A single dropped packet makes a live host look unreachable — a false negative. The `retries` knob tells a connectionless prober to resend the request before giving up. The default `0` sends one request and never resends. On a clean LAN (packet loss under 0.1%) one request almost always arrives, so `retries` stays off by default and is rarely needed.

Set it two ways:

- **Scenario field** `retries: N` — at the `defaults:` level or on one scenario, alongside `timeout_ms`.
- **CLI flag** `--retries N` — with `--file`, this overrides the scenario `retries`.

Only the connectionless probers that lack their own retransmission honor `retries`:

- **UDP** service probers — memcached, NTP, SIP, and STUN.
- **SNMP** — v1, v2c, and v3.
- **DNS** and **reverse DNS**.

TCP-based probers (`tcp_connect`, `http`, `ssh`, `tls`) ignore `retries`, because TCP already resends at the transport layer. ICMP has its own `count` knob instead, which defaults to 3 echoes. ARP and NDP do not honor `retries` yet. Flag-driven mode (`--target` + `--port`) only runs `tcp_connect`, so `--retries` changes nothing there. To reach the connectionless probers, use `--file` with a scenario that lists them.

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

## Dry-run mode

`--dry-run` validates the scenario, resolves targets (DNS lookups run for real), prints the expanded plan to stdout, and exits without probing anything or opening a sink. It works in both flag-driven mode (`--target` + `--port`) and YAML-driven mode (`--file`). CLI overrides (`--sink`, `--concurrency`, `--retries`, `--timeout-ms`) are applied to the plan — what you see is what would run.

The output shows one block per scenario listing each target's DNS / CIDR / range expansion, the configured probers with their parameters, the sink kind and destination, and the effective concurrency, probe rate, and per-probe timeout. The rate line reads `unlimited` when no pacing is set. A bottom line reports the total probe count: unique IPs × probers, counting an address once even when several targets cover it. This matches the real scan for targets that do not overlap. When targets overlap, the real scan probes each shared address once per target, so it runs more probes than this count shows. See [Overlapping targets](targets.md#overlapping-targets).

CIDRs and ranges that expand to more than six addresses are truncated with an ellipsis and a count. DNS resolution failures are printed inline (`example.com → <error: DNS lookup failed: ...>`) and the run continues with the remaining targets. The exit code is `0` when at least one target resolves and `1` only when every target fails to resolve — in that case there is nothing left to probe.

Kafka, NATS, and file sinks are described from the configured values only. `--dry-run` never opens a network connection to the sink or writes to the output file, so a bogus broker address in `--brokers` completes in milliseconds instead of hanging.

```bash
rastreo discover --target 10.0.0.0/24 --port 22,80 --dry-run
```

```text
[dry-run] would run 1 scenario
  scenario: discovery
    targets:
      10.0.0.0/24 → 10.0.0.1, 10.0.0.2, 10.0.0.3, ... (254 addresses)
    probers: tcp_connect (ports 22, 80)
    sink: stdout
    concurrency: 64
    rate: unlimited
    retries: 0
    timeout_ms: 1000
total probes: 254
```

### Machine-readable output

`--dry-run-format` chooses how the plan is printed. The default `text` is the human-readable plan shown above, unchanged. Set `json` to emit a plan you can pipe to `jq` or store as an artifact. Like the text plan, `json` resolves targets only — it never probes a host or opens a sink.

```bash
rastreo discover --file @lab --dry-run --dry-run-format json
```

The output is a JSON array with one object per scenario. Each object carries these fields:

- `scenario` — the scenario name. This is the plain name, the same value the HTTP server reports for a dry-run scan.
- `targets` — one entry per configured target. Each has the original `target` string and a `resolution` that is either `{"resolved": [ip, ...]}` or `{"error": "..."}`.
- `probers` — the probers that would run, with their ports.
- `sink` — the destination.
- `max_concurrent` — probes allowed in flight at once.
- `probe_rate` — probes started per second, or `null` when no pacing is set.
- `retries` — retransmit attempts for the connectionless probers.
- `timeout_ms` — per-probe timeout in milliseconds.
- `total_probes` — unique IPs × probers, deduplicated across overlapping targets.

```json
[
  {
    "scenario": "lab",
    "targets": [
      {
        "target": "10.0.0.0/30",
        "resolution": {
          "resolved": ["10.0.0.1", "10.0.0.2"]
        }
      }
    ],
    "probers": ["tcp_connect (ports 22)"],
    "sink": "stdout",
    "max_concurrent": 64,
    "probe_rate": null,
    "retries": 0,
    "timeout_ms": 1000,
    "total_probes": 2
  }
]
```

A `--file` with several scenarios produces one array element per scenario, in file order. When a target fails to resolve, its `resolution` holds the error string and the plan still lists the remaining targets. The exit code follows the same rule as the text plan: `0` when at least one target resolves, `1` only when every target fails.

## Override precedence in YAML-driven mode

CLI flags override YAML values. Merge order per scenario, lowest to highest:

1. `defaults:` block in the scenario file.
2. Per-scenario fields (`max_concurrent`, `probe_rate`, `retries`, `timeout_ms`, `sink`, `encoder`, `fuser`, `name`).
3. CLI flags (`--concurrency`, `--rate`, `--retries`, `--timeout-ms`, `--sink` + `--output` / Kafka flags).

Only fields the CLI flag was explicitly set for are overridden. `rastreo discover --file scan.yml --concurrency 32` overrides the YAML `max_concurrent`, but leaves the rate, sink, and timeout untouched. Omitting a flag entirely lets the YAML value win.

## Progress

A scan prints a live progress line to stderr while it runs — updated repeatedly through a long scan, and shown once at completion for a fast one. It shows how far the scan has reached and how much is left, so you can see it is still working. The line carries four fields:

- `targets N/M` — targets finished (`N`) out of the total to probe (`M`).
- `(X%)` — percent of targets finished.
- `records R` — `DeviceRecord` events emitted so far.
- `ETA ~Ss` — estimated seconds left. It appears once at least three targets have finished, so the estimate uses real timing, and it drops off at `100%`.

The line updates at most once per second. On a terminal it redraws in place on a single line, then clears when the scan ends. The summary line prints next.

When stderr is not a terminal, each update prints as a new line instead. Piping stderr to another program or redirecting it to a file keeps the full history in order.

Progress goes to stderr, never stdout. Records stream to stdout on the default sink, so the progress line never mixes into them. If you pipe stdout to `jq` or a file, only the records pass through.

```bash
rastreo discover --target 192.0.2.0/28 --port 80 --concurrency 4 2> scan.log
```

The `2> scan.log` above redirects stderr, so the progress updates are written to `scan.log` as periodic lines:

```text
targets 4/14 (28%), records 0, ETA ~2s
targets 8/14 (57%), records 0, ETA ~1s
targets 12/14 (85%), records 0, ETA ~0s
targets 14/14 (100%), records 0
discovery complete: targets_resolved=14 probe_attempts=14 probe_errors=0 records_emitted=0 elapsed_ms=4010
```

The last line is the run summary; [Runtime hints](#runtime-hints) explains its fields. In YAML-driven mode each scenario reports its own progress line, under the `running <scenario>` header the CLI prints before it starts.

!!! note "A fast scan may show no progress line"
    The line first appears after one second. A small scan against a nearby host can finish in under a second, so you see only the summary line. Progress is for the long scans where it helps — a wide CIDR, a slow link, or a low concurrency setting.

## Cancellation

On `SIGINT` (ctrl-c) or `SIGTERM`, `rastreo discover` finishes any in-flight probes that have already started, fuses the outcomes collected so far, emits the resulting records to the sink, and flushes the sink before exiting. The summary line on stderr reads `discovery cancelled:` instead of `discovery complete:` when this path runs. The exit code is still `0` for a clean shutdown — non-zero is reserved for errors.

Records that hadn't been emitted yet at the moment of cancellation are still written if they came from outcomes the pipeline had already gathered. Records from probers that hadn't started yet are not produced — `--target 10.0.0.0/24 --port 22,80,443 ...` cancelled after the `22` sweep gives you records for port 22 only.

## Checkpoints

A wide scan can run for hours. A crash, a scan timeout, or a `SIGKILL` can stop the process partway. Without a checkpoint, you lose all progress and the next run starts from zero. `--checkpoint <PATH>` writes a small file that records how far the scan reached. A later run can continue from that point instead of scanning everything again.

```bash
rastreo discover \
  --target 10.0.0.0/16 \
  --port 22,443 \
  --sink file \
  --output /var/log/scan.ndjson \
  --checkpoint /var/log/scan.checkpoint
```

rastreo writes the checkpoint every 5000 targets by default. `--checkpoint-interval <N>` sets how many targets pass between writes. A smaller number checkpoints more often and loses less work on a crash. A larger number writes less often. The minimum is 1.

### Resuming

`--resume` continues a scan from its checkpoint. Point it at the same `--checkpoint <PATH>` the interrupted run wrote. rastreo skips the targets already written to the sink and probes only the rest.

```bash
rastreo discover \
  --target 10.0.0.0/16 \
  --port 22,443 \
  --sink file \
  --output /var/log/scan.ndjson \
  --checkpoint /var/log/scan.checkpoint \
  --resume
```

The resumed run keeps the original scan's id, so records from both runs group under one logical scan. The progress line continues from where the last run stopped. A scan interrupted at 2 of 14 targets resumes at `targets 2/14`, not `0/12`. When the resumed scan finishes, rastreo removes the checkpoint, exactly as a fresh scan does on completion.

The eligibility rules in [Which scans can checkpoint](#which-scans-can-checkpoint) still apply. `--resume` re-checks them and refuses an ineligible scenario before probing.

**The checkpoint must match the scan.** A checkpoint is tied to two things: the ordered target list and the sink destination. rastreo refuses to resume when either changed, because the new records would describe a different scan or reach the wrong destination:

```text
Error: resume error: checkpoint does not match the current scenario: the target sequence or append destination changed, so resuming would produce a different scan or append to the wrong destination
```

Changing only a performance knob is allowed. `--concurrency`, `--rate`, `--timeout-ms`, and `--retries` do not change which targets are scanned or where their records go. A resume with a different value for one of them warns, then continues.

**A missing checkpoint is an error.** `--resume` needs an existing checkpoint to continue from. When the file is absent, rastreo refuses rather than start over from zero:

```text
Error: resume error: no checkpoint to resume at /var/log/scan.checkpoint; --resume requires an existing checkpoint at this path
```

!!! info "One target may be scanned twice"
    Resume restarts at the last checkpointed target, not the one after it. So exactly one target — the boundary — may be scanned in both runs. Its record is a harmless duplicate that a consumer keying on [`identity_key`](identity.md) collapses. This is deliberate. It guarantees no scanned target is ever skipped, even if the process died while writing that target's record.

!!! note "`--resume` runs one scenario at a time"
    Resume works for a single-scenario run: the flag-driven `--target` / `--port` form, or a `--file` with exactly one scenario. A multi-scenario file is refused, because one checkpoint path cannot record several scenarios' progress.

    ```text
    Error: --resume supports a single-scenario run; 'scan.yml' has 2 scenarios
    ```

### Which scans can checkpoint

A checkpoint is only offered for a scan that can be resumed correctly. rastreo checks three things before probing and refuses the scan if any fails:

| Part | Eligible | Not eligible |
|---|---|---|
| [Fuser](enrichment.md) | `direct`, `oui_enrichment`, `mib_enrichment` | `identity` |
| [Probers](../probe/index.md) | every prober except the two on the right | `lldp`, `gnmi` |
| [Sink](sinks.md) | `file`, `kafka`, `nats` | `stdout`, `memory` |

Each rule guards against a resume that would produce a different result:

- **Fuser** — the [`identity`](identity.md) fuser correlates records across the whole scan to merge one device seen on several addresses. A resume replays only the targets left, so it cannot rebuild that whole-scan state. The `direct`, `oui_enrichment`, and `mib_enrichment` fusers emit each record on its own and resume cleanly.
- **Probers** — the [`lldp`](../probe/lldp.md) and [`gnmi`](../probe/gnmi.md) probers build a second output stream — [topology links](topology.md) or [collection profiles](collection-profile.md) — from whole-scan state a checkpoint cannot replay.
- **Sink** — a resume appends new records where the previous run stopped. The `file`, `kafka`, and `nats` sinks have a durable destination to append to. The `stdout` and `memory` sinks do not.

An ineligible scenario is refused before any probe runs, with an error naming the reason:

```text
Error: resume error: scenario is not resume-safe: the stdout sink has no durable append destination to resume into
```

### What a checkpoint protects against

Before each checkpoint write, rastreo flushes the sink. Every record up to that point leaves the process and reaches the operating system first. The checkpoint then records that position. Because the flush happens first, the checkpoint never claims more progress than the sink actually holds.

This protects against the process dying: a crash, a scan timeout, or `Ctrl-C`. The records are safe with the operating system, and the checkpoint matches them.

!!! warning "Not protected: power loss and kernel panic"
    The flush hands records to the operating system, not all the way to the physical disk. A sudden power loss or a kernel panic can still lose records the system had buffered but not yet written to disk. A checkpoint protects against a process dying, not against the machine dying.

### It will not overwrite an existing checkpoint

If a file already exists at the `--checkpoint` path, the scan refuses to start and leaves the file untouched. This protects a checkpoint from an earlier run you may still want. To continue that run instead of starting over, resume it with [`--resume`](#resuming). Remove the file to start fresh:

```text
Error: resume error: a checkpoint already exists at /var/log/scan.checkpoint; remove it to start a fresh scan
```

A file at the path that is not a valid checkpoint is refused the same way, with a `corrupt` message. rastreo never overwrites it.

### Lifecycle

- The scan **removes** the checkpoint when it finishes successfully. A completed scan has nothing left to resume, and a leftover file would block the next run.
- The scan **keeps** the checkpoint when it is cancelled or killed. That file is the record of how far the scan got.

## Runtime hints

The CLI prints one `hint:` line to stderr next to the summary. It appears when a probe faulted, or when a scan without a fault emitted zero records. Hints are suppressed only when the run was cancelled or when `--dry-run` was used.

One case is a scan that reached nothing. Nobody answered, `probe_errors` stays at `0`, and you get the generic hint:

```text
discovery complete: targets_resolved=1 probe_attempts=1 probe_errors=0 records_emitted=0 elapsed_ms=1
hint: 0 records emitted — no probe reached an open port. Check target reachability and port list.
```

When `probe_errors` is above `0`, a probe hit a fault. The CLI derives the hint from the fault's typed kind, not from the wording of the error. The same fault always gives the same advice. The fault hint prints whenever a fault occurred, even when the scan also produced records. An SNMP agent that answers with a reply rastreo cannot decode keeps the device and emits a record. The CLI still prints the `decode_failed` hint next to that summary. A probe blocked by a missing `CAP_NET_RAW` capability gets a `permission_denied` fault. The hint then tells you to grant the capability or check local egress policy. A probe that needed a name lookup gets a `dns_failed` fault when the lookup did not resolve, and the hint points at the resolver. A fault kind with no specific remedy (`other`) prints no hint. Only one hint is printed per scan.

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
