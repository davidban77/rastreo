---
description: What one discovery run did: how every scenario it reached ended, and the run's totals.
---

# RunReport

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

What one discovery run did: how every scenario it reached ended, and the run's totals.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/run-report-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/run_report.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `aggregate` | [`RunAggregate`](#runaggregate) | yes | — |
| `report_version` | uint32 | yes | Version of this document's shape. A consumer that does not recognise it cannot assume the field set. |
| `scenarios` | array<[`ScenarioReport`](#scenarioreport)> | yes | One entry per scenario the run reached, in run order. Shorter than `aggregate.scenario_counts.total` when the run was cancelled before reaching the rest. |

## Definitions

### `DiscoverySummary` {#discoverysummary}

| Field | Type | Required | Description |
|---|---|---|---|
| `cancelled` | boolean | no | True when the run terminated early via the cancellation token; counters reflect partial progress. |
| `dlq_records` | uint | no | Records delivered to a DLQ destination during this scan. |
| `dlq_records_by_type_and_class` | array<[[`SinkType`](#sinktype), [`SinkErrorClass`](#sinkerrorclass), uint64]> | no | DLQ deliveries keyed by `(destination sink type, failure class)`; empty when nothing was quarantined. |
| `elapsed_ms` | uint64 | yes | Milliseconds one scan took; on a summary folding several, the sum of their durations. |
| `error_counts` | object | no | Faulted probes tallied by fault kind; empty when no probe faulted. |
| `first_probe_error` | [`ProbeFault`](#probefault) \| null | no | Kind and sample detail of the first probe that faulted; latched once per scan, absent when no probe faulted. |
| `links_emitted` | uint | no | Topology links emitted on the second stream; `0` when no LLDP data was collected. |
| `probe_attempts` | uint | yes | — |
| `probes_by_kind` | array<[`ProbeKindSummary`](#probekindsummary)> | no | Per-probe-kind attempted / errored breakdown; empty when no probes ran. |
| `profiles_emitted` | uint | no | Collection profiles emitted on the second stream; `0` when no gNMI capability data was collected. |
| `records_emitted` | uint | yes | — |
| `sink_type` | [`SinkType`](#sinktype) \| null | no | Concrete sink kind the scan wrote against. |
| `targets_resolved` | uint | yes | — |
| `unresolvable_targets` | array<string> | no | Targets the network answered for with no addresses, as written in the scenario and in input order; each was probed zero times. Empty when every target resolved. |

### `ProbeErrorKind` {#probeerrorkind}

The named reason a probe faulted, carried as data on the fault the outcome holds.

One of:

- `auth_failed`
- `permission_denied`
- `dns_failed`
- `decode_failed`
- `other`

### `ProbeFault` {#probefault}

A typed probe fault carried on the outcome: the probe attempted a target and learned that
something broke, without discarding the signals it may have gathered on other ports.

| Field | Type | Required | Description |
|---|---|---|---|
| `detail` | string | yes | — |
| `kind` | [`ProbeErrorKind`](#probeerrorkind) | yes | — |

### `ProbeKind` {#probekind}

One of:

- `TcpConnect`
- `Udp`
- `Http`
- `Dns`
- `Snmp`
- `Arp`
- `Ndp`
- `Ssh`
- `Icmp`
- `Tls`
- `ReverseDns`
- `Gnmi`
- `Lldp`

### `ProbeKindSummary` {#probekindsummary}

| Field | Type | Required | Description |
|---|---|---|---|
| `attempted` | uint | yes | — |
| `errored` | uint | yes | — |
| `kind` | [`ProbeKind`](#probekind) | yes | — |

### `RunAggregate` {#runaggregate}

The run's totals. `summary` folds every scenario's counters together, so its `elapsed_ms` is the
sum of the scenarios' durations rather than wall clock, and it attributes no `sink_type`.

| Field | Type | Required | Description |
|---|---|---|---|
| `scenario_counts` | [`ScenarioTally`](#scenariotally) | yes | — |
| `summary` | [`DiscoverySummary`](#discoverysummary) | yes | — |

### `ScenarioOutcome` {#scenariooutcome}

How one scenario the run reached ended; `skipped` is a scenario that declared no probers and never ran.

One of:

- `completed`
- `failed`
- `skipped`

### `ScenarioReport` {#scenarioreport}

| Field | Type | Required | Description |
|---|---|---|---|
| `outcome` | [`ScenarioOutcome`](#scenariooutcome) | yes | — |
| `scenario` | string | yes | The scenario's own name, or `unnamed` when it declared none. |
| `summary` | [`DiscoverySummary`](#discoverysummary) \| null | no | Absent when the scenario produced none: it was skipped, or it failed before the scan returned one. |

### `ScenarioTally` {#scenariotally}

How many scenarios the run was asked for and how the ones it reached ended. `completed + failed +
skipped` is the fold over the report's entries, and falls short of `total` when the run was
cancelled before reaching the rest.

| Field | Type | Required | Description |
|---|---|---|---|
| `completed` | uint | yes | — |
| `failed` | uint | yes | — |
| `skipped` | uint | yes | — |
| `total` | uint | yes | — |

### `SinkErrorClass` {#sinkerrorclass}

Bounded taxonomy of sink failure classes surfaced on `sink_errors_total` and `dlq_records_total`.

Each concrete sink tags its failures with one of these classes at the failure site, and the class
travels with the error rather than being re-derived from its message. The set grows as sinks are
added, so a document may carry a class a cached schema copy does not list.

One of:

- `publish_failure`
- `ack_rejection`
- `produce_failure`
- `write_failure`
- `flush_failure`
- `other`

### `SinkType` {#sinktype}

Concrete sink kind — surfaced on `dlq_records_total{sink_type}` and set on `DiscoverySummary`.

One of:

- `stdout`
- `file`
- `memory`
- `kafka`
- `nats`
- `tee`

