---
description: Run a TCP-connect discovery scan against a single host, read the resulting DeviceRecord on stdout, and learn what each field means.
---

# First scan

In this walkthrough you probe a single TCP port on a known-reachable host and read the resulting `DeviceRecord` off stdout. The scan takes one command, no config file, and prints one NDJSON line per device found.

## Pick a target

You need a host that accepts TCP on the port you ask about. Two easy options:

- **A public HTTPS endpoint**, such as `1.1.1.1:443`. Reachable from any host with outbound internet — the simplest path for a first scan.
- **The local compose stack**, which brings up three nginx target containers serving HTTP on port 80. Start it with `docker compose up -d` from the repository root. The containers live on a `10.50.0.0/24` Docker bridge network at `10.50.0.10`, `10.50.0.11`, and `10.50.0.12`. From your host the bridge addresses are not directly reachable, so run the CLI from inside the network: `docker compose exec rastreo-server /rastreo discover --target 10.50.0.10 --port 80`.

The rest of this page uses `1.1.1.1:443` because it works without any extra setup.

## Run the scan

```bash
rastreo discover --target 1.1.1.1 --port 443
```

`rastreo discover` writes one NDJSON `DeviceRecord` per line to stdout. The progress summary and any log lines go to stderr, so stdout stays clean for downstream tools.

Stdout (one line, formatted here across multiple lines for reading):

```json
{
  "identity_key": "ip:1.1.1.1",
  "mgmt_ip": "1.1.1.1",
  "mac": null,
  "manufacturer": null,
  "platform": null,
  "os_version": null,
  "role": null,
  "confidence": 0.2,
  "last_seen": "2026-07-25T10:25:21.320939Z",
  "signals": [ { "OpenPort": 443 } ],
  "probe_kinds": [ "TcpConnect" ],
  "schema_version": "v1",
  "schema_id": "https://davidban77.github.io/rastreo/schemas/device-record-v1.json",
  "possible_alias_of": null,
  "scan_metadata": {
    "scan_id": "01KYCCXPWNTY0ZGA5VGEZHRSWC",
    "scenario_name": null,
    "initiated_at": "2026-07-25T10:25:21.301389Z",
    "source_config_hash": "sha256:7d980a397706ae764d9e92c5146a747a66d9f6ddde535f4994b37e074c3422a6"
  }
}
```

Stderr:

```text
▶ discover  targets: 1 | probes: tcp_connect (ports 22) | concurrency: 64 | timeout: 1000ms | sink: stdout
■ discover  completed in 112ms | hosts: 1 | records: 1 | probes: 1 | faults: 0 | sink: stdout
```

The start banner tells you what is about to run; the completion banner tells you what happened. Add `-v` for a per-prober breakdown under the completion banner, or `-q` to silence stderr entirely.

If a scan returns zero records and at least one probe attempt happened, the CLI prints a hint on stderr explaining that no probe reached an open port. The most common cause is an unreachable target or a port the host does not actually listen on.

`faults` counts probe faults, not silent targets. A target that does not answer is a normal negative result: it keeps `faults` at `0` and produces no record. Sweeping a `/24` with twelve live hosts gives you twelve records and zero faults. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults).

## Read the output

Each NDJSON line is one `DeviceRecord`. The fields you will see on a TCP-only scan today:

| Field | Meaning |
|---|---|
| `identity_key` | Stable dedup key. For IP targets, this is `ip:<address>`. |
| `mgmt_ip` | Management IP if known. For a TCP-connect probe against an IP target, this is the target address. |
| `mac` | MAC address. `null` until an ARP-style [prober](../reference/glossary.md#prober) populates it. |
| `manufacturer` | OUI vendor name. `null` until MAC enrichment is available. |
| `platform` | Platform fingerprint. `null` until a fingerprinting prober populates it. |
| `os_version` | OS version string. `null` until a fingerprinting prober populates it. |
| `role` | Device role from the classifier. `null` until a role classifier runs. |
| `confidence` | [Fuser](../reference/glossary.md#fuser) confidence score in the range `0.0` to `1.0`. With the default `DirectFuser`, a single observed signal yields `0.2`. |
| `last_seen` | When the last probe touched this device, as an RFC 3339 UTC timestamp. |
| `signals` | Observed [signals](../reference/glossary.md#signal). For a TCP-connect probe, each open port becomes an `OpenPort` entry. |
| `probe_kinds` | Which probers observed this device. A TCP-connect scan reports `["TcpConnect"]`. |
| `schema_version` | The record schema version. `v1` today. |
| `schema_id` | URL of the JSON Schema this record validates against. See [Record schema](../reference/schema/index.md). |
| `possible_alias_of` | Set by [identity](../discover/identity.md) resolution when this record may be another device's alternate address. `null` on a single-host scan. |
| `scan_metadata` | Provenance for the scan: a unique `scan_id`, the scenario name, the start time, and a hash of the config that produced the record. |

## Pipe into jq

Because tracing logs go to stderr and records go to stdout, you can pipe stdout straight into `jq` (or any NDJSON tool) without log noise.

```bash
rastreo discover --target 1.1.1.1 --port 443 | jq .
rastreo discover --target 1.1.1.1 --port 443 | jq -r '.signals[].OpenPort'
```

## See also

- [First scenario](first-scenario.md) — write this same scan as a reusable YAML file, then add a prober and a file sink.
- [CLI](../discover/cli.md) — every flag `rastreo discover` accepts, with examples.
- [Sinks](../discover/sinks.md) — send records to a file or a Kafka topic instead of stdout.
- [Glossary](../reference/glossary.md) — the terms on this page, defined in one place.
