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
  "role": null,
  "confidence": 0.2,
  "last_seen": { "secs_since_epoch": 1782158571, "nanos_since_epoch": 423959000 },
  "signals": [ { "OpenPort": 443 } ]
}
```

Stderr:

```text
discovery complete: targets_resolved=1 probe_attempts=1 probe_errors=0 records_emitted=1 elapsed_ms=112
```

If a scan returns zero records and at least one probe attempt happened, the CLI prints a hint on stderr explaining that no probe reached an open port. The most common cause is an unreachable target or a port the host does not actually listen on.

## Read the output

Each NDJSON line is one `DeviceRecord`. The fields you will see on a TCP-only scan today:

| Field | Meaning |
|---|---|
| `identity_key` | Stable dedup key. For IP targets, this is `ip:<address>`. |
| `mgmt_ip` | Management IP if known. For a TCP-connect probe against an IP target, this is the target address. |
| `mac` | MAC address. `null` until an ARP-style prober populates it. |
| `manufacturer` | OUI vendor name. `null` until MAC enrichment is available. |
| `platform` | Platform fingerprint. `null` until a fingerprinting prober populates it. |
| `role` | Device role from the classifier. `null` until a role classifier runs. |
| `confidence` | Fuser confidence score in the range `0.0` to `1.0`. With the default `DirectFuser`, a single observed signal yields `0.2`. |
| `last_seen` | When the last probe touched this device, as seconds and nanoseconds since the Unix epoch. |
| `signals` | Observed signals. For a TCP-connect probe, each open port becomes an `OpenPort` entry. |

## Pipe into jq

Because tracing logs go to stderr and records go to stdout, you can pipe stdout straight into `jq` (or any NDJSON tool) without log noise.

```bash
rastreo discover --target 1.1.1.1 --port 443 | jq .
rastreo discover --target 1.1.1.1 --port 443 | jq -r '.signals[].OpenPort'
```

## See also

- [CLI](../discover/cli.md) — every flag `rastreo discover` accepts, with examples.
- [Sinks](../discover/sinks.md) — send records to a file or a Kafka topic instead of stdout.
