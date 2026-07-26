---
description: Turn the flag-driven first scan into a reusable YAML scenario file, then add a second prober and a file destination — the step from quick scans to the full prober set.
---

# First scenario file

The [first scan](first-scan.md) ended on a narrowed one-liner: `--target`, `--probe`, and `--port`. That is the quick path. A scenario file is the next step. It writes the same scan as YAML, then lets you configure any prober and point at any destination. This page takes you there one step at a time.

## The same scan as a file

Here is the flag scan the first-scan page ended on:

```bash
rastreo discover --target 1.1.1.1 --probe tcp_connect --port 443
```

The same scan written as a scenario file uses a few named fields:

- `version` and `kind` — the file header. Always `version: 1` and `kind: discovery`.
- `scenarios` — the list of runs. Each entry is one scan.
- `signal_type` — the run type. Use `discover` for a discovery scan.
- `name` — a label for the scenario. It appears in the progress lines.
- `targets` — what to probe. `Ip` names a single address.
- `probers` — how to probe. `tcp_connect` with `ports` is the flag scan's prober.
- `sink` — where records go. `stdout` is the default.

```yaml title="scenario.yaml"
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: first-scan
    sink:
      type: stdout
    targets:
      - Ip: "1.1.1.1"
    probers:
      - type: tcp_connect
        ports: [443]
```

Run it with `--file` instead of the scan flags:

```bash
rastreo discover --file scenario.yaml
```

The output is the same one-line `DeviceRecord` you saw on the first scan: one `OpenPort` signal for port 443. The scenario file changed how you asked, not what came back.

!!! tip "Check the file before you run it"
    `rastreo validate scenario.yaml` checks the file offline — no probing, no network. It catches a typo in the sink or prober config before a real scan. See [Validate](../discover/validate.md).

## Add a second prober

Flag mode always runs `tcp_connect` and nothing else. A scenario file can list any prober, and it can list several at once. Add a `reverse_dns` prober to the same file. It looks up the PTR record for each target IP and returns the hostname:

```yaml title="scenario.yaml" hl_lines="13"
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: first-scan
    sink:
      type: stdout
    targets:
      - Ip: "1.1.1.1"
    probers:
      - type: tcp_connect
        ports: [443]
      - type: reverse_dns
```

Run it again:

```bash
rastreo discover --file scenario.yaml
```

Now the record carries two signals. The `tcp_connect` prober found the open port, and `reverse_dns` resolved the address to its hostname. The record below is trimmed to the fields that changed:

```json
{
  "identity_key": "ip:1.1.1.1",
  "mgmt_ip": "1.1.1.1",
  "signals": [
    { "OpenPort": 443 },
    { "ReverseDnsName": "one.one.one.one" }
  ]
}
```

Confidence rises from `0.2` to `0.3` because a second signal was observed. `reverse_dns` needs no build feature, so this runs on any install. You reach every other prober — HTTP, DNS, UDP, SNMP, ARP, and more — the same way: add an entry to `probers`. See [Probe](../probe/index.md) for the full set.

## Send records to a file

stdout is fine for a first look. To keep the records, point the sink at a file. Change the `sink` block from `stdout` to `file` and give it a `path`:

```yaml title="scenario.yaml" hl_lines="7 8"
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: first-scan
    sink:
      type: file
      path: /tmp/scan.ndjson
    targets:
      - Ip: "1.1.1.1"
    probers:
      - type: tcp_connect
        ports: [443]
      - type: reverse_dns
```

The file sink appends one record per line, so repeated runs add to the file rather than replace it. A Kafka topic or a NATS subject is the same idea with a different `sink` block. See [Sinks](../discover/sinks.md) for every destination and [Scenario schema](../reference/scenario.md) for every field.

## See also

- [CLI](../discover/cli.md) — YAML-driven mode and every flag it accepts.
- [Scenario schema](../reference/scenario.md) — every field a scenario file can set.
- [Sinks](../discover/sinks.md) — send records to a file, a Kafka topic, or a NATS subject.
- [Validate](../discover/validate.md) — check a scenario file offline before you run it.
