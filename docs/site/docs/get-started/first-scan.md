---
description: Run a discovery scan against a single host with no flags beyond the target, read the resulting table on stdout, and learn what each field of the full record means.
---

# First scan

In this walkthrough you probe a single host, read the result off stdout as a table, then switch to JSON and learn what each field means. The scan takes one command and no config file.

## Pick a target

You need a host that answers something. Two easy options:

- **A public HTTPS endpoint**, such as `1.1.1.1`. Reachable from any host with outbound internet — the simplest path for a first scan.
- **The local compose stack**, which brings up three nginx target containers serving HTTP on port 80. Start it with `docker compose up -d` from the repository root. The containers live on a `10.50.0.0/24` Docker bridge network at `10.50.0.10`, `10.50.0.11`, and `10.50.0.12`. From your host the bridge addresses are not directly reachable, so run the CLI from inside the network: `docker compose exec rastreo-server /rastreo discover --target 10.50.0.10`.

The rest of this page uses `1.1.1.1` because it works without any extra setup.

## Run the scan

```bash
rastreo discover --target 1.1.1.1
```

That is the whole command. With no `--probe` flag, rastreo runs its **default probe set**. A prober joins that set when it needs no extra parameter, works across routers, and produces no second output stream. On a release binary that is `icmp`, `tcp_connect`, `http`, `ssh`, `tls`, `snmp`, and `reverse_dns`. See [Choosing probers](../discover/cli.md#choosing-probers) to pick your own.

On stdout you get one row per device, in a table sized to your terminal:

```text
ADDRESS                      NAME                      PLATFORM              PORTS
1.1.1.1                      one.one.one.one           -                     80,443,8080,8443
```

Stderr:

```text
▶ discover  targets: 1 | probes: icmp (count 3, interval_ms 200), tcp_connect (ports 22, 23, 80, 443, 830, 8080), http (ports 80, 443, 8080, 8443), ssh (ports 22), tls (ports 443), snmp (ports 161, V2c), reverse_dns (system resolvers) | concurrency: 64 | timeout: 1000ms | sink: stdout
■ discover  completed in 1.0s | hosts: 1 | records: 1 | probes: 7 | faults: 0 | sink: stdout
```

The start banner tells you what is about to run; the completion banner tells you what happened. Add `-v` for a per-prober breakdown under the completion banner, or `-q` to silence stderr entirely.

`probes: 7` counts probers, not ports — the seven default probers each ran once against the one target. A `-` in a column means the scan learned nothing for it: no SNMP `sysName` and no PTR record leaves `NAME` empty, no classifier match leaves `PLATFORM` empty.

The table is a triage view of four columns. Everything the scan learned is in the record behind it, which `--format json` prints in full.

## Get the whole record

```bash
rastreo discover --target 1.1.1.1 --format json
```

`--format json` writes one `DeviceRecord` per line as JSON, and drops the banners so stdout is a clean stream for `jq` and friends. Hints still print on stderr, which is a stream of its own.

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
  "confidence": 1.0,
  "last_seen": "2026-07-26T23:14:23.917897Z",
  "signals": [
    { "IcmpEchoRttMicros": 15052 },
    { "OpenPort": 80 },
    { "OpenPort": 443 },
    { "OpenPort": 8080 },
    { "HttpBanner": "cloudflare" },
    { "OpenPort": 8443 },
    { "TlsProtocolVersion": "TLSv1.3" },
    { "TlsCipherSuite": "TLS_AES_256_GCM_SHA384" },
    { "TlsAlpn": "h2" },
    { "TlsSubject": "cloudflare-dns.com" },
    { "TlsSanName": "cloudflare-dns.com" },
    { "TlsSanName": "*.cloudflare-dns.com" },
    { "TlsSanName": "ip:1.0.0.1" },
    { "TlsSanName": "ip:1.1.1.1" },
    { "TlsSanName": "ip:162.159.36.1" },
    { "TlsSanName": "ip:162.159.46.1" },
    { "TlsSanName": "ip:2606:4700:4700::1001" },
    { "TlsSanName": "ip:2606:4700:4700::1111" },
    { "TlsSanName": "ip:2606:4700:4700::64" },
    { "TlsSanName": "ip:2606:4700:4700::6400" },
    { "TlsSanName": "one.one.one.one" },
    { "ReverseDnsName": "one.one.one.one" }
  ],
  "probe_kinds": [ "Icmp", "TcpConnect", "Http", "Tls", "ReverseDns" ],
  "schema_version": "v1",
  "schema_id": "https://davidban77.github.io/rastreo/schemas/device-record-v1.json",
  "possible_alias_of": null,
  "scan_metadata": {
    "scan_id": "01KYGBAJ1R9D6R0548FP88TY3X",
    "scenario_name": null,
    "initiated_at": "2026-07-26T23:14:22.904079Z",
    "source_config_hash": "sha256:4e688bf2179b5b97b79369e4fc15e69289b74371da9d84f0dd792b7d137393ba"
  }
}
```

The record's `probe_kinds` lists the five probers that actually observed something; `ssh` and `snmp` got no answer on this host, which is a normal negative result rather than a failure. Your `signals` list will differ — it is whatever the host answered with, so a switch, a printer, and a DNS resolver all produce different sets.

!!! tip "Preview a scan before it sends anything"
    `rastreo discover --target 1.1.1.1 --dry-run` resolves the targets and prints the whole plan, then exits without touching the network. The plan lists the probers and their ports, the fuser and classifier, and the sink. It also shows the concurrency, rate, retry, and timeout settings. See [Dry-run mode](../discover/cli.md#dry-run-mode).

If a scan returns zero records and at least one probe attempt happened, the CLI prints a hint on stderr explaining that no probe reached the target. The most common cause is an unreachable host or a firewall dropping every probe.

`faults` counts probe faults, not silent targets. A target that does not answer is a normal negative result: it keeps `faults` at `0` and produces no record. Sweeping a `/24` with twelve live hosts gives you twelve records and zero faults. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults).

## Read the output

Each JSON line is one `DeviceRecord`.

| Field | Meaning |
|---|---|
| `identity_key` | Stable dedup key. For IP targets, this is `ip:<address>`. |
| `mgmt_ip` | Management IP if known. For an IP target, this is the target address. |
| `mac` | MAC address. `null` until an ARP-style [prober](../reference/glossary.md#prober) populates it, which needs a target on the local segment. |
| `manufacturer` | Vendor name from the SNMP `sysObjectID` lookup. `null` until the [`mib_enrichment`](../discover/enrichment.md) fuser matches one. |
| `platform` | Platform fingerprint set by the [classifier](../discover/classification.md). `null` here because Cloudflare's banners match no platform rule — point the same command at a switch or a router and it fills in. |
| `os_version` | OS version string set by the classifier alongside `platform`. `null` for the same reason. |
| `role` | Device role from the [classifier](../discover/classification.md). `null` here: the default role rules need multi-port evidence such as SSH + BGP, or SSH + HTTPS + NETCONF. |
| `confidence` | [Fuser](../reference/glossary.md#fuser) confidence score in the range `0.0` to `1.0`. Under the default `direct` fuser it climbs with the number of distinct signals, so a well-answered host saturates at `1.0`. |
| `last_seen` | When the last probe touched this device, as an RFC 3339 UTC timestamp. |
| `signals` | Observed [signals](../reference/glossary.md#signal). One entry per fact a prober read: open ports, an HTTP banner, TLS certificate names, a reverse-DNS name, an ICMP round-trip time. |
| `probe_kinds` | Which probers observed this device. Probers that ran and got nothing are not listed. |
| `schema_version` | The record schema version. `v1` today. |
| `schema_id` | URL of the JSON Schema this record validates against. See [Record schema](../reference/schema/index.md). |
| `possible_alias_of` | Set by [identity](../discover/identity.md) resolution when this record may be another device's alternate address. `null` on a single-host scan. |
| `scan_metadata` | Provenance for the scan: a unique `scan_id`, the scenario name, the start time, and a hash of the config that produced the record. |

## Narrow the scan

The default set is the right start when you do not know what is out there. When you do, `--probe` picks the probers and `--port` sets the ports for the three that have no well-known port (`tcp_connect`, `http`, `udp`):

```bash
rastreo discover --target 1.1.1.1 --probe tcp_connect --port 443
```

```text
ADDRESS                      NAME                      PLATFORM              PORTS
1.1.1.1                      -                         -                     443
```

```text
▶ discover  targets: 1 | probes: tcp_connect (ports 443) | concurrency: 64 | timeout: 1000ms | sink: stdout
■ discover  completed in 34ms | hosts: 1 | records: 1 | probes: 1 | faults: 0 | sink: stdout
```

That record carries a single `{ "OpenPort": 443 }` signal, `probe_kinds: ["TcpConnect"]`, and `confidence: 0.2` — one prober, one observation. `NAME` is empty because `reverse_dns` was not in the selection.

Pass `--port` without `--probe` and rastreo prints a note on stderr, because a port list on the default set is not the port-only scan it looks like:

```text
• note: --port applies to tcp_connect, http; the default probe set also runs icmp, ssh, tls, snmp, reverse_dns. Use --probe tcp_connect for a port-only scan.
```

See [Ports](../discover/cli.md#ports) for the full rules, including `--probe-ports` for retargeting one prober.

## Pipe into jq

Add `--format json` and stdout becomes a clean NDJSON stream. The banners and the progress line are dropped, so a scripted run prints no decoration. Stderr stays empty unless something is worth saying; hints and log lines still go there when there is. Nothing but records reaches the pipe.

```bash
rastreo discover --target 1.1.1.1 --format json | jq .
rastreo discover --target 1.1.1.1 --format json | jq -r '.signals[].OpenPort | select(. != null)'
```

That stays true if you fold stderr into the same pipe or file — `2>&1 | jq`, `> scan.json 2>&1`. Under `--format json` a merged destination carries records and nothing else for as long as the scan is producing them, because a hint written there is a line `jq` would have to parse. A run that refuses is the exception: the error and the hint that explains it go into the capture together, since an error whose remedy was suppressed is worse than a line to skip. The exit code tells you which capture you have — `0` for nothing but records, `1` for one that carries the diagnosis. Keep stderr separate (`2> scan.log`) when you want the hints from a successful run too.

Set `RASTREO_FORMAT=json` in your shell profile or your CI environment to make that the default for every run.

## See also

- [First scenario](first-scenario.md) — write this same scan as a reusable YAML file, then add a prober and a file sink.
- [CLI](../discover/cli.md) — every flag `rastreo discover` accepts, with examples.
- [Sinks](../discover/sinks.md) — send records to a file or a Kafka topic instead of stdout.
- [Glossary](../reference/glossary.md) — the terms on this page, defined in one place.
