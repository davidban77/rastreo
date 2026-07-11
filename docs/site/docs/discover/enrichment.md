---
description: Enrichment fusers for rastreo discover — OUI vendor lookup from MAC addresses, the bundled Wireshark manuf snapshot, and how to override with your own database.
---

# Enrichment

Enrichment turns a bare `DeviceRecord` — a MAC, an IP, a handful of open ports — into something identifiable. rastreo ships one enrichment fuser today: `oui_enrichment`, which resolves the MAC-address vendor from an IEEE OUI database. Enrichment runs on the fuser step, after all probers have finished, so it sees the full record.

## oui_enrichment

`oui_enrichment` is a *wrapper fuser*: it delegates the actual outcome-to-record fusion to an inner fuser (typically `direct`), then looks up the resulting record's MAC prefix in an OUI database and writes the vendor name into `DeviceRecord.manufacturer`. Records without a MAC (no ARP / NDP probe ran, or the probes returned no MAC) are passed through unchanged. Records whose MAC prefix is not in the database are also passed through — `manufacturer` stays `null`.

### When to use it

Turn on `oui_enrichment` whenever your scan produces MAC signals — that means the [ARP](../probe/arp.md) or [NDP](../probe/ndp.md) prober is in the scenario. Without a MAC there is nothing to enrich; the fuser is a no-op. Vendor names are the cheapest form of device identification you can get before layering on a heavier fingerprinting pass (SNMP `sysDescr` parsing, DNS reverse lookups) and they land at zero extra probe cost.

### Configuration

`oui_enrichment` wraps another fuser. In YAML:

```yaml
fuser:
  type: oui_enrichment
  data_path: ""
  inner:
    type: direct
    confidence_baseline: 0.1
    confidence_per_signal: 0.1
```

- `data_path` — path to a manuf-format file. Empty string (the default) loads the compiled-in bundled snapshot.
- `inner` — the fuser that produces the record. Any other fuser variant works here; validation runs recursively.

Requires the `oui` build feature — see [Build feature](#build-feature) below.

### Longest-prefix matching

The IEEE assigns MAC blocks at three sizes: MA-L (24-bit), MA-M (28-bit), and MA-S (36-bit). A small vendor might hold an MA-S carved out of a larger vendor's MA-L. The lookup returns the longest-prefix match: /36 wins over /28, which wins over /24. This matters when a MA-L holder has spun off blocks — you get the sub-allocation, not the parent.

MAC input is tolerant on format: colons, hyphens, or no separators; upper- or lower-case; all work. Invalid input (wrong length, non-hex characters) returns `null` rather than raising an error.

### Data source

The bundled snapshot is the Wireshark `manuf` file, canonically at <https://www.wireshark.org/download/automated/data/manuf>. Wireshark regenerates it once a week from IEEE registration data. The file's own license is CC0-1.0.

The snapshot currently checked in is dated `2026-07-03` and contains 57 510 entries covering MA-L / MA-M / MA-S allocations. Refresh cadence is roughly monthly — old entries are stable, but new registrations trickle in for a fast-moving industry. A GitHub Actions cron (`.github/workflows/refresh-oui.yml`) runs on the first of every month, downloads the latest snapshot, gzips it into `rastreo-core/data/manuf.gz`, and opens a PR labelled `dependencies` with the source URL, upstream `Last-Modified`, entry count, and SHA-256 in the body. The staleness guard test `bundled_manuf_gz_is_not_stale` (asserts entry count > 40 000) fails CI on a truncated refresh. To trigger an out-of-band refresh, run `scripts/refresh-oui.sh` locally and commit the result as a normal PR, or run the workflow via `Actions → Refresh OUI snapshot → Run workflow`.

### Overriding the bundled snapshot

For air-gapped labs, offline builds, or custom vendor tagging, point `data_path` at a local manuf-format file:

```yaml
fuser:
  type: oui_enrichment
  data_path: /etc/rastreo/manuf.txt
  inner:
    type: direct
```

The format is tab-separated: column 1 is the MAC prefix (`XX:XX:XX` for /24, `XX:XX:XX:XX/28` for MA-M — four full octets, the low 4 bits of the last octet are treated as unused — and `XX:XX:XX:XX:XX/36` for MA-S — five full octets, the low 4 bits of the last octet are unused), column 2 is a short vendor name, column 3 is the full vendor name. Lines starting with `#` and blank lines are ignored. Parse errors surface as `ConfigError::InvalidValue` with the offending line number.

### Build feature

`oui_enrichment` requires the `oui` Cargo feature. The bundled `manuf.gz` snapshot adds roughly 800 KB to the binary. Default builds include neither.

```bash
cargo build --release -p rastreo --features oui
```

Release tarballs and the published Docker image ship with `oui` enabled — no separate build required.

### Example scenario

Discover an IPv4 lab subnet, ARP for MACs, and tag vendors:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: lab-arp-with-oui
    targets:
      - Cidr: 192.168.1.0/24
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
      - type: arp
    fuser:
      type: oui_enrichment
      inner:
        type: direct
```

Resulting NDJSON records now carry the vendor name:

```json
{"identity_key":"mac:aa:bb:cc:11:22:33","mgmt_ip":"192.168.1.5","mac":"aa:bb:cc:11:22:33","manufacturer":"Cisco Systems, Inc",...}
```

## See also

- [Scenario reference](../reference/scenario.md#fusers) — full field table for `direct` and `oui_enrichment`.
- [ARP prober](../probe/arp.md) and [NDP prober](../probe/ndp.md) — where MAC signals come from.
- [First scan](../get-started/first-scan.md) — DeviceRecord field reference.
