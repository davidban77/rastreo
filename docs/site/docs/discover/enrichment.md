---
description: Enrichment fusers for rastreo discover — OUI vendor lookup from MAC addresses and SNMP sysObjectID model lookup, the bundled seed tables, and how to override each with your own database.
---

# Enrichment

Enrichment turns a bare `DeviceRecord` — a MAC, an IP, a handful of open ports — into something identifiable. rastreo ships two enrichment fusers today. `oui_enrichment` resolves the MAC-address vendor from an IEEE OUI database. `mib_enrichment` resolves the hardware model and product family from an SNMP `sysObjectID`. Enrichment runs on the fuser step, after all probers have finished, so it sees the full record.

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

Resulting records now carry the vendor name, shown here under `--format json`:

```json
{"identity_key":"mac:aa:bb:cc:11:22:33","mgmt_ip":"192.168.1.5","mac":"aa:bb:cc:11:22:33","manufacturer":"Cisco Systems, Inc",...}
```

## mib_enrichment

`mib_enrichment` is a *wrapper fuser*: it delegates outcome-to-record fusion to an inner fuser (typically `direct`), then matches the record's SNMP `sysObjectID` against a table and writes the hardware model and product family. It reads the `SnmpSysObjectId` signal that the [SNMP prober](../probe/snmp.md) emits. Records without that signal are passed through unchanged. Records whose OID is not in the table are also passed through — `model` and `product_family` stay `null`.

### When to use it

Turn on `mib_enrichment` when your scan runs the [SNMP prober](../probe/snmp.md) and you know your fleet's `sysObjectID` values. A `sysObjectID` names the exact product. The match gives a precise model and product family that a MAC vendor lookup cannot. The compiled-in table is only a small seed. The real value comes from your own overlay file — see [The bundled table is a seed](#mib-seed) below.

### What it writes

On a table hit, the fuser writes:

- `model` — the hardware model from the matched entry, when the entry provides one.
- `product_family` — the product family from the matched entry, when the entry provides one.
- `manufacturer` — set only when the record does not already have one. If `oui_enrichment` already filled `manufacturer` from the MAC vendor, `mib_enrichment` keeps that value.

It does not set `platform`, `os_version`, or `role`. The classifier owns those fields — see [Classification](classification.md).

### Configuration

`mib_enrichment` wraps another fuser. It takes a required `inner` — the fuser that produces the record — and an optional `data_path` for your overlay file. The smallest form uses only the bundled seed:

```yaml
fuser:
  type: mib_enrichment
  inner:
    type: direct
```

- `data_path` — path to an overlay file in the format shown below. Omit it to use only the bundled seed.
- `inner` — the fuser that produces the record. Any other fuser variant works here; validation runs recursively.

Requires the `mib_enrichment` build feature — see [Build feature](#mib-build-feature) below.

### Exact-match lookup

The lookup is an exact match on the full dotted OID. The whole `sysObjectID` must match a table key character for character. There is no prefix matching and no leading dot. This is different from `oui_enrichment`, which matches the longest MAC prefix. A device whose OID is one arc longer or shorter than a table key does not match.

The OID is dotted-decimal with no leading dot — the exact form the SNMP prober emits, for example `1.3.6.1.4.1.6527.1.20.26`. A table key written any other way is rejected when the file loads.

### The bundled table is a seed {#mib-seed}

The compiled-in table is a small, verified seed — nine entries covering Nokia SR Linux, MikroTik RouterOS, and Net-SNMP on several operating systems. It is not a full OID database. It exists so a fresh build enriches a few well-known devices, and so you have a working example to copy.

The real value comes from your own overlay file. You know your fleet's models and their `sysObjectID` values; the seed does not. Point `data_path` at an overlay file and your entries merge on top of the seed. On a key collision your entry wins, so you can also correct a seed entry.

### Overlay format

An overlay file maps each `sysObjectID` to a vendor identity. It has four columns, one entry per line, separated by a single tab:

- `sys_object_id` — the dotted-decimal OID, no leading dot (for example `1.3.6.1.4.1.9.1.563`).
- `manufacturer` — the vendor name. May be left empty; then it is filled only when no OUI lookup already set it.
- `model` — the hardware model. May be left empty, for an OID that names an operating system or agent rather than a hardware model.
- `product_family` — the product family. May be left empty.

Each entry must fill at least one of `manufacturer`, `model`, or `product_family`; a row with all three empty is rejected.

Lines that start with `#` and blank lines are ignored.

```text title="mib_identity.tsv"
# columns are tab-separated: sys_object_id  manufacturer  model  product_family
1.3.6.1.4.1.9.1.563	Cisco	Catalyst 3560-24PS	Catalyst 3560
1.3.6.1.4.1.14988.1	MikroTik	CCR2004-1G-12S+2XS	RouterOS
1.3.6.1.4.1.2636.1.1.1.2.29	Juniper	MX240	MX
```

!!! warning "Use tabs between columns, not spaces"
    Columns are separated by a single tab. Spaces inside a value are kept, so `Catalyst 3560-24PS` is one model. A space between columns is not a separator, so a line aligned with spaces fails to load. rastreo reports the line number of any malformed line — a wrong column count, a bad OID, or a row with no identity value at all (`manufacturer`, `model`, and `product_family` all empty).

### Build feature {#mib-build-feature}

`mib_enrichment` requires the `mib_enrichment` Cargo feature. You also need the `snmp` feature, because the SNMP prober produces the `sysObjectID` this fuser matches. Neither is in the pre-built release binaries — [build from source](../get-started/install.md#from-source-cargo) with both enabled:

```bash
cargo build --release -p rastreo --features snmp,mib_enrichment
```

### Example scenario

Discover an IPv4 lab subnet, probe SNMP, and tag model and product family from the bundled seed:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: lab-snmp-with-mib
    targets:
      - Cidr: 192.168.1.0/24
    probers:
      - type: snmp
        version: v2c
        community: public
    fuser:
      type: mib_enrichment
      inner:
        type: direct
```

A record for a device whose OID is in the table now carries the model and product family:

```json
{"identity_key":"ip:192.168.1.5","mgmt_ip":"192.168.1.5","manufacturer":"Nokia","model":"SR Linux","product_family":"SR Linux","signals":[{"SnmpSysObjectId":"1.3.6.1.4.1.6527.1.20.26"}]}
```

### Combining with OUI

Stack both enrichment fusers to tag the MAC vendor and the SNMP model on the same record. Make `mib_enrichment` the outer fuser so it wraps `oui_enrichment`:

```yaml
fuser:
  type: mib_enrichment
  data_path: /etc/rastreo/mib_identity.tsv
  inner:
    type: oui_enrichment
    inner:
      type: direct
```

Both fusers fill `manufacturer` only when it is still empty. The inner `oui_enrichment` sets the MAC vendor first, then `mib_enrichment` leaves it in place while adding `model` and `product_family`. To also merge multi-IP devices, wrap the whole chain in the `identity` fuser, which must be the outermost — see [Identity](identity.md).

## See also

- [Scenario reference](../reference/scenario.md#fusers) — full field tables for `direct`, `oui_enrichment`, and `mib_enrichment`.
- [SNMP prober](../probe/snmp.md) — where the `sysObjectID` that `mib_enrichment` matches comes from.
- [ARP prober](../probe/arp.md) and [NDP prober](../probe/ndp.md) — where MAC signals come from.
- [Classification](classification.md) — the classifier owns `platform`, `os_version`, and `role`.
- [DeviceRecord schema](../reference/schema/device-record.md) — the `manufacturer`, `model`, and `product_family` fields on the record.
- [First scan](../get-started/first-scan.md) — DeviceRecord field reference.
