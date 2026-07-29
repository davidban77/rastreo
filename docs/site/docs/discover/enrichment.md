---
description: Enrichment fusers for rastreo discover — SNMP sysObjectID lookup of vendor, model, and product family, the bundled seed table, how to override it with your own, and how enrichers compose.
---

# Enrichment

Enrichment turns a bare `DeviceRecord` — a MAC, an IP, a handful of open ports — into something identifiable. rastreo ships one enrichment fuser: `mib_enrichment` resolves the vendor, hardware model, and product family from an SNMP `sysObjectID`. Enrichment runs on the fuser step, after all probers have finished, so it sees the full record.

## mib_enrichment

`mib_enrichment` is a *wrapper fuser*: it delegates outcome-to-record fusion to an inner fuser (typically `direct`), then matches the record's SNMP `sysObjectID` against a table and writes the vendor, hardware model, and product family. It reads the `SnmpSysObjectId` signal that the [SNMP prober](../probe/snmp.md) emits. Records without that signal are passed through unchanged. Records whose OID is not in the table are also passed through — `manufacturer`, `model`, and `product_family` stay `null`.

### When to use it

Turn on `mib_enrichment` when your scan runs the [SNMP prober](../probe/snmp.md) and you know your fleet's `sysObjectID` values. A `sysObjectID` names the exact product, so the match gives a precise vendor, model, and product family rather than a guess. The compiled-in table is only a small seed. The real value comes from your own overlay file — see [The bundled table is a seed](#mib-seed) below.

### What it writes

On a table hit, the fuser writes each field the matched entry provides, and only where the record does not already carry a value:

- `model` — the hardware model from the matched entry.
- `product_family` — the product family from the matched entry.
- `manufacturer` — the vendor from the matched entry.

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

The lookup is an exact match on the full dotted OID. The whole `sysObjectID` must match a table key character for character. There is no prefix matching and no leading dot. A device whose OID is one arc longer or shorter than a table key does not match.

The OID is dotted-decimal with no leading dot — the exact form the SNMP prober emits, for example `1.3.6.1.4.1.6527.1.20.26`. A table key written any other way is rejected when the file loads.

### The bundled table is a seed {#mib-seed}

The compiled-in table is a small, verified seed — nine entries covering Nokia SR Linux, MikroTik RouterOS, and Net-SNMP on several operating systems. It is not a full OID database. It exists so a fresh build enriches a few well-known devices, and so you have a working example to copy.

The real value comes from your own overlay file. You know your fleet's models and their `sysObjectID` values; the seed does not. Point `data_path` at an overlay file and your entries merge on top of the seed. On a key collision your entry wins, so you can also correct a seed entry.

### Overlay format

An overlay file maps each `sysObjectID` to a vendor identity. It has four columns, one entry per line, separated by a single tab:

- `sys_object_id` — the dotted-decimal OID, no leading dot (for example `1.3.6.1.4.1.9.1.563`).
- `manufacturer` — the vendor name. May be left empty.
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

### Stacking enrichers

An enricher wraps another fuser, and the wrapped one runs first, so a chain resolves inside out. Every enricher writes a field only when that field is still empty — so whichever enricher sits innermost gets first claim on a shared field like `manufacturer` and its answer is the one that survives.

That fixes the ordering rule: **most specific lookup key innermost.** Rank an enricher by how precisely one value of its key names one product. A `sysObjectID` is an exact identifier for a single model, so `mib_enrichment` nests inside any enricher keyed on something coarser — a vendor-assigned address prefix, a banner substring, a port pattern. The coarser enricher still contributes on the records the specific one could not identify, without overwriting the ones it could.

`mib_enrichment` is the only enrichment fuser today, so there is nothing to order yet. To merge multi-IP devices, wrap it in the `identity` fuser, which must be the outermost — see [Identity](identity.md).

## See also

- [Scenario reference](../reference/scenario.md#fusers) — full field tables for `direct` and `mib_enrichment`.
- [SNMP prober](../probe/snmp.md) — where the `sysObjectID` that `mib_enrichment` matches comes from.
- [Classification](classification.md) — the classifier owns `platform`, `os_version`, and `role`.
- [DeviceRecord schema](../reference/schema/device-record.md) — the `manufacturer`, `model`, and `product_family` fields on the record.
- [First scan](../get-started/first-scan.md) — DeviceRecord field reference.
