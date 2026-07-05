---
description: The correlation fuser merges per-IP DeviceRecords for the same device into a single record with alt_ips populated, and annotates medium-confidence aliases with possible_alias_of.
---

# Correlation

A single network device often owns multiple IPs — a management IP, one per SVI, a loopback, a VRRP virtual IP shared with a peer. Every prober in rastreo targets IPs, so without correlation each of those IPs produces its own `DeviceRecord` and a downstream reconciler (Nautobot, NetBox, Infrahub) has to figure out on its own that they belong to the same device. That's what `correlation` does: it runs after per-IP fusion and merges records that share identity signals into one record whose `mgmt_ip` is the primary address and whose `alt_ips` list the secondary addresses.

Correlation is a *wrapper fuser*: it delegates the per-IP fusion to an inner fuser (typically `direct`, optionally wrapped by `oui_enrichment`), then correlates the resulting records via union-find over shared identity signals.

## When to use it

Turn on `correlation` when your scan targets multi-homed devices — routers with multiple interfaces exposed, switches with SVIs, firewalls with HA pairs, any device that answers on more than one IP. Without correlation, the reconciler receives N records for a N-interface device and has to run its own dedup logic. With correlation, it receives one record with an `alt_ips` list and can trust the primary key.

If every target in the scan is a single-IP host (a laptop, a container, a VM with one NIC), correlation is a no-op — it delegates through and the records come back unchanged.

## Composition

`correlation` wraps another fuser. The recommended stack, innermost to outermost:

```
DirectFuser → OuiEnrichmentFuser → CorrelationFuser
```

`direct` does per-IP fusion. `oui_enrichment` looks up the vendor from the MAC. `correlation` then runs across the enriched records — order matters because `correlation` uses the `manufacturer` field to detect conflicting-vendor pairs and refuse to merge them, so `oui_enrichment` needs to run first.

In YAML:

```yaml
fuser:
  type: correlation
  inner:
    type: oui_enrichment
    inner:
      type: direct
```

The three-layer stack is the common case. If you don't have the `oui` build feature enabled or don't care about vendor tagging, wrap `direct` directly:

```yaml
fuser:
  type: correlation
  inner:
    type: direct
```

## Signals used for correlation

Correlation weights pairs of records based on the identity signals they share:

| Shared signal | Weight | Notes |
|---|---|---|
| Non-virtual MAC | +0.5 | MAC comes from `record.mac`. Virtual MACs (VRRP / HSRP / CARP) are excluded — see [Virtual MAC detection](#virtual-mac-detection) below. |
| `SnmpSysName` | +0.5 | Case-insensitive equality on the `sysName` value from any SNMP prober outcome. Empty strings do not count. |
| Conflicting `manufacturer` | -0.3 | Applied when both records have a non-null `manufacturer` and the values differ. Only meaningful when `oui_enrichment` has populated the field. |

More correlation signals are coming as more probers land: SSH host key from the SSH prober, SNMPv3 engine ID from SNMPv3, both contribute at +0.5 each. The weights, thresholds, and the union-find algorithm stay unchanged — those signals will slot in as new `Signal` variants the correlator recognises.

## Confidence bands

The correlator sums the pair weights and classifies each pair into a band:

| Band | Weight range | Action |
|---|---|---|
| **High** | ≥ 0.8 | Auto-merge. Both records become one, with `alt_ips` populated. |
| **Medium** | ≥ 0.4 and < 0.8 | Do not merge. Each record's `possible_alias_of` field is set to the peer's `identity_key`. |
| **Low** | < 0.4 | No annotation. Records are unrelated. |

Union-find runs over the high-band pairs so a chain `A ↔ B ↔ C` merges into one record even when `A` and `C` don't share signals directly.

## Virtual MAC detection

The correlator hard-excludes MAC prefixes assigned to virtual-router protocols. Two routers running VRRP or HSRP share the same virtual MAC on the shared virtual IP — merging them would be wrong. The excluded prefixes:

| Prefix | Protocol |
|---|---|
| `00:00:5e:00:01:xx` | VRRPv2 IPv4 (RFC 5798) — FreeBSD CARP reuses this same prefix |
| `00:00:5e:00:02:xx` | VRRPv3 IPv6 (RFC 5798) |
| `00:00:0c:07:ac:xx` | Cisco HSRP |

A shared virtual MAC contributes **zero** weight. Two records that agree on nothing but a VRRP virtual MAC stay separate.

## User-declared VRRP hints

If your topology uses a non-standard virtual MAC — a custom keepalived VRRP setup, a proprietary FHRP variant — declare it in `correlation_hints.vrrp_groups`. Records with that MAC will contribute zero weight (same as a built-in virtual MAC), and if you also list the physical member IPs, pairs of those IPs are capped below the medium band even when their MACs would otherwise match.

```yaml
fuser:
  type: correlation
  correlation_hints:
    vrrp_groups:
      - virtual_ip: 10.0.0.1
        virtual_mac: "00:00:5e:00:01:0a"
        members:
          - 10.0.0.2
          - 10.0.0.3
  inner:
    type: direct
```

The `virtual_mac` field is validated at construction — an unparseable MAC returns `ConfigError::InvalidValue`.

## Merged record semantics

When a group of records merges into one:

- `identity_key` — the highest-confidence constituent's key.
- `mgmt_ip` — the first constituent's `mgmt_ip`, following target-list order.
- `alt_ips` — the other constituents' `mgmt_ip` values, deduplicated, in source order.
- `mac` — from the highest-confidence constituent, falling back to any non-null value.
- `manufacturer`, `platform`, `role` — from the highest-confidence constituent, falling back to any non-null value.
- `confidence` — `max(constituents) + 0.1`, clamped to `1.0`. Merging is additional evidence.
- `last_seen` — the most recent timestamp across constituents.
- `signals` — union across constituents, deduplicated.

For medium-band pairs that do not merge, both records receive `possible_alias_of = peer.identity_key`. The peer is picked by highest confidence first, then correlation weight, then earliest input position.

## Example scenario

Discover a lab where a core switch answers on three IPs — the management IP `10.0.0.1`, a loopback `1.1.1.1`, and a second interface `10.0.0.2`:

```yaml
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: lab-multi-ip-correlation
    targets:
      - Ip: 10.0.0.1
      - Ip: 10.0.0.2
      - Ip: 1.1.1.1
    probers:
      - type: tcp_connect
        ports: [22, 161]
      - type: arp
      - type: snmp
        ports: [161]
    fuser:
      type: correlation
      inner:
        type: oui_enrichment
        inner:
          type: direct
```

With SNMP returning `sysName: core-sw01` on all three IPs and ARP returning the same MAC, the output contains one record:

```json
{
  "identity_key": "mac:aa:bb:cc:11:22:33",
  "mgmt_ip": "10.0.0.1",
  "alt_ips": ["10.0.0.2", "1.1.1.1"],
  "possible_alias_of": null,
  ...
}
```

## See also

- [Scenario reference](../reference/scenario.md#correlation) — full field table for `correlation` and `correlation_hints`.
- [Enrichment](enrichment.md) — how `oui_enrichment` populates the `manufacturer` field the correlator uses for conflict detection.
- [SNMP prober](../probe/snmp.md) — where the `sysName` signal comes from.
- [ARP prober](../probe/arp.md) and [NDP prober](../probe/ndp.md) — where the MAC signal comes from.
