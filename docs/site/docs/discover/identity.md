---
description: The identity fuser merges per-IP DeviceRecords for the same device into a single record with alt_ips populated, and annotates medium-confidence aliases with possible_alias_of.
---

# Identity

A single network device often answers on several IP addresses at once. It has a management address, one address per network interface, and sometimes a shared "virtual" address that two redundant routers answer on together (a failover protocol called VRRP). Every prober in rastreo targets IPs, so without an identity pass each of those IPs produces its own `DeviceRecord` and a downstream reconciler (Nautobot, NetBox, Infrahub) has to figure out on its own that they belong to the same device. That's what `identity` does: it runs after per-IP fusion and merges records that share identity signals into one record whose `mgmt_ip` is the primary address and whose `alt_ips` list the secondary addresses.

The identity fuser is a *wrapper fuser*: it delegates the per-IP fusion to an inner fuser (typically `direct`, optionally wrapped by `oui_enrichment`), then runs union-find over the resulting records to group those that share identity signals.

## When to use it

Use `identity` when your scan targets multi-homed devices — routers with multiple interfaces exposed, switches with SVIs, firewalls with HA pairs, any device that answers on more than one IP. Without it, the reconciler receives N records for a N-interface device and has to run its own dedup logic. With `identity`, it receives one record with an `alt_ips` list and can trust the primary key.

If every target in the scan is a single-IP host (a laptop, a container, a VM with one NIC), the identity fuser does nothing — it delegates through and the records come back unchanged.

## Composition

`identity` wraps another fuser. The recommended stack, in the order records pass through it:

```mermaid
flowchart LR
    D[DirectFuser] --> O[OuiEnrichmentFuser]
    O --> I[IdentityFuser]
```

`direct` does per-IP fusion. `oui_enrichment` looks up the vendor from the MAC. `identity` then runs across the enriched records — order matters because the identity fuser uses the `manufacturer` field to detect conflicting-vendor pairs and refuse to merge them, so `oui_enrichment` needs to run first.

In YAML:

```yaml
fuser:
  type: identity
  inner:
    type: oui_enrichment
    inner:
      type: direct
```

The three-layer stack is the common case. If you don't have the `oui` build feature enabled or don't care about vendor tagging, wrap `direct` directly:

```yaml
fuser:
  type: identity
  inner:
    type: direct
```

## Signals used for identity fusion

The identity fuser weights pairs of records based on the identity signals they share. Each shared signal contributes a positive weight; a conflicting `manufacturer` contributes a penalty. The **Merges alone?** column tells you whether that signal alone crosses the [high-band threshold](#confidence-bands) and auto-merges the pair. A signal marked **No** still counts — it just needs to combine with another to reach the merge threshold.

| Shared signal | Weight | Merges alone? | Notes |
|---|---|---|---|
| `SshHostKey` | +0.8 | Yes | Byte-exact equality on the OpenSSH-format host key emitted by the [SSH prober](../probe/ssh.md). Host keys are device-unique in practice, so two records that share one land at the high band on that signal alone. Empty strings do not count. |
| Non-virtual MAC | +0.5 | No | MAC comes from `record.mac`. Virtual MACs (VRRP / HSRP / CARP) are excluded — see [Virtual MAC detection](#virtual-mac-detection) below. |
| `ReverseDnsName` | +0.5 | No | Any single overlap in the two records' PTR-name lists (PTR records are the DNS entries that map an IP back to a name) counts once. Case-insensitive match (DNS names are case-insensitive per RFC 1035; matches the `SnmpSysName` behavior). A hostname shared across two IPs strongly suggests the same device; combined with any other agreeing signal (MAC / sysname / TLS SAN) it reaches the high band. |
| `SnmpSysName` | +0.5 | No | Case-insensitive equality on the `sysName` value from any SNMP prober outcome. Empty strings do not count. |
| `TlsSanName` | +0.5 | No | Any single overlap in the two records' SAN lists counts once. DNS names and IP-prefixed entries (`ip:10.0.0.1`) match uniformly by byte-exact equality. |
| `TlsSubject` | +0.3 | No | Byte-exact match on the Subject Common Name. Alone contributes to the low band; combined with a shared `TlsSanName` (+0.5) it reaches the high band. |
| Conflicting `manufacturer` | −0.3 | penalty | Applied when both records have a non-null `manufacturer` and the values differ. Only meaningful when `oui_enrichment` has populated the field. |

`SshHostKey` is the strongest single-signal correlator the fuser has today. Host keys survive interface changes and IP renumbering, so two IPs that present the same key are the same device. TLS is the newest signal group: `TlsSubject` alone sits in the low band because Subject Common Names are often generic (`localhost`, `nginx`, wildcard-like patterns), and `TlsSanName` alone lands in the medium band; together they stand as high-band evidence that two records present the same certificate identity. `ReverseDnsName` is a third hostname-based correlator alongside `SnmpSysName` and TLS SANs — a PTR name shared across two IPs is a strong hint the same device answers on both addresses.

!!! warning "Conflicting manufacturer with a matching host key"
    Two records that share a host key (+0.8) but disagree on `manufacturer` (−0.3) land at 0.5, the medium band. The records are **not** auto-merged; instead each record's [`possible_alias_of`](#confidence-bands) is populated with the peer's `identity_key`. That combination is rare and worth investigating. A benign cause is a device that had its primary NIC swapped between scans, which changed the OUI-derived vendor. A suspicious cause is a cloned or stolen host key running on different vendor hardware.

    A populated `possible_alias_of` means: another record in the same scan looks like the same device, but the evidence is not strong enough to fold them together — a human should decide.

## Confidence bands

The identity fuser sums the pair weights and classifies each pair into a band:

| Band | Weight range | Action |
|---|---|---|
| **High** | ≥ 0.8 | Auto-merge. Both records become one, with `alt_ips` populated. |
| **Medium** | ≥ 0.4 and < 0.8 | Do not merge. Each record's `possible_alias_of` field is set to the peer's `identity_key`. |
| **Low** | < 0.4 | No annotation. Records are unrelated. |

Union-find runs over the high-band pairs so a chain `A ↔ B ↔ C` merges into one record even when `A` and `C` don't share signals directly.

## Virtual MAC detection

The identity fuser hard-excludes MAC prefixes assigned to virtual-router protocols. Two routers running VRRP or HSRP share the same virtual MAC on the shared virtual IP — merging them would be wrong. The excluded prefixes:

| Prefix | Protocol |
|---|---|
| `00:00:5e:00:01:xx` | VRRPv2 IPv4 (RFC 5798) — FreeBSD CARP reuses this same prefix |
| `00:00:5e:00:02:xx` | VRRPv3 IPv6 (RFC 5798) |
| `00:00:0c:07:ac:xx` | Cisco HSRP |

A shared virtual MAC contributes **zero** weight. Two records that agree on nothing but a VRRP virtual MAC stay separate.

## User-declared VRRP hints

If your topology uses a non-standard virtual MAC — a custom keepalived VRRP setup, a proprietary FHRP variant — declare it in `identity_hints.vrrp_groups`. Records with that MAC will contribute zero weight (same as a built-in virtual MAC), and if you also list the physical member IPs, pairs of those IPs are capped at the medium-band lower edge even when their MACs would otherwise match — they surface with `possible_alias_of` populated instead of auto-merging.

```yaml
fuser:
  type: identity
  identity_hints:
    vrrp_groups:
      - virtual_ip: 10.0.0.1
        virtual_mac: "00:00:5e:00:01:0a"
        members:
          - 10.0.0.2
          - 10.0.0.3
  inner:
    type: direct
```

The `virtual_mac` field is validated when the config loads — an unparseable MAC is rejected as invalid.

## Merged record semantics

When a group of records merges into one:

- `identity_key` — the highest-confidence constituent's key.
- `mgmt_ip` — the first constituent's `mgmt_ip`, following target-list order.
- `alt_ips` — the other constituents' `mgmt_ip` values, deduplicated, in source order. Each entry is an [`AltIp`](../reference/schema/device-record.md#altip) object; see [The `AltIp` shape](#the-altip-shape) below for the field breakdown.
- `mac` — from the highest-confidence constituent, falling back to any non-null value.
- `manufacturer`, `platform`, `role` — from the highest-confidence constituent, falling back to any non-null value.
- `confidence` — `max(constituents) + 0.1`, clamped to `1.0`. Merging is additional evidence.
- `last_seen` — the most recent timestamp across constituents.
- `signals` — union across constituents, deduplicated.

For medium-band pairs that do not merge, both records receive `possible_alias_of = peer.identity_key`. The peer is picked by highest confidence first, then pair weight, then earliest input position.

## The `AltIp` shape

Each entry in `alt_ips` is an [`AltIp`](../reference/schema/device-record.md#altip) object. The shape maps 1:1 to the IP-address models in NetBox, Nautobot, and Infrahub. A reconciler reads the address, role hint, and probe kinds straight from the record.

| Field | Type | Description |
|---|---|---|
| `address` | string (IP) | The alternate IP that merged into the primary `mgmt_ip`. Always present. |
| `role` | [`AltIpRole`](../reference/schema/device-record.md#altiprole) \| null | Role hint mapped 1:1 to NetBox / Nautobot / Infrahub IP-address role models. Omitted from the wire form when null. |
| `responded_via` | array<`ProbeKind`> | Deduplicated list of probe kinds this IP answered before the merge (for example `Arp`, `Snmp`, `TcpConnect`). A prober that ran against the IP but got no answer is not listed. Omitted from the wire form when empty. |

### `AltIpRole` values

The role hint is one of `secondary`, `loopback`, `vrrp`, `hsrp`, `carp`, `anycast`, or `vip`. The [schema reference](../reference/schema/device-record.md#altiprole) has the full enum. What the identity fuser writes today:

- `secondary` — the default when an alternate IP merges in. Written whenever the MAC is not a known virtual-router prefix (or when there is no MAC at all).
- `vrrp` — the alternate IP's MAC matches a VRRP prefix (`00:00:5e:00:01:XX` for VRRPv2, `00:00:5e:00:02:XX` for VRRPv3).
- `hsrp` — the alternate IP's MAC matches the Cisco HSRP prefix (`00:00:0c:07:ac:XX`).

The rest of the enum (`loopback`, `carp`, `anycast`, `vip`) is reserved. The identity fuser does not emit these today. They are part of the wire contract so future signals (SNMP `ifDescr`, load-balancer VIP hints) can populate them without a schema change.

!!! warning "CARP is not distinguishable from VRRP today"
    FreeBSD's CARP reuses the VRRPv2 MAC prefix `00:00:5e:00:01:XX`, so MAC-only inference reports a CARP virtual IP as `role: vrrp`. Do not expect `role: carp` on a CARP-configured device — the variant is reserved for a future signal-based detection path.

## Example scenario

Discover a lab where a core switch answers on three IPs — the management IP `10.0.0.1`, a loopback `1.1.1.1`, and a second interface `10.0.0.2`:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: lab-multi-ip-identity
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
      type: identity
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
  "alt_ips": [
    {"address": "10.0.0.2", "role": "secondary", "responded_via": ["Arp", "Snmp"]},
    {"address": "1.1.1.1", "role": "secondary", "responded_via": ["Arp", "Snmp"]}
  ],
  "possible_alias_of": null,
  ...
}
```

## See also

- [Scenario reference](../reference/scenario.md#identity) — full field table for `identity` and `identity_hints`.
- [Enrichment](enrichment.md) — how `oui_enrichment` populates the `manufacturer` field the identity fuser uses for conflict detection.
- [SNMP prober](../probe/snmp.md) — where the `sysName` signal comes from.
- [ARP prober](../probe/arp.md) and [NDP prober](../probe/ndp.md) — where the MAC signal comes from.
