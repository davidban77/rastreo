---
description: How rastreo turns LLDP neighbor data into LinkRecords — the two-endpoint edge, known-unknown neighbors, link de-duplication, correlation back to device records, the second emit stream, and the mapping to NetBox cables and Nautobot interface connections.
---

# Topology

rastreo discovers devices, and it also discovers how those devices connect. It builds this topology from LLDP neighbor data — read over SNMP by the [LLDP prober](../probe/lldp.md), or over gNMI by the [gNMI prober](../probe/gnmi.md) with `lldp: true`. Each connection between two devices becomes a `LinkRecord` — a topology edge you can reconcile into cables in NetBox or interface connections in Nautobot. This page explains what a `LinkRecord` is, how rastreo builds it, and where it is emitted.

## What a LinkRecord is

A `LinkRecord` is one link between two endpoints. rastreo names the endpoints `a` and `b`; the order carries no meaning, so do not read `a` as "near" and `b` as "far".

Each endpoint carries four values:

- `chassis_id` — the neighbor's LLDP chassis identifier. Most switches advertise this as a MAC address; rastreo renders it in lowercase hex with no separators (for example `aabbcc001122`).
- `sys_name` — the hostname the neighbor advertises over LLDP. Present when the neighbor sends it, absent otherwise.
- `port` — the interface the link uses on that endpoint (for example `Ethernet1/1`).
- `identity_key` — points at the matching `DeviceRecord` when rastreo also probed that endpoint. Absent when rastreo learned the endpoint only through a neighbor's advertisement. See [Known-unknown neighbors](#known-unknown-neighbors).

The record also carries a few top-level fields: `discovered_via` names the source that found the link (see [Topology sources](#topology-sources)), `observed_at` is when rastreo last saw it, and `scan_metadata` is the same per-scan provenance object stamped on every `DeviceRecord`. `schema_version` and `schema_id` identify the record shape.

Here is one `LinkRecord` between a probed switch and a neighbor rastreo saw but never probed:

```json
{
  "schema_version": "v1",
  "schema_id": "https://davidban77.github.io/rastreo/schemas/link-record-v1.json",
  "a": {
    "identity_key": "mac:aa:bb:cc:00:11:22",
    "chassis_id": "aabbcc001122",
    "sys_name": "core-sw-01",
    "port": "Ethernet1/1"
  },
  "b": {
    "chassis_id": "ddeeff334455",
    "sys_name": "edge-sw-07",
    "port": "Gi0/24"
  },
  "discovered_via": "lldp",
  "observed_at": "2026-07-05T13:47:22Z",
  "scan_metadata": {
    "scan_id": "01KXC3Z94835AJY8WWSYQ81Y1P",
    "initiated_at": "2026-07-05T13:47:22.676000Z",
    "source_config_hash": "sha256:63b96614fd6aa54b03a6f04d56b311d00c795f32881a27d0d4168411ec6a2f30"
  }
}
```

Endpoint `a` has an `identity_key`, so rastreo probed that device and you can join the link to its `DeviceRecord`. Endpoint `b` has no `identity_key` — it is a known-unknown neighbor.

## Topology sources

You can run either the SNMP [LLDP prober](../probe/lldp.md) or the [gNMI prober](../probe/gnmi.md) with `lldp: true`, or both. The `discovered_via` field on each `LinkRecord` names the source that found the link:

| `discovered_via` | Source |
|---|---|
| `lldp` | The SNMP LLDP prober saw the link. |
| `gnmi` | The gNMI prober saw the link. |
| `gnmi,lldp` | Both transports saw the same physical link, and rastreo de-duplicated it to one record. |

The `gnmi,lldp` value follows the [one-record-per-physical-link](#one-record-per-physical-link) rule: when the SNMP and gNMI sources report the same link, rastreo collapses them into a single `LinkRecord` and lists both sources.

## Known-unknown neighbors

An endpoint with no `identity_key` is a neighbor rastreo learned about only through LLDP. A probed device advertised it as a neighbor, but rastreo never probed the neighbor itself — it was outside the target list, or it did not answer.

rastreo keeps these endpoints instead of dropping them. You know the link exists, which chassis it connects to, and which port it uses. You just do not have a full `DeviceRecord` for that side yet. Add the neighbor to a later scan's targets and rastreo can probe it, at which point the endpoint's `identity_key` fills in.

## One record per physical link

When rastreo probes both ends of a link, each end reports the other as a neighbor — so the same physical cable shows up twice, once from each side. rastreo collapses the two reports into one `LinkRecord`, keyed by the pair of chassis identifiers. You get one edge per link, not two.

When rastreo probes only one end, the record still describes the whole link. The probed end is a full endpoint; the other end is a [known-unknown neighbor](#known-unknown-neighbors).

## Correlation to device records

rastreo matches each endpoint back to a probed device so you can join the two streams. It tries three keys in turn:

- **MAC address** — the chassis identifier matched against a device's discovered MAC.
- **Hostname** — the advertised `sys_name` matched against a device's SNMP `sysName` or reverse-DNS name.
- **IP address** — when the chassis identifier is a network address, matched against a device's management or alternate IPs.

When any key matches, the endpoint's `identity_key` is set to that device's key — the exact value on the device's `DeviceRecord`. A consumer joins a link to its devices by `identity_key` alone, with no identity logic of its own. rastreo reuses the same MAC and hostname normalization as the [identity fuser](identity.md), so the two agree on what counts as a match.

## Where links are emitted

`LinkRecord`s travel on a second stream, separate from device records. How the two streams are split depends on the sink.

=== "Kafka"

    Device records go to `topic`. Link records go to `links_topic`, which defaults to `rastreo.discovery.links.v1`. Device records default to `rastreo.discovery.records.v1`. Set `links_topic` to route links to a topic of your choice.

    ```yaml
    sink:
      type: kafka
      brokers: ["kafka-0.internal:9092"]
      topic: rastreo.discovery.records.v1
      links_topic: rastreo.discovery.links.v1
    ```

=== "NATS"

    Device records go to `subject`. Link records go to `links_subject`, which defaults to `rastreo.discovery.links.v1`. Set `links_subject` to route links to a subject of your choice.

    ```yaml
    sink:
      type: nats
      servers: ["nats://nats:4222"]
      subject: rastreo.discovery.records.v1
      links_subject: rastreo.discovery.links.v1
      stream: rastreo
    ```

    !!! warning "Bind the JetStream stream to both subjects"
        The stream must capture both the device subject and the links subject, for example with the wildcard `rastreo.discovery.>`. A stream bound only to the device subject refuses link publishes at ack time once LLDP data appears. See [NATS · Topology links on a second subject](../integrate/nats.md#topology-links-on-a-second-subject).

=== "stdout / file"

    Both record kinds share one NDJSON stream. Tell them apart by `schema_id`: a device record carries the `device-record-v1.json` URL, a link record carries the `link-record-v1.json` URL.

    ```bash
    rastreo discover --file scenario.yaml \
      | jq 'select(.schema_id | contains("link-record"))'
    ```

The scan summary reports how many link records the scan produced in `links_emitted`, alongside the device-record counts.

## Mapping to a source of truth

Each `LinkRecord` maps to one cable in NetBox or one interface connection in Nautobot: a link between two interface terminations. The two endpoints give a consumer both sides of the cable at once.

For each endpoint, a reconciler resolves the device by `identity_key` and the interface by `port`, then creates or updates the cable between the two terminations:

- **NetBox** — create a `dcim.Cable` connecting the two `dcim.Interface` terminations. Resolve each device through the same `rastreo_identity_key` custom field the device reconciler uses, then resolve the interface by `port` name.
- **Nautobot** — create the equivalent interface connection between two `dcim.Interface` records, resolved the same way.

When one endpoint is a [known-unknown neighbor](#known-unknown-neighbors), the reconciler has a chassis identifier and a port but no device record. Handle it the way your source of truth handles a cable to an unmodeled device: skip the link until the neighbor is probed, or create a placeholder device from the `chassis_id` and `sys_name`. The choice belongs to the reconciler, not to rastreo.

## See also

- [LLDP prober](../probe/lldp.md) — how rastreo reads a device's neighbor table.
- [LinkRecord schema](../reference/schema/link-record.md) — every field on the emitted record.
- [Identity](identity.md) — the MAC and hostname correlation rastreo reuses to match endpoints to devices.
- [Source of truth](../integrate/source-of-truth.md) — the reconciliation contract for the device stream.
