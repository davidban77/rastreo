---
description: How downstream consumers reconcile rastreo records into a source of truth (NetBox, Nautobot, Infrahub) — the contract, the dedup key, and one sketch per system.
---

# Source of truth reconciliation

rastreo discovers devices and emits `DeviceRecord` events; reconciling those events into a source of truth (NetBox, Nautobot, Infrahub, or anything else) is the job of an independent consumer. rastreo does not ship consumer code, and the consumer is intentionally outside the core scope. The page below describes the contract a consumer is expected to honour and gives one short sketch per target system to anchor the pattern.

## The reconciliation pattern

A consumer reads `DeviceRecord` events from the Kafka topic (or an NDJSON file, or stdin), groups by `identity_key`, and upserts each unique key into the source of truth. The same `identity_key` may arrive any number of times across scans — the consumer must be idempotent.

The minimum upsert flow is:

1. Read a `DeviceRecord` from the stream.
2. Look up the existing entry in the source of truth by `identity_key`.
3. If it exists, replace populated fields and bump `last_seen`. If it does not, create it.
4. Acknowledge the Kafka offset (or advance the NDJSON cursor) only after the upsert succeeds.

`last_seen` is an RFC 3339 UTC timestamp string (e.g. `"2026-07-05T11:22:51.423959000Z"`) marking the last probe that touched the device. Consumers should keep the most recent value seen for a given `identity_key` and use it to drive staleness policies (for example, a device that has not been seen in 30 days could be flagged or retired).

## Confidence filtering

`confidence` is a float in the range 0.0 to 1.0 produced by the fuser. A consumer can drop records below a chosen threshold to filter out weak observations. A reasonable default is `< 0.3` for "drop"; tune higher when the source of truth is sensitive to noise, lower when you want every signal in.

A record from a single TCP-connect probe (one open port) lands at `confidence: 0.2` with the default `DirectFuser`. The score rises as more signals fuse into the same `identity_key`.

## Mapping signals to source-of-truth fields

Every probe produces `Signal` entries carried on the `DeviceRecord` in the `signals` array. A reconciler decides which signals become fields on the source-of-truth object and which stay as raw observation history. The signals below have a natural mapping into the NetBox, Nautobot, and Infrahub data models — either as canonical fields populated upstream by the classifier, or as raw signals a reconciler pins directly.

The signals split by role:

- **Identity** — `SshHostKey`, `TlsSubject`, `TlsSanName`, `ReverseDnsName`. These help answer *which device is this?*. Four of them are already consumed by the [identity fuser](../discover/identity.md) for cross-IP correlation, so if you enable that fuser your reconciler receives one merged record per device and does not need to redo the correlation.
- **Fingerprint** — `SshBanner`, `SnmpSysDescr`, `SnmpSysName`, `HttpBanner`. These help answer *what software / version is running?*. When the [rules classifier](../discover/classification.md) is enabled, these signals populate `DeviceRecord.platform` and `DeviceRecord.os_version` directly; your reconciler can read the canonical fields and treat the raw signals as history. When only `noop` is configured, both fields stay `null` and the reconciler owns any inference.
- **Operational** — `IcmpEchoRttMicros`. This is a time-varying observation, not an identity claim. Treat it as a metric point, not as device metadata.

### Identity signals

These signals correlate a device across scans and across IPs. When the identity fuser is enabled, matching values fold multiple per-IP records into one; the reconciler still benefits from storing the underlying values so external systems (audit tools, network graph views) can query them directly.

| Signal | Description | NetBox field | Nautobot field | Infrahub field |
|---|---|---|---|---|
| `SshHostKey` | OpenSSH single-line encoding of the server's host key (for example `"ssh-ed25519 AAAAC3Nz..."`). Device-unique in practice. Consumed by the identity fuser at weight 0.8 — merges alone at the high band. | Custom field on `dcim.Device`, for example `rastreo_ssh_host_key`. | Custom field on `dcim.Device`, for example `rastreo_ssh_host_key`. | String attribute on your device kind, for example `ssh_host_key`. |
| `TlsSubject` | Subject Common Name from the leaf certificate. Often generic (`localhost`, `nginx`) — do not use as a stand-alone unique key. | Custom field, for example `rastreo_tls_subject`. | Same shape. | String attribute. |
| `TlsSanName` | One entry per Subject Alternative Name. DNS entries emit the name (`api.example.com`); IP entries emit `ip:<addr>` (`ip:10.0.0.1`). Multiple entries per record are normal. | Multi-value custom field or a related model. If your NetBox extension already stores certificate SANs, reuse that. | Same as NetBox. | Array attribute or related node. |
| `ReverseDnsName` | Hostname returned by a PTR query, trailing `.` stripped. Multiple names per IP are allowed by RFC and rastreo emits one signal per name. | The built-in `dcim.Device.name` field is a good primary target when a single name is present. Store additional names in a custom field or as related `ipam.IPAddress.dns_name` entries. | Same as NetBox — `dcim.Device.name` primary, custom field for extras. | Standard `name` attribute on the device kind; additional names on a related node. |

The identity fuser already consumes all four of these to merge cross-IP records. If your reconciler groups by `identity_key`, the merge has already happened and each merged record carries the union of the constituents' signals — no additional correlation code is needed on the reconciler side.

### Fingerprint signals

Fingerprint signals identify the software running on a device. `SshBanner`, `SnmpSysDescr`, `SnmpSysName`, and `HttpBanner` all feed the [rules classifier](../discover/classification.md); when the classifier is enabled, `DeviceRecord.platform` and `DeviceRecord.os_version` are populated directly and the raw signals remain on the record as history.

When the classifier is not enabled (`classifier.type: noop`, or omitted), `platform` and `os_version` stay `null` and the reconciler has to derive them from the raw signals — or leave the source of truth without a platform value.

| Signal | Populates on the record | NetBox / Nautobot mapping | Infrahub mapping |
|---|---|---|---|
| `SshBanner` | Feeds `platform` (e.g. `linux`, `freebsd`) when the SSH banner rules match. Example value: `"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3"`. | Set the built-in `dcim.Device.platform` foreign key from `DeviceRecord.platform`. Keep the raw banner in a custom field like `rastreo_ssh_banner` for audit. | Set the standard platform attribute from `DeviceRecord.platform`. Keep the raw banner in a `ssh_banner` string attribute. |
| `SnmpSysDescr` | Feeds `platform` and `os_version` when the SNMP `sysDescr` rules match. Covers Cisco IOS / IOS-XR / NX-OS, Juniper JUNOS, Arista EOS, Linux. | `dcim.Device.platform` foreign key + a `dcim.Device.software_version` custom field (or the built-in `Platform.version` if you model it that way). | `platform` attribute + a version string attribute on the device kind. |
| `SnmpSysName` | User-defined rules only; no defaults ship. Set `platform` / `os_version` from your naming convention if you have one. | Same shape as `SnmpSysDescr` above. | Same shape as `SnmpSysDescr` above. |
| `HttpBanner` | Feeds `platform` and `os_version` when the `Server:` header matches the HTTP rules. Covers `nginx/*` and `Apache/*`. | `dcim.Device.platform` + `dcim.Device.software_version`. Useful mainly for hosts and appliances that speak HTTP as the front door. | `platform` attribute + version string attribute. |

### Operational signal

`IcmpEchoRttMicros` is the minimum ICMP echo round-trip time in microseconds across the probe's echo requests. It changes on every scan, so it does not belong in a device's static configuration attributes.

| Signal | NetBox field | Nautobot field | Infrahub field |
|---|---|---|---|
| `IcmpEchoRttMicros` | Custom field like `rastreo_last_rtt_us` on `dcim.Device`, or (better) a Prometheus / InfluxDB metric point keyed by `identity_key`. | Same choice — custom field or external metric store. | Same choice — either a custom attribute or an external metric store. |

The custom-field path keeps every observation reachable through the source-of-truth API; the metric-store path keeps the source of truth lean and gives you time-series charts without extra work. Pick one based on how your team already tracks operational data.

## Multi-IP devices and `alt_ips`

When the [identity fuser](../discover/identity.md) is configured, a multi-homed device arrives as a single `DeviceRecord`. `mgmt_ip` holds the primary address; `alt_ips` holds the other addresses. Each entry is an [`AltIp`](../reference/schema/device-record.md#altip) object with `address`, an optional `role` hint, and the `responded_via` probe kinds that saw that IP before the merge.

The `role` values (`secondary`, `loopback`, `vrrp`, `hsrp`, `carp`, `anycast`, `vip`) map 1:1 onto the IP-address role fields in NetBox, Nautobot, and Infrahub. The consumer attaches each alternate IP to the primary device and copies the role field over:

- **NetBox** — create an `ipam.IPAddress` for each `AltIp.address`, set its `assigned_object` to the device's primary interface, and copy `role` into the built-in `role` field on the IP address.
- **Nautobot** — same shape as NetBox. `ipam.IPAddress` with the built-in `role` populated from `AltIp.role`.
- **Infrahub** — create one `IpamIPAddress` (or your schema's equivalent) per `AltIp.address` linked to the device, and set the role attribute from `AltIp.role`.

If your reconciler doesn't need the role hint, `AltIp.address` alone is enough for a plain "extra IP on this device" attachment.

## NetBox

NetBox exposes a REST API at `/api/dcim/devices/`. Map `identity_key` to a NetBox custom field (for example `rastreo_identity_key`) and use it as the idempotency key. Look up the device by the custom field; if it exists, `PATCH` the changed fields; otherwise `POST` a new device.

```bash
curl -X PATCH https://netbox.example.com/api/dcim/devices/123/ \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_fields": {
      "rastreo_identity_key": "ip:10.50.0.10",
      "rastreo_confidence": 0.2,
      "rastreo_last_seen": "2026-06-22T22:30:00Z"
    }
  }'
```

## Nautobot

Nautobot's REST API mirrors NetBox at `/api/dcim/devices/`. The shape is the same; the difference is the host and the auth header convention. Reuse the same `identity_key`-to-custom-field mapping.

```bash
curl -X PATCH https://nautobot.example.com/api/dcim/devices/abc-123/ \
  -H "Authorization: Token $NAUTOBOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_fields": {
      "rastreo_identity_key": "ip:10.50.0.10",
      "rastreo_last_seen": "2026-06-22T22:30:00Z"
    }
  }'
```

## Infrahub

Infrahub is GraphQL-first. Upserts are expressed as mutations against the device kind your schema defines. Use the `identity_key` as the upsert key on a string attribute.

```graphql
mutation {
  DcimDeviceUpsert(
    data: {
      rastreo_identity_key: { value: "ip:10.50.0.10" }
      mgmt_ip:              { value: "10.50.0.10" }
      rastreo_confidence:   { value: 0.2 }
      rastreo_last_seen:    { value: "2026-06-22T22:30:00Z" }
    }
  ) {
    ok
    object { id }
  }
}
```

Adjust the kind name (`DcimDeviceUpsert`) to match your Infrahub schema.

## See also

- [Kafka](kafka.md) — the wire contract a consumer reads from.
- [Troubleshooting](troubleshooting.md) — what to check when records do not reach the source of truth.
