---
description: How downstream consumers reconcile rastreo records into a source of truth (NetBox, Nautobot, Infrahub) — the contract, the dedup key, and one sketch per system.
---

# Source of truth reconciliation

rastreo discovers devices and emits `DeviceRecord` events. A *source of truth* is the inventory system your network team treats as the intended state of the network. NetBox and Nautobot are open-source web apps for exactly that — device tables, IP address management, and more; Nautobot began as a fork of NetBox. Infrahub is a newer, graph-based one. rastreo does not write to any of them directly. *Reconciling* the events into a source of truth is the job of an independent consumer you run. It compares what rastreo observed against what the inventory records, then creates or updates entries so the inventory matches reality. rastreo does not ship that consumer, and it is intentionally outside the core scope. This page describes the contract a consumer honours and gives one short sketch per target system.

## The reconciliation pattern

A consumer reads `DeviceRecord` events from the Kafka topic (or an NDJSON file, or stdin), groups by `identity_key`, and upserts each unique key into the source of truth. The same `identity_key` may arrive any number of times across scans, so the consumer must be *idempotent*: processing the same record twice leaves the same result as processing it once.

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
- **Fingerprint** — `SshBanner`, `SnmpSysDescr`, `SnmpSysName`, `HttpBanner`, `SnmpSysObjectId`, and `OpenPort`. These help answer *what software / version is running?* and *what kind of device is this?*. Under the [rules classifier](../discover/classification.md), SNMP signals populate `DeviceRecord.platform` + `DeviceRecord.os_version`, `SshBanner` populates `DeviceRecord.platform` (OS) + `DeviceRecord.os_version` (distro token) + `DeviceRecord.ssh_version` (SSH software), `HttpBanner` populates `DeviceRecord.platform` (OS) + `DeviceRecord.http_server` (web-server product) + `DeviceRecord.http_version` (product version), and `SnmpSysObjectId` + `OpenPort` populate `DeviceRecord.role`. Your reconciler reads the canonical fields and keeps the raw signals as history. The rules classifier runs by default, so these fields arrive populated unless a scenario sets `classifier.type: noop`.
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

Fingerprint signals identify the software running on a device and what role that device plays. `SshBanner`, `SnmpSysDescr`, `SnmpSysName`, and `HttpBanner` feed the platform phase of the [rules classifier](../discover/classification.md); `SnmpSysObjectId` and `OpenPort` feed the role phase. The rules classifier runs by default, so `DeviceRecord.platform`, `DeviceRecord.os_version`, `DeviceRecord.ssh_version`, `DeviceRecord.http_server`, `DeviceRecord.http_version`, and `DeviceRecord.role` are populated directly and the raw signals remain on the record as history.

Expect these fields to carry values as soon as a probe collects a signal a baked-in rule matches — an SSH banner sets `platform`, `os_version`, and `ssh_version`; `[22, 179]` open together sets `role: router`. The shipped tables classify only on evidence and leave `role` at `null` on a guess (a single open port is a guess), because `null` is the one value that is safe downstream: most reconcilers, including the three sketched below, overwrite a field whose value differs rather than filling only empty ones. A populated `platform` or `role` will therefore replace whatever an operator set by hand, so decide deliberately whether your reconciler should write those two fields at all — and consider gating the write on the object being unset, or on `confidence` clearing a threshold.

Set `classifier.type: noop` to turn classification off and keep all six fields `null`, leaving the reconciler to derive them from the raw signals. That setting lives in a scenario file; a flag-driven `rastreo discover --target ...` has no classifier switch, so use `--file`.

| Signal | Populates on the record | NetBox / Nautobot mapping | Infrahub mapping |
|---|---|---|---|
| `SshBanner` | Feeds `platform` (OS — `linux`, `freebsd`) + `os_version` (distro token, e.g. `Ubuntu`) + `ssh_version` (SSH software identifier, e.g. `OpenSSH_9.3p1`) when the SSH banner rules match. Example value: `"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3"`. | Set the built-in `dcim.Device.platform` foreign key from `DeviceRecord.platform`. Store `os_version` and `ssh_version` in custom fields (`rastreo_os_version`, `rastreo_ssh_version`) and keep the raw banner for audit. | Set the standard platform attribute from `DeviceRecord.platform`. Store `os_version` and `ssh_version` on dedicated string attributes; keep the raw banner in a `ssh_banner` string attribute. |
| `SnmpSysDescr` | Feeds `platform` and `os_version` when the SNMP `sysDescr` rules match. Covers Cisco IOS / IOS-XR / NX-OS, Juniper JUNOS, Arista EOS, Linux. | `dcim.Device.platform` foreign key + a `dcim.Device.software_version` custom field (or the built-in `Platform.version` if you model it that way). | `platform` attribute + a version string attribute on the device kind. |
| `SnmpSysName` | User-defined rules only; no defaults ship. Set `platform` / `os_version` from your naming convention if you have one. | Same shape as `SnmpSysDescr` above. | Same shape as `SnmpSysDescr` above. |
| `HttpBanner` | Feeds `platform` (OS — `linux`), `http_server` (web-server product, e.g. `nginx` or `Apache`), and `http_version` (product version, e.g. `1.24.0`) when the `Server:` header matches the HTTP rules. `os_version` stays unset from this signal. Covers `nginx/*` and `Apache/*`. | Set `dcim.Device.platform` from `DeviceRecord.platform`. Store `http_server` and `http_version` in custom fields (`rastreo_http_server`, `rastreo_http_version`). Useful mainly for hosts and appliances that speak HTTP as the front door. | `platform` attribute + dedicated `http_server` and `http_version` string attributes. |
| `SnmpSysObjectId` | Feeds `role` when a user-supplied `sys_object_id_prefix` role rule matches — no baked-in prefixes ship because no public vendor MIB tree cleanly maps sub-prefixes to device roles; users supply rules against their own fleet's OIDs. See `classification.md#baked-in-role-rules` for the rationale. Example value: `"1.3.6.1.4.1.9.1.2050"`. | `dcim.Device.role` (or `device_role`) foreign key from `DeviceRecord.role`. Keep the raw OID in a custom field like `rastreo_sys_object_id` for audit. | Standard role attribute + a `sys_object_id` string attribute. |
| `OpenPort` | Feeds `role` when a `ports_open` role rule matches. The default port sets cover `router` only (SSH + BGP, or SSH + HTTPS + NETCONF); the single-port `web_server` and `host` heuristics ship but are opt-in. Rules match when every listed port appears; extra open ports do not cause a mismatch. | `dcim.Device.role` foreign key from `DeviceRecord.role`. Individual open ports live better as related `dcim.Service` or interface records if your model has them. | Standard role attribute; individual ports as related records. |

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

NetBox stores devices in a table called `dcim.Device`, reachable over its REST API at `/api/dcim/devices/`. To hold rastreo's identity key, add a *custom field* — a user-defined extra column you create once in the NetBox admin UI — named `rastreo_identity_key`. The consumer uses that field as the idempotency key: look the device up by it, `PATCH` the changed fields if it exists, or `POST` a new device if it does not.

NetBox does not let you `PATCH` a device by identity key directly — you `PATCH` by NetBox's numeric device `id`. So the upsert is two calls. First look the device up by the custom field; the query returns the matching device and its `id`:

```bash
curl -G https://netbox.example.com/api/dcim/devices/ \
  --data-urlencode "cf_rastreo_identity_key=ip:10.50.0.10" \
  -H "Authorization: Token $NETBOX_TOKEN"
# -> {"count": 1, "results": [{"id": 123, ...}]}   # 0 results means create instead
```

Then `PATCH` that `id` (here `123`) with the fields the record carries:

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
