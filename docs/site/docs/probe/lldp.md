---
description: The LLDP prober — walks the LLDP-MIB over SNMP to read a device's directly-connected neighbors, then assembles them into topology links. Shares the SNMP prober's transport, versions, and USM credentials.
---

# LLDP prober

The LLDP prober discovers a device's link-layer neighbors — the other devices directly connected to its interfaces by a cable. A switch or router that runs LLDP announces its own identity out every port and listens for its neighbors doing the same, so each device keeps a table of who is on the other end of each cable. The prober reads that table over SNMP — it walks the LLDP-MIB, reading the table's rows one at a time — along with the device's own chassis identity. Each neighbor then flows to rastreo's topology stage. Unlike every other prober, it does not emit device signals. Its output is the set of links between devices, emitted as `LinkRecord`s. See [Topology](../discover/topology.md) for the record shape and where it is delivered.

**Use it when** you want to map which devices are directly cabled to which — the network's topology.<br>
**You get** topology links (`LinkRecord`s), not device signals: each reachable device's list of directly connected neighbors.

LLDP (IEEE 802.1AB) is the vendor-neutral neighbor-discovery protocol most switches and routers speak. Because the prober reads the neighbor table over SNMP, it needs the same SNMP access as the [SNMP prober](snmp.md).

## Configuration

Add an `lldp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "lldp"}` — that reads the neighbor table over UDP 161 with SNMPv2c and community `public`.

The prober takes the same transport fields as the SNMP prober — `ports`, `version`, `community`, and `credentials` — plus one field of its own, `max_rows`, which bounds how many table rows a single walk reads.

```yaml
probers:
  - type: lldp
    ports: [161]
    version: v2c
    community: public
    max_rows: 4096
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"lldp"`. |
| `ports` | array of port numbers | no | `[161]` | SNMP ports to read from. Sorted and deduplicated at construction. |
| `version` | string | no | `v2c` | One of `v1`, `v2c`, `v3`. Same meaning as the [SNMP prober](snmp.md#versions-supported). |
| `community` | string | no | `public` | SNMP community string. Used on `v1` and `v2c`. Ignored on `v3`. Redacted from debug output. |
| `credentials` | object | no | `{}` | USM credentials. Used on `v3`. Ignored on `v1` and `v2c`. See [SNMPv3 credentials](snmp.md#snmpv3-credentials). |
| `max_rows` | integer | no | `4096` | Maximum neighbor-table rows a single walk reads. Bounds one probe against a device with a very large table. |

## SNMP transport and authentication

The LLDP prober uses the same SNMP transport and authentication as the [SNMP prober](snmp.md). Everything on that page about versions, community strings, and USM credentials applies here unchanged:

- **Versions** — `v1`, `v2c`, and `v3` behave exactly as documented under [Versions supported](snmp.md#versions-supported). On `v3`, an engine-ID discovery round trip happens before the authenticated read.
- **Cleartext community** — `v1` and `v2c` send the community string in cleartext. The same [security notes](snmp.md#security-notes) apply: prefer `v3` with `authPriv` on sensitive networks.
- **USM credentials** — the `credentials` object has the same `username`, `auth`, and `privacy` shape described under [SNMPv3 credentials](snmp.md#snmpv3-credentials). Passwords accept `${VAR}` and `!file` secrets and are redacted from debug output.

Because the two probers share this surface, a device you already reach with the SNMP prober is reachable with the LLDP prober using the same version and credentials.

## Signals emitted

The LLDP prober emits no device signals — its `signals` array is always empty. Its result is the neighbor table, which rastreo assembles into `LinkRecord`s on a [second stream](../discover/topology.md#where-links-are-emitted).

A device the LLDP prober reaches still produces a `DeviceRecord`. The record is reachable, carries `probe_kinds: ["Lldp"]` as provenance, and has no signals of its own. The neighbor data it contributed shows up in the topology stream, not on the device record.

The prober follows the same three-way result model as every prober — reachable, unreachable, or a probe fault. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults). Three cases are worth calling out:

- **A device with neighbors** answers the read and returns its table. The device is reachable and its neighbors flow into the topology stream.
- **A device with an empty neighbor table** — LLDP enabled, but nothing seen on any port — is reachable with no neighbors. An empty table is a valid answer, not a fault.
- **A reply rastreo cannot decode** keeps the device: it answered, so it is reachable, and the fault is recorded as `decode_failed` with no neighbors. A silent device is different — nothing answered, so it is unreachable.

## Build feature

The LLDP prober is behind the `lldp` Cargo feature. Enabling `lldp` turns on `snmp` as well, because the prober reuses the SNMP transport. It is bundled in the published release binaries and Docker image; to build it yourself, enable the feature with:

```bash
cargo build --features lldp
cargo build --release --features lldp,kafka
```

The `lldp` feature is included in the pre-built release binaries and the Docker image, so no extra step is needed to use it. When rastreo is built without the feature, a scenario that references `type: lldp` is rejected with an unknown-variant error.

## Example scenarios

Read the neighbor table from a switch that speaks SNMPv2c:

```yaml
targets:
  - Ip: 10.0.0.1
probers:
  - type: lldp
    version: v2c
    community: public
```

Discover topology across a management subnet, alongside a device-fingerprinting SNMP probe. The `snmp` prober fills in vendor and identity signals; the `lldp` prober adds the links between the devices it reaches:

```yaml
targets:
  - Cidr: 10.0.0.0/24
probers:
  - type: snmp
    version: v2c
    community: public
  - type: lldp
    version: v2c
    community: public
```

Read the neighbor table over SNMPv3 with `authPriv` — SHA-256 for authentication, AES-128 for encryption:

```yaml
targets:
  - DnsName: core-01.lab.local
probers:
  - type: lldp
    version: v3
    credentials:
      username: probe
      auth:
        algorithm: sha256
        password: ${SNMP_AUTH_PASSWORD}
      privacy:
        algorithm: aes128
        password: ${SNMP_PRIV_PASSWORD}
```

Cap the walk on a device with a large neighbor table so one probe cannot read an unbounded number of rows:

```yaml
targets:
  - Ip: 10.0.0.1
probers:
  - type: lldp
    version: v2c
    community: public
    max_rows: 512
```

## See also

- [Topology](../discover/topology.md) — the `LinkRecord` shape, link de-duplication, and where links are emitted.
- [SNMP prober](snmp.md) — the shared transport, versions, USM credentials, and security notes.
- [LinkRecord schema](../reference/schema/link-record.md) — every field on the emitted link record.
- [Discover CLI](../discover/cli.md#choosing-probers) — `--probe lldp` selects it, and `--snmp-community` / `--snmp-version` tune it exactly as they do the SNMP prober. SNMPv3 USM credentials need `--file`.
- [Scenario schema](../reference/scenario.md#lldp) — the full prober configuration reference.
