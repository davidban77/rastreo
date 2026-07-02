---
description: The SNMP prober — issues an SNMP v1 or v2c GetRequest for the MIB-II system group and emits sysDescr, sysObjectID, and sysName as typed signals for vendor and identity fingerprinting.
---

# SNMP prober

The SNMP prober speaks Simple Network Management Protocol against configured UDP ports on every resolved target. It issues a single `GetRequest` for three high-signal object identifiers from the RFC 1213 MIB-II system group — `sysDescr`, `sysObjectID`, `sysName` — and emits each returned varbind as a typed signal. Those three values are enough to identify the vendor line, the specific product family, and the operator-assigned hostname for the vast majority of managed network devices: routers, switches, wireless controllers, UPSes, printers, and SNMP-enabled Linux hosts.

## Configuration

Add an `snmp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "snmp"}` — that probes UDP 161 with SNMPv2c and community `public`.

```yaml
probers:
  - type: snmp
    ports: [161]
    version: v2c
    community: public
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"snmp"`. |
| `ports` | array of u16 | no | `[161]` | Ports to probe. Sorted and deduplicated at construction. |
| `version` | string | no | `v2c` | One of `v1`, `v2c`. See [Versions supported](#versions-supported). |
| `community` | string | no | `public` | SNMP community string. Sent verbatim in the message. See [Security notes](#security-notes). |

The prober issues one `GetRequest` per port. It uses an ephemeral UDP socket per port, encodes the request via BER, sends the datagram, waits for a response until the scenario-level `timeout_ms` expires, decodes the response, and maps each returned varbind to a `Signal`. Datagrams received from a peer that isn't the target address are ignored — the prober keeps waiting until the target answers or the timeout fires.

## Versions supported

| `version` | Wire protocol | Notes |
|---|---|---|
| `v1` | RFC 1157 | Legacy. Widely supported on older enterprise gear (Cisco IOS 12.x, older Juniper releases, most printers). Uses ASN.1 `NULL` as the placeholder value in each varbind of the request. |
| `v2c` | RFC 3416 with the RFC 1901 community-based transport | Modern default. Uses the `Unspecified` varbind value for GetRequest. Encoding is more compact and error handling is richer, but the wire security model is identical to v1 — the community string travels in cleartext. |

SNMPv3 (authenticated / encrypted USM) is planned in a follow-up release. Use `v2c` for now unless the target only speaks v1.

## OIDs probed

The prober always queries the same three scalar OIDs from the MIB-II system group. The trailing `.0` on each OID is the scalar instance suffix — SNMP object identifiers name the class; the `.0` names the single instance of that scalar object.

| OID | MIB-II name | Signal | Value shape |
|---|---|---|---|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` | `SnmpSysDescr(<value>)` | Free-form vendor/OS/version string. Trimmed and capped at 256 bytes. |
| `1.3.6.1.2.1.1.2.0` | `sysObjectID` | `SnmpSysObjectId(<dotted>)` | Vendor's product OID from the enterprise arc (e.g. `1.3.6.1.4.1.9.1.516` for a Cisco Catalyst 3560). Dotted-decimal string. |
| `1.3.6.1.2.1.1.5.0` | `sysName` | `SnmpSysName(<value>)` | Operator-assigned hostname (typically the device's configured `hostname`). Trimmed and capped at 256 bytes. |

There is no configuration knob for extra OIDs today. The three baseline values are what a discovery pipeline needs to fingerprint vendor, model family, and identity; deeper polling of interface, inventory, or environmental tables is the reconciler's job, not the probe's.

## Security notes

SNMPv1 and SNMPv2c transmit the community string in cleartext in every message. Anyone who can capture the UDP packet can replay it against the agent. Do not use v1 or v2c against agents that hold sensitive counters or that respond to `SetRequest` over the same community — use SNMPv3 with `authPriv` for those cases. rastreo does not support SNMPv3 today; that support is planned in a follow-up release.

The default community `public` matches the read-only community configured on the majority of unmanaged SNMP agents. This is a deliberate discovery default — most greenfield scans target unknown or legacy fleets where `public` is what actually works — but it is not appropriate for production monitoring against hardened networks. Set `community` explicitly on scenarios that target managed fleets with rotated community strings.

The prober does not log the community string at any level. Configuration is logged only by field name, and error messages wrap only the operation and target address, never the credentials. The `community` field is also redacted from `Debug` output of both `SnmpProber` and `ProberConfig::Snmp`, so any accidental `dbg!` / `tracing::debug!` on those types prints `<redacted>` in place of the credential.

## Signals emitted

| Signal | When produced |
|---|---|
| `SnmpSysDescr(<value>)` | The response contained an `OCTET STRING` varbind at `1.3.6.1.2.1.1.1.0`. |
| `SnmpSysObjectId(<dotted>)` | The response contained an `OBJECT IDENTIFIER` varbind at `1.3.6.1.2.1.1.2.0`. |
| `SnmpSysName(<value>)` | The response contained an `OCTET STRING` varbind at `1.3.6.1.2.1.1.5.0`. |

A response with a nonzero `error-status` (for example `authorizationError` when the community is wrong on v2c, or `noSuchName` when v1 doesn't recognise the OID) marks the target as reachable but emits no signals. A reachable-but-refusing agent is still a signal in itself for discovery — you know a device is there and running SNMP, even if the community is not what was configured. A varbind whose value is not the ASN.1 type expected for that OID (for example `sysDescr` returned as an `INTEGER`) is silently skipped; the remaining varbinds are still processed.

If every port fails to reach the agent, the probe returns an error. Timeouts map to `Timeout`; connection-refused or unreachable-host errors map to `Unreachable`; BER decode failures on every port map to `Other("snmp decode failed on all ports")`.

## Build feature

The SNMP prober is gated behind the `snmp` Cargo feature on `rastreo-core`. Enable it explicitly when building from source:

```bash
cargo build --features snmp
cargo build --release --features snmp,http,kafka
```

The published Docker image and release binaries bundle the `snmp` feature by default. When the feature is disabled the prober module is not compiled and the `snmp` variant of `ProberConfig` is not present — scenarios that reference `type: snmp` will fail to deserialize with an unknown-variant error.

The feature pulls in `rasn`, `rasn-smi`, and `rasn-snmp` — pure-Rust BER/SNMP implementations. No C dependency, no OpenSSL, no `net-snmp` binding.

## Example scenarios

Probe a Linux server running `snmpd` on the standard port with SNMPv2c:

```json
{
  "targets": [{"Ip": "192.0.2.10"}],
  "probers": [
    {"type": "snmp", "ports": [161], "version": "v2c", "community": "public"}
  ]
}
```

A record produced against such an agent typically contains all three signals:

```json
{
  "signals": [
    {"SnmpSysDescr": "Linux router-01 6.6.32-generic #1 SMP x86_64"},
    {"SnmpSysObjectId": "1.3.6.1.4.1.8072.3.2.10"},
    {"SnmpSysName": "router-01"}
  ]
}
```

Probe legacy Cisco IOS gear that only speaks SNMPv1 with a rotated community:

```json
{
  "targets": [{"Cidr": "10.0.0.0/29"}],
  "probers": [
    {"type": "snmp", "ports": [161], "version": "v1", "community": "readonly-2026"}
  ]
}
```

Probe a fleet where some agents listen on a non-standard port:

```json
{
  "targets": [{"DnsName": "core-01.lab.local"}],
  "probers": [
    {"type": "snmp", "ports": [161, 1161], "version": "v2c", "community": "public"}
  ]
}
```

## See also

- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [UDP prober](udp.md) — for non-SNMP UDP fingerprinting (NTP, SIP, memcached, STUN).
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
