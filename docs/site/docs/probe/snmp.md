---
description: The SNMP prober — issues an SNMP v1, v2c, or v3 GetRequest for the MIB-II system group and emits sysDescr, sysObjectID, and sysName as typed signals for vendor and identity fingerprinting.
---

# SNMP prober

The SNMP prober speaks Simple Network Management Protocol against configured UDP ports on every resolved target. It issues a single `GetRequest` for three values from the MIB-II system group — the standard set of basic identity fields every SNMP device exposes. The three are `sysDescr`, `sysObjectID`, and `sysName`, and the prober emits each returned value as a typed signal. (Each returned value is a *varbind*: one queried name paired with its answer.) Those three values identify the vendor line, the product family, and the operator-assigned hostname for the vast majority of managed network devices: routers, switches, wireless controllers, UPSes, printers, and SNMP-enabled Linux hosts.

**Use it when** you want a network device's vendor, model, and hostname. Almost every router, switch, and printer already speaks SNMP.<br>
**You get** up to three signals: a free-form description, a model identifier, and the device's configured hostname.

## Configuration

Add an `snmp` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "snmp"}` — that probes UDP 161 with SNMPv2c and community `public`. The **community** is the shared read password that SNMP v1 and v2c use, and `public` is the near-universal factory default. SNMPv3 replaces it with per-user credentials — see [SNMPv3 credentials](#snmpv3-credentials).

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
| `version` | string | no | `v2c` | One of `v1`, `v2c`, `v3`. See [Versions supported](#versions-supported). |
| `community` | string | no | `public` | The shared read password on `v1` and `v2c`; `public` is the common default. Ignored on `v3`. See [Security notes](#security-notes). |
| `credentials` | object | no | `{}` | USM credentials — SNMPv3's per-user username and password. Used on `v3`. Ignored on `v1` and `v2c`. See [SNMPv3 credentials](#snmpv3-credentials). |

The prober issues one `GetRequest` per port. It uses an ephemeral UDP socket per port, encodes the request via BER, sends the datagram, waits for a response until the scenario-level `timeout_ms` expires, decodes the response, and maps each returned varbind to a `Signal`. Datagrams received from a peer that isn't the target address are ignored — the prober keeps waiting until the target answers or the timeout fires.

On `v3`, an engine-ID discovery round trip happens before the authenticated probe. Both round trips share the scenario-level `timeout_ms` budget; the total wall time is bounded regardless of how many messages are exchanged internally.

## Versions supported

| `version` | Wire protocol | Notes |
|---|---|---|
| `v1` | RFC 1157 | Legacy. Widely supported on older enterprise gear (Cisco IOS 12.x, older Juniper releases, most printers). Uses ASN.1 `NULL` as the placeholder value in each varbind of the request. |
| `v2c` | RFC 3416 with the RFC 1901 community-based transport | Modern default. Uses the `Unspecified` varbind value for GetRequest. Encoding is more compact and error handling is richer, but the wire security model is identical to v1 — the community string travels in cleartext. |
| `v3` | RFC 3412 / RFC 3414 with the User-based Security Model (USM) | Full auth + encryption. Auth algorithms: MD5 (RFC 3414), SHA-1 (RFC 3414), SHA-224 / SHA-256 / SHA-384 / SHA-512 (RFC 7860). Privacy algorithms: DES-CBC (RFC 3414), AES-128-CFB (RFC 3826), AES-192-CFB and AES-256-CFB (draft-reeder-snmpv3-usm-3desede-00 key extension). Security levels `noAuthNoPriv`, `authNoPriv`, and `authPriv` are derived from the configured auth/privacy pair. |

## SNMPv3 credentials

`credentials` is only meaningful when `version: v3`. Under `v1` or `v2c` it is silently ignored — the config author can pre-populate `credentials` before switching versions without validation errors.

The `credentials` object has three fields:

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `username` | string | on `v3` | `""` | USM `msgUserName`. Not a secret per RFC 3414 §2.2. Required for `v3` — the constructor errors on an empty username. |
| `auth` | object | no | `{"algorithm": "none"}` | Auth algorithm + password. See below. |
| `privacy` | object | no | `{"algorithm": "none"}` | Privacy algorithm + password. See below. |

`auth` is an internally-tagged object:

```yaml
auth:
  algorithm: sha256   # one of: none | md5 | sha1 | sha224 | sha256 | sha384 | sha512
  password: authpw    # required for every algorithm except none; redacted in Debug output
```

`privacy` follows the same shape:

```yaml
privacy:
  algorithm: aes128   # one of: none | des | aes128 | aes192 | aes256
  password: privpw    # required for every algorithm except none; redacted in Debug output
```

Both `auth.password` and `privacy.password` accept the `${VAR}` env-var interpolation and the `!file /path` YAML tag — see [Secrets](../reference/secrets.md) for the syntax, so scenario files can reference k8s secret mounts or environment values instead of embedding plaintext.

The security level is derived from the `(auth, privacy)` pair per RFC 3411:

| `auth` | `privacy` | Security level | On the wire |
|---|---|---|---|
| `none` | `none` | `noAuthNoPriv` | GetRequest sent unauthenticated and cleartext. |
| any algorithm | `none` | `authNoPriv` | HMAC authentication over the whole SNMP message; scoped PDU cleartext. |
| any algorithm | any algorithm | `authPriv` | HMAC authentication over the whole SNMP message; scoped PDU encrypted with the chosen cipher. |
| `none` | any algorithm | invalid | Rejected at construction with `snmp v3 privacy requires an auth algorithm`. |

??? note "Key derivation and HMAC truncation (crypto internals)"
    Key derivation follows RFC 3414 §2.6 (password-to-key localization) and, for AES-192 / AES-256, the key-extension algorithm from draft-reeder-snmpv3-usm-3desede. HMAC output is truncated per RFC 3414 §6.3.1 and RFC 7860 §4: MD5 and SHA-1 to 12 bytes, SHA-224 to 16, SHA-256 to 24, SHA-384 to 32, SHA-512 to 48.

The `usmStatsNotInTimeWindow` Report PDU triggers exactly one retry with the corrected `msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime` extracted from the report. Persistent time-window errors surface as reachable-but-no-signals. All other Report PDUs (`usmStatsUnknownEngineIDs` outside discovery, `usmStatsUnknownUserNames`, `usmStatsWrongDigests`, `usmStatsDecryptionErrors`) mark the target reachable with no signals — the target is confirmed to speak SNMPv3 even if the credentials are wrong.

## OIDs probed

The prober always queries the same three scalar OIDs from the MIB-II system group. The trailing `.0` on each OID is the scalar instance suffix — SNMP object identifiers name the class; the `.0` names the single instance of that scalar object.

| OID | MIB-II name | Signal | Value shape |
|---|---|---|---|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` | `SnmpSysDescr(<value>)` | Free-form vendor/OS/version string. Trimmed and capped at 256 bytes. |
| `1.3.6.1.2.1.1.2.0` | `sysObjectID` | `SnmpSysObjectId(<dotted>)` | Vendor's product OID from the enterprise arc (e.g. `1.3.6.1.4.1.9.1.516` for a Cisco Catalyst 3750-series switch stack). Dotted-decimal string. |
| `1.3.6.1.2.1.1.5.0` | `sysName` | `SnmpSysName(<value>)` | Operator-assigned hostname (typically the device's configured `hostname`). Trimmed and capped at 256 bytes. |

There is no configuration knob for extra OIDs today. The three baseline values are what a discovery pipeline needs to fingerprint vendor, model family, and identity; deeper polling of interface, inventory, or environmental tables is the reconciler's job, not the probe's.

## Security notes

SNMPv1 and SNMPv2c transmit the community string in cleartext in every message. Anyone who can capture the UDP packet can replay it against the agent. Do not use v1 or v2c against agents that hold sensitive counters or that respond to `SetRequest` over the same community — use SNMPv3 with `authPriv` for those cases.

The default community `public` matches the read-only community configured on the majority of unmanaged SNMP agents. This is a deliberate discovery default — most greenfield scans target unknown or legacy fleets where `public` is what actually works — but it is not appropriate for production monitoring against hardened networks. Set `community` explicitly on scenarios that target managed fleets with rotated community strings.

USM passwords never travel on the wire. They are used only to derive localized keys via the RFC 3414 password-to-key algorithm; only the localized keys are used to authenticate and encrypt messages. HMAC verification of the response is constant-time. Received messages whose HMAC does not match the expected value are dropped and the target is reported as reachable with no signals.

The prober does not log the community string or any USM password at any level. Configuration is logged only by field name, and error messages wrap only the operation and target address, never the credentials. The `community` field and every USM `password` field are redacted from `Debug` output of `SnmpProber`, `ProberConfig::Snmp`, `UsmCredentials`, `UsmAuth`, and `UsmPrivacy` — any accidental `dbg!` / `tracing::debug!` on those types prints `<redacted>` in place of the credential. USM `username` is not treated as secret per RFC 3414 §2.2 and is printed as-is.

Report PDUs with `msgFlags.authFlag == 0` (unauthenticated Reports) are accepted for classification only — enough to conclude the target speaks SNMPv3 and either mark it reachable-with-no-signals or, for `usmStatsNotInTimeWindow`, drive the single retry with the reported `msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime` used verbatim. No secrets are derived from unauthenticated Reports and no varbind data is trusted; the acceptance is bounded to the classification decision.

## Signals emitted

| Signal | When produced |
|---|---|
| `SnmpSysDescr(<value>)` | The response contained an `OCTET STRING` varbind at `1.3.6.1.2.1.1.1.0`. |
| `SnmpSysObjectId(<dotted>)` | The response contained an `OBJECT IDENTIFIER` varbind at `1.3.6.1.2.1.1.2.0`. |
| `SnmpSysName(<value>)` | The response contained an `OCTET STRING` varbind at `1.3.6.1.2.1.1.5.0`. |

A response with a nonzero `error-status` (for example `authorizationError` when the community is wrong on v2c, or `noSuchName` when v1 doesn't recognise the OID) marks the target as reachable but emits no signals. A reachable-but-refusing agent is still a signal in itself for discovery — you know a device is there and running SNMP, even if the community is not what was configured. A varbind whose value is not the ASN.1 type expected for that OID (for example `sysDescr` returned as an `INTEGER`) is silently skipped; the remaining varbinds are still processed.

A target whose agent answers on no configured port — every port times out, is refused, or reports the host as unreachable — is marked unreachable and contributes no signals. That is a normal discovery result, not a fault. A reply the prober cannot decode is different: the agent did answer, so the device is reachable and rastreo keeps it. The record carries no SNMP signals, and the decode failure is still recorded — the scan summary counts it under `decode_failed` and names it in `first_probe_error`. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The SNMP prober is gated behind the `snmp` Cargo feature on `rastreo-core`. Enable it explicitly when building from source:

```bash
cargo build --features snmp
cargo build --release --features snmp,http,kafka
```

The published Docker image and release binaries bundle the `snmp` feature by default. When the feature is disabled the prober module is not compiled and the `snmp` variant of `ProberConfig` is not present — scenarios that reference `type: snmp` will fail to deserialize with an unknown-variant error.

The feature pulls in `rasn`, `rasn-smi`, and `rasn-snmp` — pure-Rust BER/SNMP implementations — plus the RustCrypto stack (`hmac`, `md-5`, `sha1`, `sha2`, `aes`, `cbc`, `cfb-mode`, `des`) for USM authentication and privacy. No C dependency, no OpenSSL, no `net-snmp` binding. Musl builds work out of the box.

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

Probe an agent that only accepts SNMPv3 discovery — no authentication, no encryption. Useful for identifying v3-only devices before credentials are provisioned:

```yaml
targets:
  - Ip: 192.0.2.20
probers:
  - type: snmp
    version: v3
    credentials:
      username: probe
```

Probe an agent configured with `authNoPriv` using SHA-256 as the auth algorithm:

```yaml
targets:
  - Cidr: 192.0.2.0/29
probers:
  - type: snmp
    version: v3
    credentials:
      username: probe
      auth:
        algorithm: sha256
        password: authpassword
```

Probe an agent configured with `authPriv` using SHA-256 for authentication and AES-128 for encryption — the most common production SNMPv3 deployment:

```yaml
targets:
  - DnsName: core-01.lab.local
probers:
  - type: snmp
    version: v3
    credentials:
      username: probe
      auth:
        algorithm: sha256
        password: authpassword
      privacy:
        algorithm: aes128
        password: privpassword
```

## See also

- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the SNMP prober from the CLI via `--file`.
- [UDP prober](udp.md) — for non-SNMP UDP fingerprinting (NTP, SIP, memcached, STUN).
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
