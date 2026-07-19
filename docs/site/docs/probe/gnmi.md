---
description: The gNMI prober — connects to a device's gRPC/gNMI endpoint, issues Capabilities and Get RPCs, and emits the gNMI version, supported YANG models and encodings, and configured state values as fingerprint signals. TLS accepts any certificate; credentials are optional but unlock the real state values.
---

# gNMI prober

gNMI is a network-device management protocol that runs over gRPC. Modern network operating systems expose it — Nokia SR Linux, Arista EOS, Cisco IOS-XR, and Juniper among them. The gNMI prober connects to that endpoint on each configured port and asks the device two questions. First a **Capabilities** call, which returns the gNMI protocol version, the YANG data models the device supports, and the encodings it can speak. Then a **Get** call, which reads the current value at each path you list, such as `/system/state/hostname`. Each answer becomes a typed signal for vendor and identity fingerprinting.

!!! tip "Credentials are what unlock the value"
    Real devices require authentication on gNMI. With valid credentials you get the hostname and any other state paths you request. Without them, most devices reject the read, and the prober learns only that the port speaks gNMI — roughly a port check. Set `username` and `password` for every scan against production gear. See [Authentication](#authentication).

## Configuration

Add a `gnmi` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "gnmi"}` — that probes TCP 57400 over TLS, anonymously, and reads `/system/state/hostname`.

The prober has five fields:

- `ports` — the TCP ports to probe.
- `plaintext` — cleartext gRPC instead of TLS.
- `username` — the gNMI username.
- `password` — the gNMI password.
- `get_paths` — the gNMI paths to read with the Get call.

```yaml
probers:
  - type: gnmi
    ports: [57400]
    plaintext: false
    username: admin
    password: NokiaSrl1!
    get_paths:
      - /system/state/hostname
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"gnmi"`. |
| `ports` | array of u16 | no | `[57400]` | Ports to probe. Sorted and deduplicated at construction. Common gNMI ports are `57400` (SR Linux, IOS-XR), `6030` (Arista EOS), and `9339` (the IANA-assigned port). |
| `plaintext` | bool | no | `false` | When `false`, the prober connects over TLS. When `true`, it connects over cleartext gRPC (no TLS) — use this for lab devices with TLS disabled on the gNMI port. See [Transport and certificate handling](#transport-and-certificate-handling). |
| `username` | string | no | `""` | gNMI username. Empty means an anonymous probe — no credentials are sent. See [Authentication](#authentication). |
| `password` | string | no | `""` | gNMI password. Redacted from logs and from any debug output. Supports the `${VAR}` and `!file /path` secret syntax — see [Secrets](../reference/secrets.md). |
| `get_paths` | array of string | no | `["/system/state/hostname"]` | gNMI paths for the Get call. Each path is a slash-separated location in the device's data tree. An empty list skips the Get call and runs Capabilities only. |

`username` and `password` are checked when the scenario loads. A value with a control character is not a valid gRPC header, so it is rejected before the scan starts rather than failing mid-probe.

## Transport and certificate handling

By default (`plaintext: false`) the prober connects over TLS and **accepts any server certificate**. It does not verify the chain, the expiration date, or the name. This is the same fingerprinting posture as the [TLS prober](tls.md). rastreo probes unknown networks where self-signed and internally-issued certificates are normal. A strict handshake would refuse to reach the very devices that most need fingerprinting.

!!! warning "TLS is not verified"
    The prober fingerprints the gNMI endpoint; it does not authenticate the server. There is no `tls_verify` toggle. Treat the values you read as unverified claims, useful for correlation and inventory, not as proof of the device's identity.

Set `plaintext: true` to connect over cleartext gRPC with no TLS. Use this only for lab devices that expose gNMI without TLS. A `plaintext: true` probe against a TLS-only port fails to connect. A `plaintext: false` probe against a cleartext-only port fails the same way. The two are not interchangeable, so match the setting to the device.

## Authentication

Credentials are optional and travel as gRPC request metadata. When `username` is empty, the probe is anonymous and sends no credentials.

Most production devices require authentication for both Capabilities and Get. An anonymous probe against such a device is still useful. The device answers with a gRPC status, which proves the port speaks gNMI, even though it reads no state values. Provide `username` and `password` to get the hostname and any other paths in `get_paths`.

Keep the password out of the scenario file. Reference an environment variable with `${GNMI_PASSWORD}` or a mounted file with `!file /run/secrets/gnmi-password`. Both are resolved when the scenario loads. See [Secrets](../reference/secrets.md).

## Signals emitted

| Signal | Source | When produced |
|---|---|---|
| `GnmiVersion(<value>)` | Capabilities | The device reported a non-empty gNMI protocol version, such as `0.10.0`. |
| `GnmiSupportedModel(<value>)` | Capabilities | One per YANG model the device supports. Rendered as `name version` (for example `openconfig-interfaces 3.0.0`), or just `name` when the device reports no version. |
| `GnmiSupportedEncoding(<value>)` | Capabilities | One per encoding the device can speak, by its gNMI name, such as `JSON_IETF` or `PROTO`. |
| `GnmiState { path, value }` | Get | One per path/value pair the Get call returned. `path` is the full path, with list keys rendered inline as `/interfaces/interface[name=ethernet-1/1]/state/oper-status`. `value` is the scalar rendered as a string. |

`GnmiState` values are read from scalar types — string, integer, unsigned integer, boolean, double, and JSON. Values are trimmed and capped at 256 bytes. A path whose value is an opaque or binary type produces no signal; the remaining paths are still read.

Example signals from an SR Linux node that answered Capabilities and a hostname Get:

```
GnmiVersion("0.10.0")
GnmiSupportedModel("openconfig-interfaces 3.0.0")
GnmiSupportedModel("srl_nokia-system")
GnmiSupportedEncoding("JSON_IETF")
GnmiState { path: "/system/state/hostname", value: "srlinux-a" }
```

## Reachability

The prober reports one of three results per target, the same model every prober follows — see [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

- **Unreachable.** Every port refused the connection, timed out, or connected but produced no gNMI answer before the deadline. No record is emitted. This is a normal negative discovery result, not a fault.
- **Reachable with signals.** Capabilities or Get returned data. The record carries `reachable: true` and the signals above, with no fault.
- **Reachable with a fault.** The device answered with a gRPC status instead of data. A status is a response, so the device is provably a gNMI endpoint and is kept. This mirrors an [SNMP](snmp.md) agent that answers with a reply rastreo cannot decode. The record carries `reachable: true`, no signals, and a typed fault.

The fault kind depends on the status:

| gRPC status from the device | Fault kind | Meaning |
|---|---|---|
| `Unauthenticated` or `PermissionDenied` | `auth_failed` | The device speaks gNMI but rejected the credentials. You gave none, or the pair was wrong. Add or fix `username` and `password`. |
| Any other status | `other` | The device speaks gNMI but refused the specific call for another reason, such as an unimplemented RPC. |

An `auth_failed` fault is the expected result of an anonymous probe against a production device. It confirms the endpoint is a live gNMI target, then tells you exactly what to fix. The device stays in your inventory rather than being dropped as a silent host.

## Build feature

The gNMI prober is gated behind the `gnmi` Cargo feature on `rastreo-core`. The published release binaries, the Docker image, and the Helm chart all bundle `--features gnmi`, so no extra step is needed when using them. Building from source, opt in with:

```bash
cargo build -p rastreo --features gnmi
cargo build -p rastreo-server --features gnmi
```

The prober needs only TCP reachability to the gNMI port. No special operating-system capability (such as `CAP_NET_RAW`) is required — a scan works from an unprivileged process.

When the feature is disabled the `gnmi` variant of the prober config is not present, so scenarios that reference `type: gnmi` fail to load with an unknown-variant error.

## Example scenario

Probe two SR Linux nodes on the default gNMI port with credentials, reading the hostname. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```yaml
targets:
  - Ip: "198.51.100.11"
  - Ip: "198.51.100.12"
probers:
  - type: gnmi
    ports: [57400]
    username: admin
    password: ${GNMI_PASSWORD}
    get_paths:
      - /system/state/hostname
```

A record produced against an authenticated SR Linux node looks like this:

```json
{
  "signals": [
    {"GnmiVersion": "0.10.0"},
    {"GnmiSupportedModel": "openconfig-interfaces 3.0.0"},
    {"GnmiSupportedEncoding": "JSON_IETF"},
    {"GnmiState": {"path": "/system/state/hostname", "value": "srlinux-a"}}
  ]
}
```

Read several state paths in one scan by listing them all in `get_paths`:

```yaml
probers:
  - type: gnmi
    ports: [57400]
    username: admin
    password: ${GNMI_PASSWORD}
    get_paths:
      - /system/state/hostname
      - /system/state/version
      - /system/state/platform
```

Probe an Arista EOS lab device that exposes gNMI in cleartext on port 6030:

```yaml
probers:
  - type: gnmi
    ports: [6030]
    plaintext: true
    username: admin
    password: ${EOS_PASSWORD}
```

## See also

- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a device that rejects your credentials is kept, not dropped.
- [SNMP prober](snmp.md) — the same "keep the device that answered even when it withheld data" behavior, applied to SNMP, plus the credential-redaction approach.
- [TLS prober](tls.md) — the same accept-any-certificate fingerprinting posture over TLS.
- [Scenario schema](../reference/scenario.md#gnmi) — the `gnmi` prober's field table in the scenario reference.
- [Secrets](../reference/secrets.md) — `${VAR}` and `!file` syntax for the password.
- [Device record schema](../reference/schema/device-record.md) — every signal variant in the emitted record.
- [Probe index](index.md) — pointers to every prober.
