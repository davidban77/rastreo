---
description: The HTTP prober — issues GET requests against configured ports and emits the response Server header as an HttpBanner signal.
---

# HTTP prober

The HTTP prober issues a `GET` request against each configured port on every resolved target and captures the response `Server:` header as an `HttpBanner` signal. It complements the TCP-connect prober by returning a fingerprint (`nginx/1.24.0`, `Apache/2.4.62`, `Caddy`) alongside "port responds to HTTP" reachability information.

## Configuration

Add an `http` entry to a scenario's `probers` array. Every field except `ports` has a default, so the minimum shape is `{"type": "http", "ports": [80]}`.

```yaml
probers:
  - type: http
    ports: [80, 443, 8080, 8443]
    scheme: auto
    path: /
    tls_verify: false
    user_agent: rastreo/0.3.0
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"http"`. |
| `ports` | array of u16 | yes | — | Ports to probe. Must not be empty; sorted and deduplicated at construction. |
| `scheme` | string | no | `auto` | `auto`, `http`, or `https`. See [Scheme resolution](#scheme-resolution). |
| `path` | string | no | `/` | Request path. Must start with `/`. |
| `tls_verify` | bool | no | `false` | When `false`, TLS handshakes accept self-signed and expired certificates — appropriate for probing unknown networks. |
| `user_agent` | string | no | `rastreo/<version>` | Sent as the `User-Agent` request header on every probe. |

## Scheme resolution

When `scheme: auto`, the scheme is chosen per-port using the table below. Setting `scheme: http` or `scheme: https` overrides the table for every port on this prober.

| Port | Scheme (auto) |
|---|---|
| 443 | `https` |
| 8443 | `https` |
| all others | `http` |

## TLS behaviour

`tls_verify: false` (the default) lets the prober complete handshakes against hosts that present self-signed certificates, expired certificates, or names that do not match the certificate's Subject Alternative Names. Enabling verification (`tls_verify: true`) fails the probe when the certificate chain does not verify against the system's webpki root store — appropriate when probing known-good hosts on a trusted network.

The prober disables HTTP redirects (`301`, `302`, `307`, and `308` count as reachable, banner-carrying responses rather than being followed).

## Signals emitted

| Signal | When produced |
|---|---|
| `OpenPort(<port>)` | The TCP connection to the port succeeded. Emitted for a full HTTP response and for a connection that opened but failed at the TLS layer. Enables role heuristics via `ports_open` classifier rules without a paired `tcp_connect` prober. |
| `HttpBanner(<value>)` | Response carries a `Server:` header. The value is trimmed of surrounding whitespace and truncated at 256 bytes on a UTF-8 character boundary. |

A response without a `Server:` header still marks the target as reachable and still emits `OpenPort` for that port; it just does not add an `HttpBanner`.

A target that refuses the TCP connection on every port, or that times out on every port, is marked unreachable and contributes no signals. That is a normal discovery result, not an error.

Probing an `https` scheme against a port that fails at the TLS layer still records the open port. Whether the peer speaks plain HTTP, sends a handshake alert, offers no shared protocol version or cipher, or presents a certificate the probe rejects under `tls_verify: true` — the TCP connection already opened, so the prober keeps the `OpenPort` signal and emits a normal record with no `HttpBanner`. `probe_errors` stays at zero, and the device is recorded.

The prober's only fault is a local socket failure on the scan host, such as descriptor exhaustion or a denied socket at connect time. That is the one case where the connection never opened and the probe learned nothing. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

When the [rules classifier](../discover/classification.md) is enabled, an `HttpBanner` matching a baked-in rule (`nginx/*`, `Apache/*`) populates `DeviceRecord.platform` (OS — `linux`), `DeviceRecord.http_server` (web-server product), and `DeviceRecord.http_version` (product version) as three separate fields on the record.

## Build feature

The HTTP prober is gated behind the `http` Cargo feature on `rastreo-core`. The published release binaries ship with `--features kafka,http`, so no extra step is needed when using the tarball, Docker image, or Helm chart.

Library consumers building from source must opt in:

```bash
cargo build -p rastreo --features http
cargo build -p rastreo-server --features http
```

## Example scenario

The following scenario probes an nginx target on port 80 with the HTTP prober. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```json
{
  "targets": [{"Ip": "10.50.0.10"}],
  "probers": [
    {"type": "http", "ports": [80], "scheme": "http"}
  ]
}
```

A record produced against a default nginx install contains at least one `HttpBanner` signal:

```json
{
  "signals": [{"HttpBanner": "nginx/1.31.1"}]
}
```

## See also

- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the HTTP prober from the CLI via `--file`.
- [Probe index](index.md) — pointers to every prober.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
