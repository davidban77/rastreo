---
description: The TLS prober — opens a TCP connection to each configured port, performs a TLS handshake accepting any server certificate, and captures the certificate Subject Common Name and Subject Alternative Names as identity-fingerprint signals.
---

# TLS prober

The TLS prober **fingerprints** a TLS server. It does not authenticate one. It opens a TCP connection to each configured port, completes a TLS handshake that accepts any server certificate, then reads the leaf certificate's Subject Common Name and Subject Alternative Names as identity signals. The result is a compact fingerprint of the device answering on that port: the name it claims, plus every alias baked into the certificate. No client data is sent, and no trust check is performed.

!!! warning "Accepts any certificate — by design"
    The prober **does not** verify the certificate chain, the expiration date, or the name match. Self-signed lab appliances, expired firewall management planes, and internally-issued enterprise CAs all produce signals identically. This is intentional: rastreo probes unknown networks where a strict-verification handshake would refuse to reach the very devices that most need fingerprinting. Treat `TlsSubject` and `TlsSanName` as **unverified claims**, useful for correlation, not for authentication. See [Certificate handling](#certificate-handling) for the full rationale.

## Configuration

Add a `tls` entry to a scenario's `probers` array. `ports` has a default, so the minimum shape is `{"type": "tls"}`.

```yaml
probers:
  - type: tls
    ports: [443, 8443]
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"tls"`. |
| `ports` | array of u16 | no | `[443]` | Ports to probe. Sorted and deduplicated at construction. |

## Signals emitted

| Signal | When produced |
|---|---|
| `OpenPort(<port>)` | The prober opened a TCP connection to the port. Emitted even when the subsequent TLS handshake fails — a non-TLS port that answers TCP is still an open port. Enables role heuristics via `ports_open` classifier rules without a paired `tcp_connect` prober. |
| `TlsSubject(<value>)` | The server's leaf certificate has a non-empty Common Name (CN) attribute in its Subject Distinguished Name. `<value>` is the CN string, trimmed of surrounding whitespace. Certificates with no CN (increasingly common in modern PKIs that put the identity in the SAN extension only) produce no `TlsSubject` signal. |
| `TlsSanName(<value>)` | Emitted once per DNS or IP entry in the leaf certificate's Subject Alternative Name (SAN) extension. DNS entries are emitted as-is. IP entries are prefixed with `ip:` so downstream consumers can differentiate `router.example.com` from `10.0.0.1`. Entries appear in the order the certificate lists them. |

An example Subject: `TlsSubject("edge-fw-1.lab.example.com")`.

Example SANs from an appliance whose certificate covers both a hostname and its management IP:

```
TlsSanName("edge-fw-1.lab.example.com")
TlsSanName("edge-fw-1")
TlsSanName("ip:10.50.0.5")
```

A target that refuses the TCP connection, that closes the TCP connection without sending a `ServerHello`, or that times out during the handshake is marked unreachable and contributes no signals. A target that completes the handshake but presents a certificate with neither a CN nor a SAN extension is marked reachable with an empty signal list.

## Certificate handling

The prober completes a TLS handshake but skips every trust check: the chain, the expiration window, the name match, and the signature. This is the same permissive mode `curl --insecure` uses. Every point below explains a specific consequence of that choice.

**Why bypass verification.** The goal of this prober is to reveal what identity a server publishes, not to prove that identity is legitimate. Self-signed lab appliances, expired firewall management planes, internally-issued PKIs the probe host does not trust, and embedded devices whose factory cert covers `localhost` all refuse a strict handshake and produce no signal at all. Reconciliation to source-of-truth systems (NetBox, Nautobot, Infrahub) happens downstream, where the operator already knows which CA is authoritative for which subnet.

**What "identity fingerprint" means here.** A malicious server can forge a certificate that claims to be anything. Downstream consumers must treat `TlsSubject` and `TlsSanName` as **unverified claims** — like an SNMP `sysName` or an HTTP `Server:` header. They are useful for correlation, not for authentication. The prober's job is to surface the claim; the consumer's job is to weigh it against other evidence.

**SAN entry format.** A SAN extension can carry DNS names, IP addresses, email addresses, URIs, and directory names. This prober only emits DNS and IP entries — the two forms that identify a network endpoint. DNS entries are emitted verbatim (`router.example.com`). IP entries are decoded from their raw four-byte (IPv4) or sixteen-byte (IPv6) form and prefixed with `ip:` in the signal:

| SAN entry in the certificate | Signal emitted |
|---|---|
| DNS: `router.example.com` | `TlsSanName("router.example.com")` |
| IP: `10.0.0.1` | `TlsSanName("ip:10.0.0.1")` |
| IP: `2001:db8::1` | `TlsSanName("ip:2001:db8::1")` |

Consumers that need to distinguish "the cert names a host" from "the cert names an IP" can match on the `ip:` prefix.

**SNI.** The handshake sends the target's IP address as the SNI value. Servers that key certificate selection by SNI hostname (typical of virtual-hosted TLS reverse proxies) fall back to their default certificate on an IP-only SNI. A per-probe SNI override is not yet supported. To probe named vhosts, run one scenario per SNI value and target the IP behind it.

**Chain handling.** Only the leaf certificate is parsed. Intermediates and roots the server returns are dropped after the handshake completes. Recording a chain fingerprint or CA subject is a possible future extension; it will add signals, not replace them.

## Build feature

The TLS prober is gated behind the `tls` Cargo feature on `rastreo-core`. The published release binaries, the Docker image, and the Helm chart all bundle `--features tls`, so no extra step is needed when using them. Building from source, opt in with:

```bash
cargo build -p rastreo --features tls
cargo build -p rastreo-server --features tls
```

No system OpenSSL or root-store data is needed — the prober accepts any certificate, so trust anchors do not apply.

## Example scenario

The following scenario probes an appliance on the default HTTPS port and an alternative management port. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```yaml
targets:
  - Ip: "10.50.0.5"
probers:
  - type: tls
    ports: [443, 8443]
```

A record produced against a device presenting a certificate with a CN and two DNS SANs plus one IP SAN looks like this:

```json
{
  "signals": [
    {"TlsSubject": "edge-fw-1.lab.example.com"},
    {"TlsSanName": "edge-fw-1.lab.example.com"},
    {"TlsSanName": "edge-fw-1"},
    {"TlsSanName": "ip:10.50.0.5"}
  ]
}
```

Combine the TLS prober with `tcp_connect` and `http` in the same scenario when you want reachability, HTTP `Server:` fingerprinting, and TLS identity signals from a single scan:

```yaml
probers:
  - type: tcp_connect
    ports: [443, 8443]
  - type: http
    ports: [443, 8443]
    scheme: https
  - type: tls
    ports: [443, 8443]
```

## See also

- [HTTP prober](http.md) — also runs over TLS on ports 443 and 8443. Emits the `Server:` header rather than the certificate identity, so the two are complementary — `http` says what software answers, `tls` says what name the certificate carries.
- [SSH prober](ssh.md) — the same "identity fingerprint over an unauthenticated transport" philosophy applied to SSH. `TlsSubject` plays a role analogous to `SshHostKey` in tying together IPs that answer with the same claimed identity.
- [Scenario schema](../reference/scenario.md#tls) — the `tls` prober's field table in the scenario reference.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
- [Probe index](index.md) — pointers to every prober.
