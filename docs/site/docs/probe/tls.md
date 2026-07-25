---
description: The TLS prober — opens a TCP connection to each configured port, performs a TLS handshake accepting any server certificate, captures the certificate Subject Common Name and Subject Alternative Names as identity-fingerprint signals, and records the negotiated TLS version, cipher suite, and ALPN protocol.
---

# TLS prober

The TLS prober **fingerprints** a TLS server. It does not authenticate one. It opens a TCP connection to each configured port, completes a TLS handshake that accepts any server certificate, then reads the leaf certificate — the server's own certificate, the one carrying its identity. From that certificate it takes two identity signals: the Subject Common Name (CN), the primary name the certificate claims to be, and the Subject Alternative Names (SANs), the extra names it also claims. It also records how the connection was negotiated: the TLS version, the cipher suite, and the application protocol the server selected. The result is a compact fingerprint of the device answering on that port: the name it claims, plus every alias baked into the certificate, plus how it agreed to speak TLS. No client data is sent, and no trust check is performed.

**Use it when** you want the names a TLS service claims, to help identify the device behind it.<br>
**You get** the certificate's main name and every alternative name it lists, plus how the connection was negotiated. It reads the certificate; it does not check that the certificate is trusted.

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
| `TlsProtocolVersion(<value>)` | The TLS version negotiated for the connection, rendered like `TLSv1.3` or `TLSv1.2`. Captured on every completed handshake, even when the server presents no certificate. |
| `TlsCipherSuite(<value>)` | The negotiated cipher suite, by its IANA name, such as `TLS_AES_128_GCM_SHA256`. Captured on every completed handshake, alongside the version. |
| `TlsAlpn(<value>)` | The application protocol the server selected during the handshake, such as `h2` or `http/1.1`. The prober offers both `h2` and `http/1.1`, so this signal appears only when the server selects one. A server that does not use ALPN omits it, and the version and cipher are still captured. |
| `TlsSubject(<value>)` | The server's leaf certificate has a non-empty Common Name (CN) attribute in its Subject Distinguished Name. `<value>` is the CN string, trimmed of surrounding whitespace. Certificates with no CN (increasingly common in modern PKIs that put the identity in the SAN extension only) produce no `TlsSubject` signal. |
| `TlsSanName(<value>)` | Emitted once per DNS or IP entry in the leaf certificate's Subject Alternative Name (SAN) extension. DNS entries are emitted as-is. IP entries are prefixed with `ip:` so downstream consumers can differentiate `router.example.com` from `10.0.0.1`. Entries appear in the order the certificate lists them. |

An example Subject: `TlsSubject("edge-fw-1.lab.example.com")`.

Example SANs from an appliance whose certificate covers both a hostname and its management IP:

```
TlsSanName("edge-fw-1.lab.example.com")
TlsSanName("edge-fw-1")
TlsSanName("ip:10.50.0.5")
```

Example connection signals from a modern server that negotiated TLS 1.3 and HTTP/2:

```
TlsProtocolVersion("TLSv1.3")
TlsCipherSuite("TLS_AES_128_GCM_SHA256")
TlsAlpn("h2")
```

rastreo negotiates TLS 1.2 and TLS 1.3 only. A server that offers only older versions cannot complete the handshake, so it produces `OpenPort` alone — see [When the handshake fails](#when-the-handshake-fails).

!!! note "Servers that strictly require another protocol"
    The prober offers `h2` and `http/1.1` on every handshake. A server that strictly requires some other application protocol, and speaks neither `h2` nor `http/1.1`, rejects the handshake. The port still shows as reachable through `OpenPort`, but no TLS signals are captured. Servers that ignore ALPN, or that speak HTTP, are unaffected.

A target that refuses the TCP connection on every port, or that times out on every port, is marked unreachable and contributes no signals. A target that completes the handshake always reports its negotiated version and cipher. A certificate with no CN and no SAN is still marked reachable, with `OpenPort` and those connection signals but no `TlsSubject` or `TlsSanName`.

### When the handshake fails

A handshake that fails is never an error. Whatever the reason — the port speaks plain text, the peer sends a fatal alert, the protocol versions do not overlap, no cipher suite is shared — the prober keeps the `OpenPort` signal it already earned and emits a normal record. It adds no other signals: not version, not cipher, not certificate.

That record is the diagnostic. An open port sitting next to absent certificate signals reads as: something is listening here, and rastreo could not fingerprint it. Legacy gear pinned to an old TLS version shows up exactly this way, and it stays in your inventory instead of being dropped.

Scan `[80, 443]` on an ordinary web server and you get zero probe errors: port 80 does not speak TLS, port 443 hands you the certificate.

The prober's only fault is a socket failure on the scan host itself, such as descriptor exhaustion at connect time. That is the one case where it learns nothing at all. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

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

**SNI.** SNI (Server Name Indication) is the hostname a client announces at the start of a TLS handshake, so a server hosting many sites can present the matching certificate. The prober sends the target's IP address as the SNI value, not a hostname. Servers that pick a certificate by SNI hostname (typical of virtual-hosted TLS reverse proxies) fall back to their default certificate on an IP-only SNI. A per-probe SNI override is not yet supported. To probe named vhosts, run one scenario per SNI value and target the IP behind it.

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
    {"OpenPort": 443},
    {"TlsProtocolVersion": "TLSv1.2"},
    {"TlsCipherSuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {"TlsAlpn": "http/1.1"},
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

- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a silent target is not a probe error.
- [HTTP prober](http.md) — also runs over TLS on ports 443 and 8443. Emits the `Server:` header rather than the certificate identity, so the two are complementary — `http` says what software answers, `tls` says what name the certificate carries.
- [SSH prober](ssh.md) — the same "identity fingerprint over an unauthenticated transport" philosophy applied to SSH. `TlsSubject` plays a role analogous to `SshHostKey` in tying together IPs that answer with the same claimed identity.
- [Scenario schema](../reference/scenario.md#tls) — the `tls` prober's field table in the scenario reference.
- [Device record schema](../reference/schema/device-record.md) — every signal variant in the emitted record, including the TLS connection signals.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
- [Probe index](index.md) — pointers to every prober.
