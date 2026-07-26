---
description: The SSH prober — opens a TCP connection to each configured port, captures the server's pre-negotiation SSH banner, then completes the SSH KEX to record the server's host public key.
---

# SSH prober

The SSH prober captures two observable facts from every SSH server it can reach. The first is the pre-negotiation identification banner, for example `SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3`. The second is the server's host public key in OpenSSH single-line format, for example `ssh-ed25519 AAAAC3Nz…`. The banner tells you which SSH implementation and version answers on that port. The host key is a stable per-device identifier. The [identity fuser](../discover/identity.md#signals-used-for-identity-fusion) consumes it as a high-weight correlation signal: two IPs that present the same host key auto-merge into a single record. The prober never attempts authentication. It disconnects immediately after the key exchange completes.

**Use it when** you want to fingerprint an SSH server, or tie together several IPs that turn out to be the same box.<br>
**You get** the server's banner (software and version) and its host key, a stable per-device identifier. No login is attempted.

!!! note "Offers legacy SSH crypto — by design"
    The prober also offers legacy key-exchange, cipher, and MAC algorithms. This lets it capture host keys from legacy gear — older Cisco IOS, NX-OS, and JunOS that support only old SSH crypto. It offers them after the modern ones, so a modern server still negotiates modern crypto. The prober only reads a public host key and never authenticates, so accepting weak crypto to finish the handshake exposes no secret. See [Legacy algorithms](#legacy-algorithms) for the full list and the rationale.

## Configuration

Add an `ssh` entry to a scenario's `probers` array. `ports` has a default, so the minimum shape is `{"type": "ssh"}`.

```yaml
probers:
  - type: ssh
    ports: [22, 2222]
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"ssh"`. |
| `ports` | array of u16 | no | `[22]` | Ports to probe. Sorted and deduplicated at construction. |

## Signals emitted

| Signal | When produced |
|---|---|
| `OpenPort(<port>)` | The prober opened a TCP connection to the port. Enables role heuristics via `ports_open` classifier rules without a paired `tcp_connect` prober. |
| `SshBanner(<value>)` | The server sends its identification banner as the first line on the TCP connection (RFC 4253 §4.2). The prober captures the full line including the `SSH-2.0-` prefix and strips the trailing `\r\n`. |
| `SshHostKey(<value>)` | The server's host public key, captured during the key-exchange step. Emitted as OpenSSH single-line format: `<algorithm> <base64-blob>`, matching the shape used in `~/.ssh/known_hosts` (without the leading host field). |

An example banner: `SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.13`.

An example host key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ`.

The [rules classifier](../discover/classification.md) runs by default, so an `SshBanner` matching a baked-in rule (Ubuntu, Debian, FreeBSD) populates `DeviceRecord.platform` (OS — `linux` or `freebsd`), `DeviceRecord.os_version` (distro token — `Ubuntu`, `Debian`, or `FreeBSD`), and `DeviceRecord.ssh_version` (SSH software identifier — for example `OpenSSH_9.3p1`) as three separate fields on the record.

The banner and host-key steps are independent. A target that answers only one of them is still marked reachable, and only the step that succeeded contributes a signal. A target that refuses the TCP connection, or that times out on both steps, is marked unreachable and contributes no signals. That is a normal discovery result, not an error.

A socket failure on the scan host itself — file-descriptor exhaustion, for example — is a probe fault and surfaces as an error. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The SSH prober is gated behind the `ssh` Cargo feature on `rastreo-core`. The published release binaries ship with `--features ssh` bundled, so no extra step is needed when using the tarball, Docker image, or Helm chart.

Library consumers building from source must opt in:

```bash
cargo build -p rastreo --features ssh
cargo build -p rastreo-server --features ssh
```

Disabling the feature drops the SSH transport and its cryptographic dependencies from the build.

## Authentication

The prober does not authenticate. It runs the SSH transport layer as far as key exchange, captures the server's host key, then disconnects. No username, password, or key material is ever sent. This is enough to fingerprint the server and its identity. It also means the prober can safely target hosts you have no account on.

Authenticated probes are a planned extension. They would let the prober run scripted commands over an SSH session and parse the output. They are not implemented today. A scenario that configures an `ssh` prober will produce banner and host-key signals only.

## Legacy algorithms

Some network gear supports only old SSH crypto. Older Cisco IOS, NX-OS, and JunOS devices often support only legacy key exchange, ciphers, and MACs. Against those devices a modern-only handshake fails, and the host key — a high-weight identity signal — is never captured. To reach them, the prober offers legacy algorithms in addition to the modern defaults.

The prober offers the legacy algorithms after the modern ones. A modern server negotiates modern crypto, and only a legacy-only server uses the older algorithms. The prober offers these legacy algorithms:

| Category | Legacy algorithms offered |
|---|---|
| Key exchange | `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`, `diffie-hellman-group-exchange-sha1` |
| Cipher | `aes256-cbc`, `aes192-cbc`, `aes128-cbc` |
| MAC | `hmac-sha1-etm@openssh.com`, `hmac-sha1` |

The older `3des-cbc` cipher is not offered.

Offering weak crypto here is safe because the prober fingerprints — it does not authenticate. It reads a public host key over a read-only handshake and never sends or accepts a secret. No credential is ever at risk, whatever algorithms the two sides agree on. This matches rastreo's permissive-by-default posture for discovery, the same reasoning behind the TLS prober's [accept-any-certificate handling](tls.md#certificate-handling).

## Example scenario

The following scenario probes an SSH target on port 22. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```json
{
  "targets": [{"Ip": "10.50.0.20"}],
  "probers": [
    {"type": "ssh", "ports": [22]}
  ]
}
```

A record produced against a stock OpenSSH server contains the banner and the host key for the algorithm the two sides negotiate during key exchange (typically `ssh-ed25519` against a modern OpenSSH default):

```json
{
  "signals": [
    {"SshBanner": "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.13"},
    {"SshHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ"}
  ]
}
```

## See also

- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a silent target is not a probe error.
- [Identity fuser](../discover/identity.md#signals-used-for-identity-fusion) — how `SshHostKey` participates as a high-weight correlation signal (0.8, enough to auto-merge alone).
- [TLS prober](tls.md#certificate-handling) — the same fingerprint-not-authenticate posture applied to TLS certificates.
- [Scenario schema](../reference/scenario.md#ssh) — the full `ProberConfig::Ssh` field table.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the SSH prober from the CLI via `--file`.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
- [Probe index](index.md) — pointers to every prober.
