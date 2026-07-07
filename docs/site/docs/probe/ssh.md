---
description: The SSH prober — opens a TCP connection to each configured port, captures the server's pre-negotiation SSH banner, then completes the SSH KEX to record the server's host public key.
---

# SSH prober

The SSH prober captures two observable facts from every SSH server it can reach. The first is the pre-negotiation identification banner, for example `SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3`. The second is the server's host public key in OpenSSH single-line format, for example `ssh-ed25519 AAAAC3Nz…`. The banner tells you which SSH implementation and version answers on that port. The host key is a stable per-device identifier. The [identity fuser](../discover/identity.md#signals-used-for-identity-fusion) consumes it as a high-weight correlation signal: two IPs that present the same host key auto-merge into a single record. The prober never attempts authentication. It disconnects immediately after the key exchange completes.

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
| `SshBanner(<value>)` | The server sends its identification banner as the first line on the TCP connection (RFC 4253 §4.2). The prober captures the full line including the `SSH-2.0-` prefix and strips the trailing `\r\n`. |
| `SshHostKey(<value>)` | The server's host public key, captured during the key-exchange step. Emitted as OpenSSH single-line format: `<algorithm> <base64-blob>`, matching the shape used in `~/.ssh/known_hosts` (without the leading host field). |

An example banner: `SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.13`.

An example host key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ`.

The banner and host-key steps are independent. A target that answers only one of them is still marked reachable, and only the step that succeeded contributes a signal. A target that refuses the TCP connection, or that times out on both steps, is marked unreachable.

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

- [Identity fuser](../discover/identity.md#signals-used-for-identity-fusion) — how `SshHostKey` participates as a high-weight correlation signal (0.8, enough to auto-merge alone).
- [Scenario schema](../reference/scenario.md#ssh) — the full `ProberConfig::Ssh` field table.
- [Discover CLI](../discover/cli.md#yaml-driven-mode) — running the SSH prober from the CLI via `--file`.
- [Sinks](../discover/sinks.md) — where the resulting records are written.
- [Probe index](index.md) — pointers to every prober.
