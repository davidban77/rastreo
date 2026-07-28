---
description: The TCP-connect prober — opens a TCP connection to each configured port and emits an OpenPort signal for every port that accepts one. The default reachability probe, always available in every build.
---

# TCP-connect prober

The TCP-connect prober asks the simplest question in discovery: does this port accept a TCP connection? It tries to open a connection to each configured port on every target. A port that completes the connection is open; the prober emits an `OpenPort(<port>)` signal for it and moves on. It sends no data and reads no banner. This is the cheapest, fastest way to learn which ports on a device are live.

**Use it when** you want a quick yes/no on whether a device is listening on a port. It is the default first probe on almost every scan.<br>
**You get** an `OpenPort(<port>)` signal for every port that accepts a connection.

A TCP connection is the standard handshake that opens most network services — the web, SSH, databases, and more all start with one. If the handshake completes, something is listening. If it is refused or times out, nothing is (or a firewall is blocking it).

## Configuration

Add a `tcp_connect` entry to a scenario's `probers` array. Both fields are required — there is no default port list.

```yaml
probers:
  - type: tcp_connect
    ports: [22, 80, 443]
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Must be `"tcp_connect"`. |
| `ports` | array of u16 | yes | Ports to probe. Sorted and deduplicated at construction. |

The prober opens one connection per port, bounded by the scenario-level `timeout_ms`. It runs against every resolved target.

## Signals emitted

| Signal | When produced |
|---|---|
| `OpenPort(<port>)` | The TCP connection to the port completed. One signal per open port. |

A port that is closed, refused, or silent is a normal negative result, not an error. A target whose every port is closed or silent is marked unreachable and contributes no signals. That is a normal discovery result. The prober's only fault is a socket failure on the scan host itself, such as file-descriptor exhaustion at connect time. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

## Build feature

The TCP-connect prober is always available — no Cargo feature is required. It uses only `tokio::net::TcpStream`, so it is present in every build of `rastreo-core`, including builds with `--no-default-features`.

## Example scenario

Probe a host for the three most common service ports. Load it via `rastreo discover --file scan.yml` on the CLI, or send the equivalent JSON as the `POST /scans` body to `rastreo-server`:

```json
{
  "targets": [{"Ip": "10.50.0.10"}],
  "probers": [
    {"type": "tcp_connect", "ports": [22, 80, 443]}
  ]
}
```

A record produced against a host with SSH and HTTP open contains one `OpenPort` signal per open port:

```json
{
  "signals": [
    {"OpenPort": 22},
    {"OpenPort": 80}
  ]
}
```

Pair it with a fingerprinting prober in the same scenario to turn "port 80 is open" into "port 80 is nginx":

```yaml
probers:
  - type: tcp_connect
    ports: [22, 80, 443]
  - type: http
    ports: [80, 443]
```

## See also

- [HTTP prober](http.md) — adds the web-server banner on top of the open-port signal.
- [SSH prober](ssh.md) — adds the SSH banner and host key on port 22.
- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a silent port is not a probe error.
- [Discover CLI](../discover/cli.md#ports) — `tcp_connect` is in the default probe set, and `--port` sets the ports it tries.
- [Scenario schema](../reference/scenario.md#tcp_connect) — the `tcp_connect` field table in the scenario reference.
- [Probe index](index.md) — pointers to every prober.
