---
description: The reverse DNS prober — issues a PTR query for each target IP against a configured resolver (or the system resolver) and emits each returned hostname as a ReverseDnsName signal.
---

# Reverse DNS prober

The reverse DNS prober asks a resolver "who is this IP?" and records the hostname it comes back with. This is the opposite direction from the [DNS prober](dns.md), which treats each target as a DNS server and asks it to resolve names. Here the resolver is a peer, not the target — the target is the IP whose hostname you want to look up.

**Use it when** you have an IP address and want the hostname registered for it.<br>
**You get** a `ReverseDnsName` signal for each name a resolver returns for the IP.

A PTR record is the DNS record type that maps an IP back to a name. For each resolved target IP, the prober issues a PTR query against every configured resolver — or against the host's system resolver when none are configured. Each PTR record the resolver returns becomes one `ReverseDnsName` signal. IPv4 targets are looked up under `in-addr.arpa` and IPv6 targets under `ip6.arpa`. The prober builds both arpa-name shapes automatically from the target `IpAddr` and only needs the IP.

## Configuration

Add a `reverse_dns` entry to a scenario's `probers` array. Every field has a default, so the minimum shape is `{"type": "reverse_dns"}`.

```yaml
probers:
  - type: reverse_dns
    resolvers:
      - 1.1.1.1
      - 8.8.8.8
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `"reverse_dns"`. |
| `resolvers` | array of IP address | no | `[]` (system resolver) | Explicit resolver IPs to query. When empty, the host's system resolver configuration (`/etc/resolv.conf` on Unix, the registry on Windows) is used. Each resolver is contacted over UDP on port 53. |

Unlike the DNS prober, `reverse_dns` does not accept a `ports` field — resolvers are always contacted on the standard DNS port (UDP 53). If a scenario needs to probe a resolver on a non-standard port, use the DNS prober with `query_type: ptr` and write the arpa-form name yourself in `query_names`.

## Signals emitted

| Signal | When produced |
|---|---|
| `ReverseDnsName(<hostname>)` | The resolver returned at least one PTR record for the target IP. One signal is emitted per PTR record. The trailing `.` on the returned name is stripped, so `router.example.com.` becomes `router.example.com`. |

Reachability tracks whether the resolver itself responded, not whether it knew the target. The resolver can answer in several ways that carry no name: `NXDOMAIN` (no record for that IP), `REFUSED` (the resolver will not answer), `SERVFAIL` (the resolver tried and failed), or an empty answer section. In every one of these, the prober records `reachable = true` with zero signals — the resolver is up, it just had no name to hand back. When the resolver never replies (outer timeout, network unreachable, UDP port closed), the prober records `reachable = false` with zero signals. Neither case is an error. This matches the classification the [DNS prober](dns.md) uses when treating a target as a DNS server.

A resolver that answers with something the prober cannot read, and a socket or permission failure on the scan host, are probe faults and surface as errors. Those are cases where the lookup broke, so "this IP has no PTR record" would be the wrong conclusion to draw. See [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults).

When more than one resolver is configured, the prober queries them in the listed order and stops at the first successful response. When a single response contains more than one PTR record — common when a load-balanced service publishes several friendly names — every returned name produces its own `ReverseDnsName` signal.

## Resolver selection

**System resolver (default).** When `resolvers` is empty, the prober loads the host's resolver configuration once at startup and reuses it for every probe. On Linux and macOS that means whatever `/etc/resolv.conf` points at, with the host's `search` and `ndots` options respected. Choose this when rastreo runs inside a container that already resolves DNS through cluster DNS or a corporate resolver.

**Custom resolvers.** When `resolvers` is populated, the system configuration is bypassed and the prober queries each listed IP directly over UDP port 53. Choose this when the resolver you want to interrogate is not the one the host would use. Typical cases are a public resolver such as Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`) when you want a known-good baseline for an unknown IP, or a lab resolver you want to test against explicitly.

Resolver-list validation runs at scenario load. An invalid IP is rejected during config parsing. A resolver that fails to initialize (rare — usually a malformed `/etc/resolv.conf`) surfaces as a scenario-config error.

### Distroless / minimal container images

Distroless (`FROM scratch`) and other minimal container images do not ship `/etc/resolv.conf`. Building the system resolver on those images fails at startup with a clear pointer: set the `resolvers` field to a non-empty list of IP addresses so the prober bypasses the system configuration and queries the listed resolvers directly. The default `ghcr.io/davidban77/rastreo` image is `FROM scratch`, so any scenario that uses the reverse DNS prober on that image must set `resolvers` explicitly:

```yaml
probers:
  - type: reverse_dns
    resolvers:
      - 1.1.1.1
      - 8.8.8.8
```

The same failure reaches [`rastreo validate`](../discover/validate.md#reverse_dns-and-minimal-container-images), because the lint builds every prober. A scenario that leaves `resolvers` empty is refused on an image with no `/etc/resolv.conf`, even though nothing is probed.

## Build feature

The reverse DNS prober is always available — no build feature is required. It is present in every build of `rastreo-core`, including builds with `--no-default-features`.

## Example scenario

Query Cloudflare's public resolver for the PTR of `1.1.1.1`:

```json
{
  "targets": [{"Ip": "1.1.1.1"}],
  "probers": [
    {
      "type": "reverse_dns",
      "resolvers": ["1.0.0.1"]
    }
  ]
}
```

A resolver that publishes the Cloudflare PTR returns at least one `ReverseDnsName` signal shaped like this:

```json
{
  "signals": [{"ReverseDnsName": "one.one.one.one"}]
}
```

To rely on the host's system resolver instead, omit `resolvers`:

```yaml
probers:
  - type: reverse_dns
```

This is the typical shape inside a lab container that already has cluster DNS pointing at a resolver that knows the lab's private zones. Every discovered lab IP then gets its friendly hostname attached with no per-scenario configuration.

## See also

- [Reachable, unreachable, and probe faults](index.md#reachable-unreachable-and-probe-faults) — why a silent target is not a probe error.
- [DNS prober](dns.md) — treats the target as a DNS server and issues forward queries against it. Opposite direction from this prober.
- [Identity fuser](../discover/identity.md#signals-used-for-identity-fusion) — a shared `ReverseDnsName` is a correlation signal worth +0.5, matched case-insensitively. It reaches the merge threshold when it agrees with another signal such as MAC, `SnmpSysName`, or `TlsSanName`.
- [Discover CLI](../discover/cli.md#choosing-probers) — `reverse_dns` is in the default probe set. Custom resolvers need `--file`.
- [Scenario schema](../reference/scenario.md) — full `ProberConfig` reference.
- [Troubleshooting](../integrate/troubleshooting.md) — diagnosing probes that don't produce the expected signals.
