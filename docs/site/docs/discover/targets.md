---
description: Target syntax for rastreo discover — single IP, CIDR block, IP range, or DNS name, with detection rules and worked examples.
---

# Targets

The `--target` flag accepts four forms: a single IP address, a CIDR block, an IP range, or a DNS name. rastreo detects which form you mean from the shape of the string you pass — no separate flag per form.

## Single IP

A single IPv4 or IPv6 address is parsed directly. Probes are dispatched against that one address.

```bash
rastreo discover --target 10.0.0.1 --port 22
rastreo discover --target 2001:db8::1 --port 22
```

## CIDR

A string containing `/` is parsed as a CIDR block. Both IPv4 and IPv6 prefixes are accepted. The target resolver expands the block into individual host addresses before probing.

```bash
rastreo discover --target 10.0.0.0/24 --port 80
rastreo discover --target 2001:db8::/120 --port 80
```

A `/24` block expands to 254 usable host addresses; a `/29` expands to 6. The resolver skips the network and broadcast addresses, except on `/31` point-to-point links (RFC 3021) where both addresses are used and `/32` which expands to the single host. IPv6 prefixes do not have a broadcast carve-out — a `/120` block expands to 256 addresses.

## Range

A string of the form `<ip>-<ip>` (whitespace around the `-` is tolerated) is parsed as an inclusive IP range. Both sides must parse as IP addresses; otherwise the string falls through to DNS-name detection.

```bash
rastreo discover --target 10.0.0.1-10.0.0.5 --port 22
rastreo discover --target "10.0.0.1 - 10.0.0.5" --port 22
```

## DNS name

Anything that is not an IP, a CIDR, or an IP range is treated as a DNS name. rastreo resolves it through the system resolver and probes the resulting address.

```bash
rastreo discover --target router-1.lab.local --port 22
```

When a name resolves to more than one A or AAAA record, every address is probed. Duplicate addresses across multiple `--target` values are deduplicated by IP before scheduling.

## Mixing forms

`--target` is repeatable, and the four forms can be mixed freely. Each target is resolved independently before scheduling.

```bash
rastreo discover \
  --target 10.0.0.1 \
  --target 192.0.2.0/29 \
  --target router-1.lab \
  --port 22,80,443
```

## Detection rules

| Form | Example | Detection rule |
|---|---|---|
| Single IP | `10.0.0.1`, `2001:db8::1` | Parses as an IP address. |
| CIDR | `10.0.0.0/24`, `2001:db8::/120` | Contains `/`. |
| Range | `10.0.0.1-10.0.0.5` | Contains `-` AND both sides parse as IP addresses. |
| DNS name | `router-1.lab.local` | Anything else. |

The rules are evaluated in this order, so a CIDR is matched before a range, and a range is matched before a DNS name. A hyphenated hostname such as `router-1.lab` is treated as DNS rather than range, because the substring before the first `-` (`router`) is not an IP.

## Edge cases

- **Hyphenated hostnames** stay DNS names. The range rule only fires when both halves of the `-` are IPs.
- **Leading and trailing whitespace** around the value is trimmed before detection.
- **Empty strings** are rejected with an `invalid --target` error.
- **Malformed CIDR**, for example `10.0.0.0/99`, fails with a CIDR-specific error message before any probe runs.

## See also

- [CLI](cli.md) — the full flag reference for `rastreo discover`.
- [Sinks](sinks.md) — where the resulting records go.
