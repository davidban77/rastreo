---
description: Target syntax for rastreo discover — single IP, CIDR block, IP range, or DNS name, with detection rules and worked examples.
---

# Targets

The `--target` flag accepts four forms: a single IP address, a CIDR block, an IP range, or a DNS name. rastreo detects which form you mean from the shape of the string you pass — no separate flag per form.

## Single IP

A single IPv4 or IPv6 address is parsed directly. Probes are dispatched against that one address.

```bash
rastreo discover --target 10.0.0.1
rastreo discover --target 2001:db8::1
```

## CIDR

A string containing `/` is parsed as a CIDR block. Both IPv4 and IPv6 prefixes are accepted. The target resolver expands the block into individual host addresses before probing.

```bash
rastreo discover --target 10.0.0.0/24
rastreo discover --target 2001:db8::/120
```

A `/24` block expands to 254 usable host addresses; a `/29` expands to 6. The resolver skips the network and broadcast addresses, except on `/31` point-to-point links (RFC 3021) where both addresses are used and `/32` which expands to the single host. IPv6 prefixes do not have a broadcast carve-out — a `/120` block expands to 256 addresses.

## Range

A string of the form `<ip>-<ip>` (whitespace around the `-` is tolerated) is parsed as an inclusive IP range. Both sides must parse as IP addresses; otherwise the string falls through to DNS-name detection.

```bash
rastreo discover --target 10.0.0.1-10.0.0.5
rastreo discover --target "10.0.0.1 - 10.0.0.5"
```

## DNS name

Anything that is not an IP, a CIDR, or an IP range is treated as a DNS name. rastreo resolves it through the system resolver and probes the resulting addresses.

```bash
rastreo discover --target router-1.lab.local
```

A name contributes every address it resolves to. `localhost` normally answers with an IPv6 and an IPv4 address, so it contributes two:

```bash
rastreo discover --target localhost --dry-run
```

```text
    targets:
      localhost → ::1, 127.0.0.1
```

**Each address counts once per target.** Within one target, rastreo probes each address once, no matter how many records point at it. A nameserver that returns the same record twice in one answer still contributes one address.

That rule applies to one target at a time. An address that two targets both cover is still probed for each of them — see [Overlapping targets](#overlapping-targets).

**An underscore in a hostname is fine.** `core_sw01.lab` and `dist_rtr02.example.com` are common in device inventories, and rastreo asks the resolver for them exactly as written.

### Names with no addresses

A name the network answers for with no addresses — a stale entry the zone has dropped, or a name that exists with no A or AAAA record — is **skipped**, not fatal. It contributes nothing to the scan, every other target is probed as asked, and the run reports it so you know which host to investigate:

```text
■ discover  completed in 2.1s | hosts: 254 | records: 31 | probes: 508 | faults: 0 | unresolvable: 1 | sink: stdout
```

Add `-v` and the completion detail names them:

```text
  • unresolvable   stale-switch.lab
```

The `--dry-run` plan marks the same target inline, and the JSON plan carries `"resolution": "unresolvable"` for it:

```text
    targets:
      10.0.0.0/24 → 10.0.0.1, 10.0.0.2, 10.0.0.3, ... (254 addresses)
      stale-switch.lab → <unresolvable: no addresses>
```

The rule is about what the network said, not about which lookup failed. **Only an answer means "this name has no addresses" is skippable.** A lookup that timed out, a server that returned SERVFAIL or REFUSED, or a resolver rastreo could not reach at all are facts about the nameserver rather than about the target, and every one of them still refuses the whole scan — otherwise a broken resolver would silently skip every name and report success.

Two things stay fatal for the same reason a stale name does not: an over-cap CIDR or range discards enumerable work you asked for, so it is refused rather than skipped.

### Names rastreo cannot look up

The DNS-name form is the catch-all, so a mistyped target becomes a name too. Some strings are not names any DNS query can carry, and rastreo can tell that before it asks.

An IP address never reaches these rules, whether you write it as an IP target or as a DNS name. Either way it contributes that one address. Every other value has to be a name, and rastreo looks one up when all of these are true:

- Every part between the dots uses only letters, digits, hyphens, and underscores. Accented and non-Latin letters count as letters.
- No part is empty, and no part starts with a hyphen.
- No part is longer than 63 characters, and the whole name is 253 characters or shorter.

A name that breaks any of these is **skipped**, the same way a name with no addresses is. rastreo asks nothing, probes that target zero times, names it in the same unresolvable list, and runs the rest of the scan as asked. The warning on stderr names the target and the reason:

```text
WARN scan:resolve: rastreo_core::resolver: target has no addresses; it will not be probed target=192.168.1.1:80 reason=target name 192.168.1.1:80 is neither a DNS name nor an IP address, so it was never looked up
```

These are the shapes that come up most often:

| Target | What rastreo does |
|---|---|
| `core_sw01.lab` | Looks it up. An underscore is allowed inside a name. |
| `192.168.1.1:80` | Skips it. A colon is not allowed. Pass the address as `--target 192.168.1.1` and the port as `--port 80`. |
| `[::1]` | Skips it. Brackets are not allowed. Pass the address as `--target ::1`. |
| `10.0.0.1..2` | Skips it. The part between the two dots is empty. Write the range as `10.0.0.1-10.0.0.2`. |
| `fe80::1%eth0` | Skips it. A percent sign is not allowed in a name, and rastreo does not accept a zone suffix on an IP target either. |

!!! info "The report does not separate the two kinds of skip"
    `unresolvable_targets` and the `unresolvable:` count on the banner hold both kinds — a name the network answered for with none, and a name rastreo never asked about. Only the `reason=` field on the warning tells them apart.

### When every target is skipped

A scan that skipped every target probed nothing, so it exits `1`. Both kinds of skip count towards it, and the refusal names every target in the list:

```text
⚠ hint: Either the network answered that these names have no addresses, or they are not names a DNS query can carry: a port, brackets, or a zone suffix in a hostname. Check the target list for typos, then the resolver configuration.
Error: every target is unresolvable (stale-switch.lab, gone.lab); there is nothing to probe
```

!!! note "A resumed scan replays the original answer"
    `--resume` never re-resolves a name; it replays the addresses the interrupted run pinned in the checkpoint. A name that was skipped then stays skipped on resume, and a resumed run reports how many targets were skipped, not why.

## Mixing forms

`--target` is repeatable, and the four forms can be mixed freely. Each target is resolved on its own before scheduling. See [Overlapping targets](#overlapping-targets) when two targets cover the same address.

```bash
rastreo discover \
  --target 10.0.0.1 \
  --target 192.0.2.0/29 \
  --target router-1.lab \
  --probe tcp_connect \
  --port 22,80,443
```

## Overlapping targets

rastreo probes each target on its own and does not remove duplicate addresses across targets. An address that appears in two targets is probed once for each of them. When that address responds, each probe produces its own record.

rastreo warns whenever two targets cover at least one shared address, whatever form each target takes. These are the shapes that come up most often:

- A DNS name and an address target that repeats the address the name resolves to, for example `router-1.lab` and `10.0.0.5`. This is common in an inventory export that records some devices by name and others by address.
- Two DNS names that answer with the same address, for example a device and its management alias.
- A CIDR block and a host address inside it, for example `10.0.0.0/24` and `10.0.0.5`.
- Two CIDR blocks or ranges that share addresses, for example `10.0.0.0/24` and `10.0.0.128/25`.

The warning on stderr names the targets that overlap, so you can see which ones to change:

```bash
rastreo discover --target localhost --target 127.0.0.1 --probe tcp_connect --port 9
```

```text
WARN scan:resolve: rastreo_core::resolver: target specs overlap; overlapping addresses will be probed and emitted more than once pairs_named=1 targets=2 more_pairs_overlap=false overlaps=DnsName("localhost") & Ip(127.0.0.1)
```

The message text is the same on every overlap. The fields carry the detail:

| Field | What it holds |
|---|---|
| `overlaps` | The overlapping pairs, each written as two targets joined by `&`. Every target keeps its form: `Ip(10.0.0.5)`, `Cidr(10.0.0.0/24)`, `Range { start: 10.0.0.1, end: 10.0.0.10 }`, `DnsName("router-1.lab")`. |
| `pairs_named` | How many pairs `overlaps` lists. |
| `targets` | How many targets the list held. |
| `more_pairs_overlap` | `true` when more pairs overlap than the warning named. |

One warning names at most 20 pairs. A list with more overlap than that reports `pairs_named=20` and `more_pairs_overlap=true`. Read the named pairs as a sample, not as the whole set. A subnet target listed alongside the individual hosts inside it reaches the cap at 21 hosts.

`--dry-run` reports the same overlaps without probing, so you can catch them before any traffic is sent. `-q` drops the warning along with every other one, since an overlap is not an error. Under `--log-format json` the same fields appear inside the line's `fields` object — see [Logging](../reference/logging.md).

!!! tip "List disjoint targets to avoid duplicate probes"
    Cover each address once across your whole target list. Disjoint targets probe every address once, with no duplicate records.

!!! info "A duplicate record is not a corrupt record"
    Probing a shared address twice is what the target list asked for, not a failure. Both records carry the same [`identity_key`](identity.md), so a consumer that upserts on that key collapses them. What the overlap costs you is the extra probes and the extra records your consumer handles.

## Detection rules

| Form | Example | Detection rule |
|---|---|---|
| Single IP | `10.0.0.1`, `2001:db8::1` | Parses as an IP address. |
| CIDR | `10.0.0.0/24`, `2001:db8::/120` | Contains `/`. |
| Range | `10.0.0.1-10.0.0.5` | Contains `-` AND both sides parse as IP addresses. |
| DNS name | `router-1.lab.local` | Anything else. |

The rules are evaluated in this order, so a CIDR is matched before a range, and a range is matched before a DNS name. A hyphenated hostname such as `router-1.lab` is treated as DNS rather than range, because the substring before the first `-` (`router`) is not an IP.

The DNS-name row is a catch-all, so it also matches anything you mistyped. Detection only decides which form a target is. Whether the name can be looked up at all is a separate question, answered when the scan starts — see [Names rastreo cannot look up](#names-rastreo-cannot-look-up).

## Edge cases

- **Hyphenated hostnames** stay DNS names. The range rule only fires when both halves of the `-` are IPs.
- **Underscored hostnames** such as `core_sw01.lab` are looked up like any other name.
- **Leading and trailing whitespace** around the value is trimmed before detection.
- **Empty strings** are rejected with an `invalid --target` error.
- **Malformed CIDR**, for example `10.0.0.0/99`, fails with a CIDR-specific error message before any probe runs.
- **A `host:port` pair, a zone-suffixed IPv6 address, or a bracketed address** is detected as a DNS name, then skipped because it is not a name rastreo can look up. The scan runs on without it. See [Names rastreo cannot look up](#names-rastreo-cannot-look-up).

## See also

- [CLI](cli.md) — the full flag reference for `rastreo discover`.
- [Sinks](sinks.md) — where the resulting records go.
- [Logging](../reference/logging.md) — how warnings are rendered, and how `-q` and `--log-format json` change them.
