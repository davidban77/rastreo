---
description: The classifier stage assigns canonical platform and os_version values on each DeviceRecord after fusion and before encoding. Two variants ship — noop and a regex-based rules classifier with a baked-in default table for common network-OS and web-server banners.
---

# Classification

Classification is the pipeline stage that assigns canonical `platform`, `os_version`, and `role` values on each `DeviceRecord`. It runs after fusion (per-IP records plus identity correlation) and before encoding, so the classifier sees the fully merged record — every signal from every prober against every IP that folded into the device.

`platform` is a fielded identifier like `cisco_ios`, `linux`, or `junos`. `os_version` carries a version string paired with the platform, for example `15.7` or `1.24.0`. `role` is a fielded category like `router`, `switch`, or `host`. All three exist so downstream reconcilers (NetBox, Nautobot, Infrahub) receive already-canonicalised values instead of inferring them from raw signals.

Two classifier variants ship: `noop` (pass-through, the default) and `rules` (regex-driven, with a baked-in default table). The `rules` classifier populates `platform` and `os_version`; `role` classification is not implemented yet and stays `null` on every record.

## Available classifiers

| Classifier | Behaviour |
|---|---|
| `noop` | Leaves every `DeviceRecord` unchanged. `platform`, `os_version`, and `role` stay `null`. Selected by default when the scenario does not configure a classifier. |
| `rules` | Matches regex patterns against `SnmpSysDescr`, `SnmpSysName`, `SshBanner`, and `HttpBanner` signals. First match wins and assigns `platform`; when the matched pattern names an `os_version_capture` group, its value populates `os_version`. |

## Pipeline position

```
probe → fuse → classify → encode → sink
```

The classifier is the fourth stage. Each stage has one job:

- **probe** — runs each configured prober and produces raw probe outcomes per target.
- **fuse** — groups outcomes into `DeviceRecord` objects and correlates records that describe the same physical device.
- **classify** — assigns `platform`, `os_version`, and `role` on each merged record.
- **encode** — serialises the record for output.
- **sink** — delivers the encoded record to Kafka, NATS, a file, stdout, or memory.

Because the classifier runs after fusion, it operates on merged records. A device with three interfaces classifies once, not three times.

## Configuration

The classifier is configured under the top-level `classifier` key of a scenario. Omitting the key selects `noop`:

```yaml
classifier:
  type: noop
```

Selecting the `rules` classifier with no additional configuration runs the baked-in defaults on their own:

```yaml
classifier:
  type: rules
```

The `type` field is required. Each variant adds its own configuration fields.

## Rules classifier

The `rules` classifier is opt-in — a scenario must set `classifier.type: rules` to enable it. When enabled, it walks each `DeviceRecord`'s signals and evaluates an ordered list of regex rules against them. The first rule whose regex matches a signal of the requested kind wins: it sets `platform` (and `os_version` when the pattern names a capture group). Later rules are skipped for that record.

Turn on `rules` when you want `platform` populated on records reaching your downstream (NetBox, Nautobot, Infrahub). The baked-in defaults cover common enterprise network gear and popular web servers with no user configuration; add your own rules only for platforms not covered.

Rule patterns are validated when the classifier is built. A pattern that fails to compile is rejected before the scan starts, not silently ignored at match time.

## Baked-in platform rules

The baked-in rules are evaluated in the order shown below. SNMP `sysDescr` rules run first (most specific), followed by SSH banner rules, then HTTP banner rules.

| # | Signal | Pattern | Platform | Version capture |
|---|---|---|---|---|
| 1 | `snmp_sys_descr` | `^Cisco IOS Software.*Version (?P<version>[\d\.]+)` | `cisco_ios` | `version` |
| 2 | `snmp_sys_descr` | `^Cisco IOS XR.*Version (?P<version>[\d\.]+)` | `cisco_ios_xr` | `version` |
| 3 | `snmp_sys_descr` | `^Cisco NX-OS.*Version (?P<version>[\d\.]+)` | `cisco_nxos` | `version` |
| 4 | `snmp_sys_descr` | `^Juniper Networks, Inc\..*JUNOS (?P<version>[\d\.]+)` | `junos` | `version` |
| 5 | `snmp_sys_descr` | `^Arista Networks EOS version (?P<version>[\d\.]+)` | `arista_eos` | `version` (numeric prefix; the `M`/`F` maintenance/feature suffix is not captured) |
| 6 | `snmp_sys_descr` | `^Linux\s+\S+\s+(?P<version>[\d\.]+)-` | `linux` | `version` (kernel release, e.g. `5.15.0`, not the distro name like `Ubuntu 22.04`) |
| 7 | `ssh_banner` | `^SSH-2\.0-OpenSSH_[\d\.p]+\s+Ubuntu` | `linux` | — |
| 8 | `ssh_banner` | `^SSH-2\.0-OpenSSH_[\d\.p]+\s+Debian` | `linux` | — |
| 9 | `ssh_banner` | `^SSH-2\.0-OpenSSH_[\d\.p]+\s+FreeBSD` | `freebsd` | — |
| 10 | `http_banner` | `^nginx/(?P<version>[\d\.]+)` | `nginx` | `version` |
| 11 | `http_banner` | `^Apache/(?P<version>[\d\.]+)` | `apache_httpd` | `version` |

!!! info "What the baked-in table does not cover"
    The default rules target the platforms most common in enterprise network and lab environments. They intentionally leave gaps that would benefit from richer probes than a single banner:

    - No Windows detection — the HTTP prober does not distinguish IIS versions reliably, and no SMB / RPC prober ships today.
    - No container-runtime detection — Docker, containerd, and Kubernetes ingress do not expose stable identifiers in HTTP `Server` headers.
    - No load-balancer, proxy, or CDN detection — HAProxy, Envoy, Traefik, Cloudflare, and similar are not matched.
    - No firewall or SD-WAN detection — Palo Alto, Fortinet, Check Point, and similar require SNMP OID or vendor-specific probes not yet implemented.
    - SNMP `sysName` rules ship no defaults — the `snmp_sys_name` signal kind is supported but only user rules use it today.

    Add your own rules under `platform_rules` to cover any of these — see [Extending the rule set](#extending-the-rule-set).

## Extending the rule set

The `merge_mode` field controls how user-supplied rules combine with the baked-in defaults:

- `extend` (the default) — user rules are checked first, then the baked-in defaults. Use this when the defaults cover your baseline and you want to add narrower or extra rules on top.
- `replace` — only user rules run; the baked-in defaults are ignored. Use this when you want full control over what `platform` is assigned.

Each user rule has four fields: `signal` (which signal kind to match, one of `snmp_sys_descr`, `snmp_sys_name`, `ssh_banner`, `http_banner`), `pattern` (the regex to compile), `platform` (the label to assign on match), and the optional `os_version_capture` (the named capture group whose value populates `os_version`).

Extending: prepending a narrower rule to the baked-in list.

```yaml
classifier:
  type: rules
  merge_mode: extend     # default; may be omitted
  platform_rules:
    - signal: snmp_sys_descr
      pattern: "^Cisco IOS Software.*Version (?P<version>15\\.\\d+)"
      platform: "cisco_ios_15"
      os_version_capture: "version"
```

The user rule and the baked-in rule both match Cisco IOS `sysDescr` strings, but the user rule runs first and only fires on IOS 15.x, so IOS 12.x devices still fall through to the baked-in `cisco_ios` rule.

Replacing: running only user rules.

```yaml
classifier:
  type: rules
  merge_mode: replace
  platform_rules:
    - signal: ssh_banner
      pattern: "^SSH-2\\.0-OpenSSH_.*Ubuntu"
      platform: "linux"
    - signal: http_banner
      pattern: "^HAProxy"
      platform: "haproxy"
```

With `replace`, only the two rules above run. A Cisco IOS device with an `SnmpSysDescr` signal matches nothing and leaves the pipeline with `platform: null`.

## Precedence

- Rules are evaluated in list order. First match wins; later rules are not checked for that record.
- Under `merge_mode: extend`, user rules are checked before the baked-in defaults. Under `merge_mode: replace`, only user rules run.
- A record whose `platform` is already set (for example by an upstream custom pipeline) is left untouched. The classifier never overwrites an existing value.
- Invalid regex patterns are rejected when the classifier is built, before any record is classified. A malformed pattern never runs at match time.
- When the winning pattern names an `os_version_capture` group that does not appear in the actual match, `platform` is set and `os_version` stays `null`.

## See also

- [Identity](identity.md) — how records are merged before classification runs.
- [Scenario reference](../reference/scenario.md#classifier) — the full configuration surface for `classifier.type: rules`.
- [Source of truth reconciliation](../integrate/source-of-truth.md) — how downstream consumers pick up `platform` and `os_version`.
