---
description: The classifier stage assigns canonical platform, os_version, ssh_version, http_server, http_version, and role values on each DeviceRecord after fusion and before encoding. Two variants ship — noop and a rules classifier that runs a regex-based platform phase and a signal-driven role phase, each with a baked-in default table.
---

# Classification

Classification is the pipeline stage that assigns canonical `platform`, `os_version`, `ssh_version`, `http_server`, `http_version`, and `role` values on each `DeviceRecord`. It runs after fusion (per-IP records plus identity correlation) and before encoding, so the classifier sees the fully merged record — every signal from every prober against every IP that folded into the device.

`platform` is a fielded identifier for the OS the device runs — `cisco_ios`, `linux`, `freebsd`, `junos`. `os_version` carries the OS version paired with `platform`, for example `15.7` (IOS release) or `Ubuntu` (Linux distro token from an SSH banner). `ssh_version` carries the SSH software identifier from an `SshBanner` — for example `OpenSSH_8.9p1`. `http_server` and `http_version` carry the web-server product and version captured from an `HttpBanner` — for example `nginx` + `1.24.0`. `role` is a fielded category like `router`, `switch`, `web_server`, or `host`.

All six fields exist so downstream reconcilers (NetBox, Nautobot, Infrahub) receive already-canonicalised values instead of inferring them from raw signals. Keeping the web-server product on its own field (`http_server`) preserves `platform` for the OS — nginx runs on Linux, BSD, and Windows, so putting `nginx` in `platform` would be a category error against source-of-truth OS-platform models.

Two classifier variants ship: `noop` (pass-through, the default) and `rules` (regex-driven platform detection plus signal-driven role detection, each with a baked-in default table). The `rules` classifier populates `platform`, `os_version`, `ssh_version`, `http_server`, and `http_version` in its platform phase, then `role` in its role phase.

## Available classifiers

| Classifier | Behaviour |
|---|---|
| `noop` | Leaves every `DeviceRecord` unchanged. `platform`, `os_version`, `ssh_version`, `http_server`, `http_version`, and `role` stay `null`. Selected by default when the scenario does not configure a classifier. |
| `rules` | Runs a platform phase (regex patterns against `SnmpSysDescr`, `SnmpSysName`, `SshBanner`, `HttpBanner`) then a role phase (`SnmpSysObjectId` byte-prefix and `OpenPort` set-membership matching). First match per phase wins. |

## Pipeline position

```
probe → fuse → classify → encode → sink
```

The classifier is the fourth stage. Each stage has one job:

- **probe** — runs each configured prober and produces raw probe outcomes per target.
- **fuse** — groups outcomes into `DeviceRecord` objects and correlates records that describe the same physical device.
- **classify** — assigns `platform`, `os_version`, `ssh_version`, `http_server`, `http_version`, and `role` on each merged record.
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

The `rules` classifier is opt-in — a scenario must set `classifier.type: rules` to enable it. When enabled, it walks each `DeviceRecord`'s signals in two phases. The platform phase evaluates an ordered list of regex rules and, on first match, sets `platform` (and `os_version` when the pattern names a capture group). The role phase then evaluates an ordered list of role rules and, on first match, sets `role`. Each phase preserves prepopulated values on the record.

Turn on `rules` when you want `platform` and `role` populated on records reaching your downstream (NetBox, Nautobot, Infrahub). The baked-in defaults cover common enterprise network gear and popular web servers on the platform side, and port-heuristic `router` / `web_server` / `host` inferences on the role side. Add your own rules for anything the defaults do not cover — in particular, `sys_object_id_prefix` role rules against your own devices' `sysObjectID` values (rastreo ships no baked defaults for OID prefixes; see [Baked-in role rules](#baked-in-role-rules) for why).

Platform rule patterns are validated when the classifier is built. A pattern that fails to compile is rejected before the scan starts, not silently ignored at match time. Role rules are validated similarly — a `ports_open` rule with an empty `ports` list is rejected at construction.

## Baked-in platform rules

The baked-in rules are evaluated in the order shown below. SNMP `sysDescr` rules run first (most specific), followed by SSH banner rules, then HTTP banner rules.

| # | Signal | Pattern | `platform` | `os_version` | `ssh_version` | `http_server` | `http_version` |
|---|---|---|---|---|---|---|---|
| 1 | `snmp_sys_descr` | `^Cisco IOS Software.*Version (?P<version>[\d\.]+)` | `cisco_ios` | `version` | — | — | — |
| 2 | `snmp_sys_descr` | `^Cisco IOS XR.*Version (?P<version>[\d\.]+)` | `cisco_ios_xr` | `version` | — | — | — |
| 3 | `snmp_sys_descr` | `^Cisco NX-OS.*Version (?P<version>[\d\.]+)` | `cisco_nxos` | `version` | — | — | — |
| 4 | `snmp_sys_descr` | `^Juniper Networks, Inc\..*JUNOS (?P<version>[\d\.]+)` | `junos` | `version` | — | — | — |
| 5 | `snmp_sys_descr` | `^Arista Networks EOS version (?P<version>[\d\.]+)` | `arista_eos` | `version` (numeric prefix; the `M`/`F` maintenance/feature suffix is not captured) | — | — | — |
| 6 | `snmp_sys_descr` | `^Linux\s+\S+\s+(?P<version>[\d\.]+)-` | `linux` | `version` (kernel release, e.g. `5.15.0`, not the distro name like `Ubuntu 22.04`) | — | — | — |
| 7 | `ssh_banner` | `^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>Ubuntu)` | `linux` | `osv` → `Ubuntu` | `sshv` → `OpenSSH_9.6p1` | — | — |
| 8 | `ssh_banner` | `^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>Debian)` | `linux` | `osv` → `Debian` | `sshv` → `OpenSSH_9.2p1` | — | — |
| 9 | `ssh_banner` | `^SSH-2\.0-(?P<sshv>OpenSSH_[\d\.p]+)\s+(?P<osv>FreeBSD)` | `freebsd` | `osv` → `FreeBSD` | `sshv` → `OpenSSH_9.5` | — | — |
| 10 | `http_banner` | `^(?P<server>nginx)/(?P<version>[\d\.]+)` | `linux` | — | — | `server` → `nginx` | `version` → `1.24.0` |
| 11 | `http_banner` | `^(?P<server>Apache)/(?P<version>[\d\.]+)` | `linux` | — | — | `server` → `Apache` | `version` → `2.4.58` |

!!! info "Three-dimensional split for SSH and HTTP banners"
    SSH and HTTP banners describe two dimensions: the OS the device runs and the software product answering on the port. The baked-in table honours that split. An SSH banner like `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` sets `platform: linux` (the OS), `os_version: Ubuntu` (the distro token), and `ssh_version: OpenSSH_8.9p1` (the SSH software). An HTTP banner like `nginx/1.24.0` sets `platform: linux` (nginx runs on Linux and BSD with high confidence in enterprise environments), `http_server: nginx` (the web-server product), and `http_version: 1.24.0` (the product version). Downstream reconcilers map these to distinct source-of-truth fields — see [Source of truth reconciliation](../integrate/source-of-truth.md).

!!! info "What the baked-in table does not cover"
    The default rules target the platforms most common in enterprise network and lab environments. They intentionally leave gaps that would benefit from richer probes than a single banner:

    - No Windows detection — the HTTP prober does not distinguish IIS versions reliably, and no SMB / RPC prober ships today.
    - No container-runtime detection — Docker, containerd, and Kubernetes ingress do not expose stable identifiers in HTTP `Server` headers.
    - No load-balancer, proxy, or CDN detection — HAProxy, Envoy, Traefik, Cloudflare, and similar are not matched.
    - No firewall or SD-WAN detection — Palo Alto, Fortinet, Check Point, and similar require SNMP OID or vendor-specific probes not yet implemented.
    - SNMP `sysName` rules ship no defaults — the `snmp_sys_name` signal kind is supported but only user rules use it today.

    Add your own rules under `platform_rules` to cover any of these — see [Extending the rule set](#extending-the-rule-set).

## Baked-in role rules

The role phase runs after the platform phase. The baked-in table ships only `ports_open` rules — each matches when every port in the list is present as an `OpenPort` signal on the record. Rules are evaluated in the order shown below; first match wins.

| # | Match | Role |
|---|---|---|
| 1 | `[22, 179]` (SSH + BGP) | `router` |
| 2 | `[22, 443, 830]` (SSH + HTTPS + NETCONF) | `router` |
| 3 | `[443]` | `web_server` |
| 4 | `[80]` | `web_server` |
| 5 | `[22]` (SSH-only host) | `host` |

!!! info "Why no baked-in SNMP `sysObjectID` rules"
    `sys_object_id_prefix` is a first-class role-rule kind — a user can supply their own list under `role_rules` and it will be evaluated before the baked-in port heuristics. rastreo ships no baked defaults for it because no public vendor MIB tree cleanly maps sub-prefixes to device roles at a level rastreo could ship a defensible default for: the common vendor product subtrees commingle routers, switches, firewalls, and management gear inside the same prefix, so any curated default would misclassify as often as it helps. Users supply their own `sys_object_id_prefix` rules against their fleet's actual OIDs.

    To classify by `sysObjectID` today, add rules that match the exact OID prefixes present on your devices:

    ```yaml
    classifier:
      type: rules
      role_rules:
        - type: sys_object_id_prefix
          prefix: "1.3.6.1.4.1.9.9.109.1"   # verified against your Cisco ASR fleet
          role: "router"
    ```

!!! info "What the baked-in role table does not cover"
    The defaults target the roles that show up cleanly in signals shipped by the current probers. They intentionally leave gaps that would benefit from probes not yet available:

    - No `firewall` heuristic — Palo Alto, Fortinet, and Check Point require SNMP OID or vendor-specific probes not yet implemented.
    - No `load_balancer` heuristic — F5, Citrix ADC, HAProxy, and Envoy do not expose a stable role signature via TCP or HTTP banner probes.
    - No `printer`, `voip_phone`, or `access_point` heuristic — these require SNMP `sysObjectID` mapping tables that are not shipped.
    - No `hypervisor` or `container_host` heuristic.

    Add your own rules under `role_rules` to cover any of these — see [Extending the rule set](#extending-the-rule-set).

## Port heuristic semantics

`ports_open` rules match when **every** port in the `ports` list appears as an `OpenPort` signal on the record. Extra open ports on the device do not cause a mismatch: `ports: [22, 179]` matches a record that also has `OpenPort(443)`, but does not match a record that only has `OpenPort(22)`.

Every prober that opens a TCP connection to a target port emits `Signal::OpenPort(port)` alongside its protocol-specific signals. `tcp_connect`, `http`, `ssh`, and `tls` all satisfy this contract today. A `ports_open` rule matching `[80]` fires against a record produced by any of them.

Because rule evaluation is first-match-wins, ordering matters for role rules with overlapping port sets. A `[22, 179]` rule for `router` must be listed before a `[22]` rule for `host`, otherwise every router with SSH open would classify as `host`. The baked-in table follows this pattern: more specific port sets are listed before less specific ones. User-supplied `sys_object_id_prefix` rules run before either kind when merged via `merge_mode: extend`, because SNMP fingerprints are more specific evidence of role than a port-only heuristic.

## Extending the rule set

The `merge_mode` field controls how user-supplied rules combine with the baked-in defaults. It applies uniformly to both `platform_rules` and `role_rules`:

- `extend` (the default) — user rules are checked first, then the baked-in defaults. Use this when the defaults cover your baseline and you want to add narrower or extra rules on top.
- `replace` — only user rules run; the baked-in defaults are ignored. Use this when you want full control over what `platform` and `role` are assigned.

Each user `PlatformRule` has three required fields — `signal` (which signal kind to match, one of `snmp_sys_descr`, `snmp_sys_name`, `ssh_banner`, `http_banner`), `pattern` (the regex to compile), and `platform` (the OS label to assign on match) — plus four optional named-capture-group fields that populate the paired fields on the record: `os_version_capture` → `os_version`, `ssh_version_capture` → `ssh_version` (meaningful only with `signal: ssh_banner`), `http_server_capture` → `http_server`, and `http_version_capture` → `http_version` (both meaningful only with `signal: http_banner`). Any capture-group field that is absent, or that names a group not present in the actual match, leaves the paired record field `null`.

Each user `RoleRule` is a tagged object. Two variants exist. A `sys_object_id_prefix` rule carries `prefix` (an SNMP `sysObjectID` byte prefix) and `role` (the label to assign on match). A `ports_open` rule carries `ports` (a non-empty list of ports that must all be present) and `role`.

Extending: prepending narrower rules to the baked-in lists.

```yaml
classifier:
  type: rules
  merge_mode: extend     # default; may be omitted
  platform_rules:
    - signal: snmp_sys_descr
      pattern: "^Cisco IOS Software.*Version (?P<version>15\\.\\d+)"
      platform: "cisco_ios_15"
      os_version_capture: "version"
  role_rules:
    - type: sys_object_id_prefix
      prefix: "1.3.6.1.4.1.9.12"
      role: "wireless_controller"
    - type: ports_open
      ports: [22, 8443]
      role: "management_appliance"
```

The user platform rule runs before the baked-in `cisco_ios` rule, so IOS 15.x devices get the more specific `cisco_ios_15` label while IOS 12.x devices fall through to `cisco_ios`. The user role rules run before the baked-in table, so a device matching the wireless-controller OID or the management-appliance port set gets those roles first.

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
  role_rules:
    - type: ports_open
      ports: [22]
      role: "host"
```

With `replace`, only the user rules above run. A Cisco IOS device with an `SnmpSysDescr` signal and a matching `sysObjectID` matches nothing in either phase and leaves the pipeline with `platform: null` and `role: null`.

## Precedence

- Platform rules run before role rules. Both phases evaluate rules in list order; first match per phase wins.
- Under `merge_mode: extend`, user rules are checked before the baked-in defaults for both phases. Under `merge_mode: replace`, only user rules run.
- A record whose `platform` is already set (for example by an upstream custom pipeline) is left untouched by the platform phase — `os_version`, `ssh_version`, `http_server`, and `http_version` are not populated either, because the phase skips the rule loop entirely. A record whose `role` is already set is left untouched by the role phase. The classifier never overwrites existing values.
- Invalid regex patterns and invalid role rules are rejected when the classifier is built, before any record is classified. A `ports_open` rule with an empty `ports` list surfaces as a construction error.
- When the winning platform pattern names any capture-group field (`os_version_capture`, `ssh_version_capture`, `http_server_capture`, `http_version_capture`) that does not appear in the actual match, `platform` is set and the paired field stays `null`.

## See also

- [Identity](identity.md) — how records are merged before classification runs.
- [Scenario reference](../reference/scenario.md#classifier) — the full configuration surface for `classifier.type: rules`.
- [Source of truth reconciliation](../integrate/source-of-truth.md) — how downstream consumers pick up `platform`, `os_version`, `ssh_version`, `http_server`, and `http_version`.
