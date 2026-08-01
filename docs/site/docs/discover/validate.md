---
description: Lint a scenario file offline with `rastreo validate` — check the targets, probers, sink, encoder, fuser, and classifier with no DNS, no probing, and no broker connection.
---

# Validate

`rastreo validate <scenario.yml>` checks a scenario file offline. It applies the same check a real scan applies before it probes. A file that passes here is a file `rastreo discover` accepts. It never resolves DNS, never probes a host, and never connects to a broker. Use it as the pre-flight check before `rastreo discover` opens a real connection.

The main benefit: you can lint a production sink config with **no broker running**. A Kafka sink with TLS and SASL, or a NATS JetStream sink, is checked for shape only — empty topic, empty broker list, a CA certificate that would be silently ignored. The check runs in milliseconds and needs nothing but the file.

## When to use it

- **Before a real scan.** Run `validate` first to catch a typo in the sink block before `discover` tries to connect and hangs or fails halfway.
- **In CI.** Add `rastreo validate` to a pipeline that lints scenario files on every commit. The exit code is `0` when every scenario is valid and `1` when any scenario is invalid — see [Using it in CI](#using-it-in-ci).
- **When editing a secured sink.** A TLS or SASL block is easy to get wrong. `validate` catches the common mistakes offline, so you find them before running against a live broker.

## What it checks

`validate` runs the same file front-end as `discover --file`: it reads the file, checks `version: 1` and `kind: discovery`, expands `${VAR}` secret references, and rejects retired fields. Then, for every scenario, it checks these in order and reports the first failure:

- **A non-empty `targets` list.** A scenario with `targets: []` has nothing to probe. The message reads `scenario.targets must not be empty`.
- **A non-empty `probers` list.** A scenario with `probers: []` has nothing to run. The message reads `scenario.probers must not be empty`.
- **The shape of each target.** A `Range` target is checked from how it is written, before any lookup. A backwards range and a range mixing IPv4 with IPv6 are both rejected. See [Catching a malformed target range](#catching-a-malformed-target-range).
- **The sink config shape.** For a Kafka sink: a non-empty broker list, a non-empty topic, a well-formed TLS block, a well-formed SASL block, and a non-empty dead-letter topic when one is set. For a NATS sink: non-empty servers, subject, and stream. The `stdout` and `file` sinks are always valid — they need no network.
- **The encoder against the sink.** A scenario that sets `encoder: {type: table}` on a Kafka or NATS sink is rejected, because a broker's consumers read one structured record per message. See [Record format](cli.md#record-format).
- **That every prober can be built.** rastreo builds each prober, then discards it. A `tcp_connect` prober with `ports: []` reads `TcpConnectProber requires at least one port`. A `dns` prober with no `query_names` reads `dns prober requires at least one query_name`. See [Catching an unbuildable prober](#catching-an-unbuildable-prober).
- **The fuser configuration.** When a scenario sets a `fuser`, `validate` checks it too. The `direct` fuser has two confidence scores: `confidence_baseline` must be a number from `0.0` to `1.0`, and `confidence_per_signal` must be zero or greater. The `identity` fuser must be the outermost fuser. It cannot be nested inside `mib_enrichment` or another `identity`. Each `vrrp_groups` entry on an `identity` fuser needs a valid MAC address in `virtual_mac`. A `mib_enrichment` fuser that points `data_path` at a lookup table is checked by opening that file — see [The verdict is about the host you run on](#the-verdict-is-about-the-host-you-run-on).
- **That every classifier rule can be built.** A `platform_rules` entry whose `pattern` is not a valid regex is rejected. So is a `role_rules` entry whose `prefix` is not a dotted-decimal OID. See [Catching an invalid classifier rule](#catching-an-invalid-classifier-rule).

!!! info "Offline means offline"
    `validate` checks the config **shape**, not reachability. It confirms the sink block is well-formed. It does not check that the broker is up, that the topic exists, or that a target answers. Those are runtime facts, and `validate` never opens a network connection. It does read some local state, because building a prober or a fuser can require it — see [The verdict is about the host you run on](#the-verdict-is-about-the-host-you-run-on) and [What validate does not check](#what-validate-does-not-check).

## Usage

```text
rastreo validate <SCENARIO.yml>
rastreo validate @name
```

The single argument is the scenario file. It accepts a path, or an `@name` catalog reference that resolves the same way as `discover --file @name` — see [Catalog](catalog.md).

## A valid scenario

A scenario file has a `sink` (where records go), `targets` (what to probe), and `probers` (how to probe). This file writes to `stdout`, sweeps a `/24`, and runs a TCP-connect probe on three ports:

```yaml title="office.yml"
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: office-tcp
    timeout_ms: 500
    sink:
      type: stdout
    targets:
      - Cidr: "10.10.0.0/24"
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
```

Validate it:

```bash
rastreo validate office.yml
```

```text
scenario 'office-tcp' (1 of 1): ok
1 scenario(s) validated: all valid
```

The command exits `0`. Every scenario is valid.

## Reading the output

`validate` prints one line per scenario, then a final summary line:

- A **valid** scenario prints `scenario '<name>' (N of M): ok` to stdout. A scenario with no `name` prints `scenario N of M: ok` instead.
- An **invalid** scenario prints `scenario '<name>' (N of M): <reason>` to stderr.
- The final line reports the total: `N scenario(s) validated: all valid` when every scenario passed, or `Error: N of M scenario(s) invalid` when any failed.

The command checks every scenario in the file, even after one fails. One run tells you about all the problems, not just the first.

## Catching an invalid sink

A common mistake is an empty Kafka `topic`. This file has one valid scenario and one with a blank topic:

```yaml title="two-scenarios.yml"
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: routers
    sink:
      type: stdout
    targets:
      - Cidr: "10.0.0.0/29"
    probers:
      - type: tcp_connect
        ports: [22]
  - signal_type: discover
    name: web-tier
    sink:
      type: kafka
      brokers: ["kafka-1:9092"]
      topic: ""
    targets:
      - Cidr: "10.1.0.0/28"
    probers:
      - type: tcp_connect
        ports: [80, 443]
```

```bash
rastreo validate two-scenarios.yml
```

```text
scenario 'routers' (1 of 2): ok
scenario 'web-tier' (2 of 2): kafka sink: topic is empty
Error: 1 of 2 scenario(s) invalid
```

The command exits `1`. The valid scenario still reports `ok`; only the broken one is flagged.

Another common mistake is a TLS block that would accept any certificate. Setting `verify: false` with a `ca_cert` present is rejected, because the CA certificate would be read only when `verify: true` — a silent misconfiguration:

```yaml
    sink:
      type: kafka
      brokers: ["kafka-1:9092"]
      topic: rastreo.devices
      tls:
        verify: false
        ca_cert: |
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
```

```text
scenario 'secured-web' (1 of 1): kafka sink: tls.ca_cert requires tls.verify: true
Error: 1 of 1 scenario(s) invalid
```

An empty list is flagged the same way. Take the `office.yml` file [above](#a-valid-scenario) and set its `probers` to `[]`:

```text
scenario 'office-tcp' (1 of 1): scenario.probers must not be empty
Error: 1 of 1 scenario(s) invalid
```

A scenario with `targets: []` reads `scenario.targets must not be empty`. Both exit `1`. When both lists are empty, `targets` is the one reported. The checks run in the order listed under [What it checks](#what-it-checks), and you see the first failure.

## Catching an invalid fuser

`validate` checks a scenario's `fuser` block offline. It catches several common mistakes without connecting to anything.

One is a confidence score out of range. A `direct` fuser with `confidence_baseline: 5.0` is rejected, because the value must be between `0.0` and `1.0`:

```yaml
    fuser:
      type: direct
      confidence_baseline: 5.0
```

```text
scenario 'office' (1 of 1): confidence_baseline must be finite and in [0.0, 1.0], got 5
Error: 1 of 1 scenario(s) invalid
```

Another is a mis-nested `identity` fuser. The `identity` fuser runs last, so it must wrap the other fusers. This file has the order backwards — `identity` nested inside `mib_enrichment` — and is rejected:

```yaml
    fuser:
      type: mib_enrichment
      inner:
        type: identity
        inner:
          type: direct
```

```text
scenario 'office' (1 of 1): identity fuser must be the outermost fuser; it cannot be nested inside another fuser
Error: 1 of 1 scenario(s) invalid
```

The correct order is `direct` innermost, then `mib_enrichment`, then `identity` outermost. See [Identity](identity.md#composition) for the recommended stack.

`validate` also checks the `identity` fuser's `vrrp_groups`. Each entry gives a virtual router's IP in `virtual_ip` and its shared MAC in `virtual_mac`. That MAC must be a real address, and this one is not:

```yaml
    fuser:
      type: identity
      identity_hints:
        vrrp_groups:
          - virtual_ip: "10.0.0.1"
            virtual_mac: "not-a-real-mac"
      inner:
        type: direct
```

```text
scenario 'office' (1 of 1): vrrp_groups virtual_mac 'not-a-real-mac' is not a valid MAC address
Error: 1 of 1 scenario(s) invalid
```

See [Identity · User-declared VRRP hints](identity.md#user-declared-vrrp-hints) for the full `vrrp_groups` entry shape.

!!! note "`mib_enrichment` needs the `mib_enrichment` build feature"
    A `type: mib_enrichment` fuser is only recognized when the binary is built with the `mib_enrichment` feature — see [Enrichment · Build feature](enrichment.md#mib-build-feature). A default build does not recognize it and rejects the file while parsing.

## Catching an unbuildable prober

A prober can be well-formed YAML and still be impossible to run. `validate` catches that by building each prober, then discarding it. The check is therefore the same one a real scan makes.

A `tcp_connect` prober with an empty port list has nothing to connect to:

```yaml
    probers:
      - type: tcp_connect
        ports: []
```

```text
scenario 'office' (1 of 1): TcpConnectProber requires at least one port
Error: 1 of 1 scenario(s) invalid
```

A `dns` prober needs at least one name to look up:

```yaml
    probers:
      - type: dns
        ports: [53]
        query_names: []
```

```text
scenario 'office' (1 of 1): dns prober requires at least one query_name
Error: 1 of 1 scenario(s) invalid
```

The ARP and NDP probers name a local network interface. An interface the machine does not have is rejected:

```yaml
    probers:
      - type: arp
        interface: eth42
```

```text
scenario 'office' (1 of 1): network interface 'eth42' not found
Error: 1 of 1 scenario(s) invalid
```

!!! warning "The interface check reads the machine you run on"
    `validate` sends no packets, but building an ARP or NDP prober reads the local interface list. A scenario naming an interface that exists only on your scanner passes there and fails elsewhere. Set the interface per host instead of writing it into the file. Or run the lint on a machine with the same interfaces. This is one case of a wider rule — see [The verdict is about the host you run on](#the-verdict-is-about-the-host-you-run-on).

## Catching an invalid classifier rule

`validate` builds the classifier too, so a rule that cannot compile is caught before a scan starts. A `platform_rules` entry needs a `pattern` that is a valid regex:

```yaml
    classifier:
      type: rules
      platform_rules:
        - signal: ssh_banner
          pattern: "([unclosed"
          platform: broken
```

```text
scenario 'office' (1 of 1): invalid regex `([unclosed`
Error: 1 of 1 scenario(s) invalid
```

A `sys_object_id_prefix` role rule needs a dotted-decimal OID in `prefix`. The message names the rule, the role, and the shape it expected:

```yaml
    classifier:
      type: rules
      role_rules:
        - type: sys_object_id_prefix
          prefix: "not.an.oid"
          role: router
```

```text
scenario 'office' (1 of 1): invalid role rule: sys_object_id_prefix rule for role `router` has prefix `not.an.oid`, which is not a dotted-decimal OID: expected two or more digit arcs joined by `.` with no leading dot, as in `1.3.6.1.4.1.9.1`
Error: 1 of 1 scenario(s) invalid
```

See [Classification · Extending the rule set](classification.md#extending-the-rule-set) for the full rule shapes.

## Catching a malformed target range

A `Range` target is checked from how it is written, before any address is expanded and before any DNS lookup. A range whose `start` is above its `end` is rejected:

```yaml
    targets:
      - Range:
          start: "10.0.0.9"
          end: "10.0.0.1"
```

```text
scenario 'office' (1 of 1): IP range is invalid: start 10.0.0.9 > end 10.0.0.1
Error: 1 of 1 scenario(s) invalid
```

So is a range that mixes IPv4 and IPv6:

```yaml
    targets:
      - Range:
          start: "10.0.0.1"
          end: "2001:db8::1"
```

```text
scenario 'office' (1 of 1): IP range mixes IPv4 and IPv6: start 10.0.0.1 end 2001:db8::1
Error: 1 of 1 scenario(s) invalid
```

A CIDR or range that is merely *too wide* is a different case. That limit belongs to the resolver the run is given, not to the file, so `validate` does not report it. See [Targets](targets.md).

## Validating a secured sink offline

This is the case `validate` is built for. A production Kafka sink uses TLS for the encrypted connection and SASL for the credentials. The `tls` block has `verify` (check the broker certificate) and an optional `ca_cert` (a private CA). The `sasl` block has `mechanism`, `username`, and `password`. Full field definitions are on the [Kafka](../integrate/kafka.md#tls-and-sasl-authentication) page.

`validate` checks this whole block with **no broker running**:

```yaml title="prod.yml"
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: prod-devices
    sink:
      type: kafka
      brokers: ["kafka-1.prod:9093", "kafka-2.prod:9093"]
      topic: rastreo.devices
      tls:
        verify: true
      sasl:
        mechanism: scram_sha_512
        username: rastreo-producer
        password: ${KAFKA_PASSWORD}
      dead_letter:
        topic: rastreo.devices.dlq
    targets:
      - Cidr: "10.0.0.0/24"
    probers:
      - type: tcp_connect
        ports: [22, 443]
```

```bash
KAFKA_PASSWORD=... rastreo validate prod.yml
```

```text
scenario 'prod-devices' (1 of 1): ok
1 scenario(s) validated: all valid
```

The check passes offline, in milliseconds, without a broker. It confirms the broker list, topic, TLS block, SASL block, and dead-letter topic are all well-formed.

!!! warning "Secret references must be set in the environment"
    `validate` expands `${VAR}` secret references while parsing, the same as `discover`. A referenced variable that is not set fails the whole file with `environment variable KAFKA_PASSWORD referenced in scenario is not set`. Export the referenced variables before you validate, even though no broker is contacted. The value itself is never sent anywhere — it is only expanded so the parse can complete.

A NATS JetStream sink is checked the same way. The `nats` sink has `servers`, `subject`, and `stream` — all must be non-empty. See [NATS](../integrate/nats.md) for the field details.

!!! warning "Sink types need the matching build feature"
    A `type: kafka` sink is only recognized when the binary is built with `--features kafka`; a `type: nats` sink needs `--features nats`. Validate the file with the same build you plan to run it with. A default build does not recognize either sink type and rejects the file while parsing.

## Catalog references

`validate` accepts an `@name` catalog reference in place of a path, resolved through the same search order as `discover`:

```bash
rastreo validate @office-network
```

rastreo looks up `office-network.yml` (then `.yaml`) across the catalog directories and validates the file it finds. See [Catalog](catalog.md) for the search order and how to set up the directories.

## The verdict is about the host you run on

`validate` builds every prober, classifier, and fuser the scenario names, then discards them. Building is the check. That makes it exactly the check a real scan makes before it probes.

It also sets the limit of what a passing verdict means. **Building something that reads local state makes the verdict specific to the machine you ran the lint on.** The same file can be valid on your scanner and invalid in CI. The rule holds for anything rastreo builds, including probers and fusers added later. Today it reaches three things:

- An `arp` or `ndp` prober names a local `interface`, so building it reads the machine's network interface list.
- A `reverse_dns` prober can name its own DNS servers in `resolvers:`. When you leave that list out, building the prober loads the system resolver configuration instead — `/etc/resolv.conf` on Linux.
- A `mib_enrichment` fuser can point `data_path` at your own lookup table. Building it opens and reads that file.

None of the three opens a network connection, so `validate` is still offline. Reading a local file is a different thing from reaching the network.

The `mib_enrichment` case is the easiest to see. The fuser below sits over a `direct` fuser in `inner`, and its `data_path` names a table the machine running the lint does not have:

```yaml
    fuser:
      type: mib_enrichment
      data_path: /etc/rastreo/fleet-mib.tsv
      inner:
        type: direct
```

```text
scenario 'office' (1 of 1): MIB data file '/etc/rastreo/fleet-mib.tsv' could not be opened: No such file or directory (os error 2)
Error: 1 of 1 scenario(s) invalid
```

Run the lint on a machine that holds the same table, or install the table where the job runs. A `mib_enrichment` fuser needs the matching build feature before it is recognized at all — see [Catching an invalid fuser](#catching-an-invalid-fuser).

### reverse_dns and minimal container images

The `reverse_dns` case is the one most likely to surprise you, because the prober needs no settings of its own. A scenario that names it and stops there is asking for the system resolver:

```yaml
    probers:
      - type: reverse_dns
```

That validates on any normal machine. It fails on a minimal container image, such as `scratch` or `distroless`. Those images carry no `/etc/resolv.conf` for the prober to load. The message names the cause and the fix:

```text
scenario 'office' (1 of 1): failed to load system resolver: io error: No such file or directory (os error 2). On distroless / minimal container images without /etc/resolv.conf, supply explicit DNS servers via the reverse_dns prober's `resolvers: [1.1.1.1, 8.8.8.8]` config field to bypass the system resolver.
Error: 1 of 1 scenario(s) invalid
```

!!! tip "Name the resolvers to make the scenario portable"
    An explicit `resolvers:` list skips the system configuration entirely, so the scenario lints the same way everywhere:

    ```yaml
        probers:
          - type: reverse_dns
            resolvers: ["1.1.1.1", "8.8.8.8"]
    ```

    The addresses are only read at scan time. `validate` never sends a query to them. See [Reverse DNS](../probe/reverse-dns.md).

## Using it in CI

`validate` is built for a config-lint step. It exits `0` when every scenario in the file is valid and `1` when any scenario is invalid, so a CI job can check the exit code directly:

```bash
for scenario in scenarios/*.yml; do
  rastreo validate "$scenario" || exit 1
done
```

The per-scenario `ok` lines and the final summary go to stdout and stderr, so the job log shows exactly which scenario failed and why. The runner needs no network access and no broker: `validate` opens no connection.

It does need whatever local state the scenario's probers and fusers read when they are built. A CI runner is rarely the same machine as your scanner, so this is where a verdict stops being portable. Read [The verdict is about the host you run on](#the-verdict-is-about-the-host-you-run-on) before you rely on the result.

Two cases come up in a normal pipeline:

- **A minimal runner image breaks `reverse_dns`.** A `scratch` or `distroless` image has no `/etc/resolv.conf`, so a `reverse_dns` prober with no `resolvers:` cannot be built and the lint fails. Give the prober an explicit `resolvers:` list, or run the job on an image that has one.
- **A runner has different network interfaces.** A scenario naming an ARP or NDP `interface` is checked against the runner's own interface list, and that list rarely matches your scanner's.

## How it differs from a dry-run

`validate` judges the file. [`discover --dry-run`](cli.md#dry-run-mode) predicts what a run would do. On a scenario rastreo cannot build, the two agree: both name the same reason and both exit `1`.

They differ in two ways.

**A scenario with `probers: []`.** `validate` calls it invalid, because a scenario that runs nothing is a mistake in the file. A real run skips that scenario with a notice and carries on with the rest of the file. `--dry-run` predicts exactly that. It prints the notice, leaves the scenario out of the plan, and exits `0`.

Here is the notice from a two-scenario file whose second scenario, `placeholder`, has no probers:

```text
• 'placeholder' (2 of 2): no probers configured, skipping
```

**Targets.** `validate` never resolves targets. A name that does not resolve passes, and so does a CIDR that expands past the host limit. `--dry-run` resolves for real and exits `1` when any target fails. See [What validate does not check](#what-validate-does-not-check).

Use `validate` in CI, or before you commit the file. Use `--dry-run` when you want to know what the next run will do.

## What validate does not check

`validate` checks the config shape, not the running system. It does **not**:

- Connect to the broker, or check that it is reachable.
- Confirm the Kafka topic or NATS stream exists.
- Resolve DNS names in `targets`.
- Probe any host or check that a target answers.
- Verify SASL credentials against the broker.
- Reject a CIDR or range that expands to too many hosts. That limit belongs to the resolver a run is given, not to the file.

To resolve targets and print the plan without probing, use [`discover --dry-run`](cli.md#dry-run-mode). To run the real scan, use [`discover`](cli.md).

## Exit codes

`rastreo validate` exits `0` when every scenario is valid and `1` on any failure. A file-level error — a missing file, an unsupported `version`, an unset secret reference — also exits `1` and prints the reason to stderr before any per-scenario check runs.

## See also

- [CLI](cli.md) — `rastreo discover`, including `--dry-run` and YAML-driven mode.
- [Catalog](catalog.md) — `@name` references and the catalog search order.
- [Sinks](sinks.md) — stdout, file, Kafka, and NATS output in depth.
- [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication) — the TLS and SASL blocks `validate` checks.
- [Integrate · NATS](../integrate/nats.md) — the NATS JetStream sink fields.
- [Classification](classification.md#extending-the-rule-set) — the classifier rule shapes `validate` builds.
- [Scenario schema](../reference/scenario.md) — the full YAML shape of a scenario file.
