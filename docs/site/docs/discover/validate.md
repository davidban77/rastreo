---
description: Lint a scenario file offline with `rastreo validate` — check the config shape, sink config, and fuser config with no DNS, no probing, and no broker connection.
---

# Validate

`rastreo validate <scenario.yml>` checks a scenario file offline. It parses the file, checks each scenario's sink and fuser config, then flags empty `probers` or empty `targets`. It never resolves DNS, never probes a host, and never connects to a broker. Use it as the pre-flight check before `rastreo discover` opens a real connection.

The main benefit: you can lint a production sink config with **no broker running**. A Kafka sink with TLS and SASL, or a NATS JetStream sink, is checked for shape only — empty topic, empty broker list, a CA certificate that would be silently ignored. The check runs in milliseconds and needs nothing but the file.

## When to use it

- **Before a real scan.** Run `validate` first to catch a typo in the sink block before `discover` tries to connect and hangs or fails halfway.
- **In CI.** Add `rastreo validate` to a pipeline that lints scenario files on every commit. The exit code is `0` when every scenario is valid and `1` when any scenario is invalid — see [Using it in CI](#using-it-in-ci).
- **When editing a secured sink.** A TLS or SASL block is easy to get wrong. `validate` catches the common mistakes offline, so you find them before running against a live broker.

## What it checks

`validate` runs the same file front-end as `discover --file`: it reads the file, checks `version: 1` and `kind: discovery`, expands `${VAR}` secret references, and rejects retired fields. Then, for every scenario, it checks:

- **The sink config shape.** For a Kafka sink: a non-empty broker list, a non-empty topic, a well-formed TLS block, a well-formed SASL block, and a non-empty dead-letter topic when one is set. For a NATS sink: non-empty servers, subject, and stream. The `stdout` and `file` sinks are always valid — they need no network.
- **The fuser configuration.** When a scenario sets a `fuser`, `validate` checks it too. The `direct` fuser has two confidence scores: `confidence_baseline` must be a number from `0.0` to `1.0`, and `confidence_per_signal` must be zero or greater. The `identity` fuser must be the outermost fuser. It cannot be nested inside `oui_enrichment` or another `identity`. Each `vrrp_groups` entry on an `identity` fuser needs a valid MAC address in `virtual_mac`.
- **A non-empty `probers` list.** A scenario with `probers: []` has nothing to run.
- **A non-empty `targets` list.** A scenario with `targets: []` has nothing to probe.

!!! info "Offline means offline"
    `validate` checks the config **shape**, not reachability. It confirms the sink block is well-formed. It does not check that the broker is up, that the topic exists, or that a target answers. Those are runtime facts, and `validate` never opens a network connection. See [What validate does not check](#what-validate-does-not-check).

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

A structurally empty scenario is flagged the same way. `probers: []` gives `no probers configured`; `targets: []` gives `no targets configured`. Both exit `1`.

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

Another is a mis-nested `identity` fuser. The `identity` fuser runs last, so it must wrap the other fusers. This file has the order backwards — `identity` nested inside `oui_enrichment` — and is rejected:

```yaml
    fuser:
      type: oui_enrichment
      inner:
        type: identity
        inner:
          type: direct
```

```text
scenario 'office' (1 of 1): identity fuser must be the outermost fuser; it cannot be nested inside another fuser
Error: 1 of 1 scenario(s) invalid
```

The correct order is `direct` innermost, then `oui_enrichment`, then `identity` outermost. See [Identity](identity.md#composition) for the recommended stack.

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

!!! note "`oui_enrichment` needs the `oui` build feature"
    A `type: oui_enrichment` fuser is only recognized when the binary is built with the `oui` feature — see [Enrichment · Build feature](enrichment.md#build-feature). A default build does not recognize it and rejects the file while parsing.

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

## Using it in CI

`validate` is built for a config-lint step. It exits `0` when every scenario in the file is valid and `1` when any scenario is invalid, so a CI job can check the exit code directly:

```bash
for scenario in scenarios/*.yml; do
  rastreo validate "$scenario" || exit 1
done
```

The per-scenario `ok` lines and the final summary go to stdout and stderr, so the job log shows exactly which scenario failed and why. No broker, resolver, or network access is needed in the CI runner.

## What validate does not check

`validate` checks the config shape, not the running system. It does **not**:

- Connect to the broker, or check that it is reachable.
- Confirm the Kafka topic or NATS stream exists.
- Resolve DNS names in `targets`.
- Probe any host or check that a target answers.
- Verify SASL credentials against the broker.

To resolve targets and print the plan without probing, use [`discover --dry-run`](cli.md#dry-run-mode). To run the real scan, use [`discover`](cli.md).

## Exit codes

`rastreo validate` exits `0` when every scenario is valid and `1` on any failure. A file-level error — a missing file, an unsupported `version`, an unset secret reference — also exits `1` and prints the reason to stderr before any per-scenario check runs.

## See also

- [CLI](cli.md) — `rastreo discover`, including `--dry-run` and YAML-driven mode.
- [Catalog](catalog.md) — `@name` references and the catalog search order.
- [Sinks](sinks.md) — stdout, file, Kafka, and NATS output in depth.
- [Integrate · Kafka](../integrate/kafka.md#tls-and-sasl-authentication) — the TLS and SASL blocks `validate` checks.
- [Integrate · NATS](../integrate/nats.md) — the NATS JetStream sink fields.
- [Scenario schema](../reference/scenario.md) — the full YAML shape of a scenario file.
</content>
</invoke>
