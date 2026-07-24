---
description: rastreo scans a network and tells you what is on it. It finds every device that answers, works out who made each one and what it does, and emits one clean record per device to Kafka, a file, or stdout.
hide:
  - navigation
  - toc
---

<p align="center" markdown>
  ![rastreo](assets/rastreo-banner-light.png#only-light){ width="300" }
  ![rastreo](assets/rastreo-banner-dark.png#only-dark){ width="300" }
</p>

<p align="center" markdown>
  [![crates.io](https://badgen.net/crates/v/rastreo?icon=rust)](https://crates.io/crates/rastreo)
  [![CI](https://img.shields.io/github/actions/workflow/status/davidban77/rastreo/ci.yml?branch=main&color=1e40af)](https://github.com/davidban77/rastreo/actions/workflows/ci.yml)
  [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-f97316)](https://github.com/davidban77/rastreo/blob/main/LICENSE-MIT)
</p>

<h1 class="rastreo-hero__tagline" markdown="span">
Point rastreo at a network. Get back a clean, structured list of every device that answers — and what each one is.
</h1>

rastreo scans a range of addresses and finds every device that answers. For each device, it works out:

- who made it (the vendor),
- what software it runs (the platform), and
- what job it does on the network (the role).

It merges everything it learns into one clean record per device — deduplicated and ready to load into your inventory.

<p align="center" markdown>
[Get started](get-started/index.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/davidban77/rastreo){ .md-button }
</p>

## Install

One line on Linux or macOS. Docker and Cargo work too.

=== "Script"

    ```bash
    curl -fsSL https://raw.githubusercontent.com/davidban77/rastreo/main/install.sh | sh
    ```

=== "Docker"

    ```bash
    docker run --rm --entrypoint /rastreo ghcr.io/davidban77/rastreo:latest discover --target 1.1.1.1 --port 443
    ```

=== "Cargo"

    ```bash
    cargo install --path rastreo
    ```

See [Install](get-started/install.md) for every path, including the Helm chart for Kubernetes.

## Try it

One command, no config file. Point rastreo at a host and a port:

```bash
rastreo discover --target 1.1.1.1 --port 443
```

It prints one record per device it finds, as a single line of JSON on stdout. The scan summary goes to stderr, so stdout stays clean for tools like `jq`.

=== "Output"

    ```json
    {"identity_key":"ip:1.1.1.1","mgmt_ip":"1.1.1.1","mac":null,"manufacturer":null,"platform":null,"os_version":null,"role":null,"confidence":0.2,"last_seen":"2026-07-24T21:24:30.391132Z","signals":[{"OpenPort":443}],"probe_kinds":["TcpConnect"],"schema_version":"v1","schema_id":"https://davidban77.github.io/rastreo/schemas/device-record-v1.json","possible_alias_of":null,"scan_metadata":{"scan_id":"01KYB07Y0HVA3XEM0M15BK0038","scenario_name":null,"initiated_at":"2026-07-24T21:24:30.353748Z","source_config_hash":"sha256:7d980a397706ae764d9e92c5146a747a66d9f6ddde535f4994b37e074c3422a6"}}
    ```

=== "Same record, expanded"

    ```json
    {
      "identity_key": "ip:1.1.1.1",
      "mgmt_ip": "1.1.1.1",
      "mac": null,
      "manufacturer": null,
      "platform": null,
      "os_version": null,
      "role": null,
      "confidence": 0.2,
      "last_seen": "2026-07-24T21:24:30.391132Z",
      "signals": [ { "OpenPort": 443 } ],
      "probe_kinds": [ "TcpConnect" ],
      "schema_version": "v1",
      "schema_id": "https://davidban77.github.io/rastreo/schemas/device-record-v1.json",
      "possible_alias_of": null,
      "scan_metadata": {
        "scan_id": "01KYB07Y0HVA3XEM0M15BK0038",
        "scenario_name": null,
        "initiated_at": "2026-07-24T21:24:30.353748Z",
        "source_config_hash": "sha256:7d980a397706ae764d9e92c5146a747a66d9f6ddde535f4994b37e074c3422a6"
      }
    }
    ```

The summary line on stderr confirms what ran:

```text
discovery complete: targets_resolved=1 probe_attempts=1 probe_errors=0 records_emitted=1 elapsed_ms=39
```

!!! info "Why some fields are empty"
    This scan used a single prober, a plain TCP connect, so it reports only an open port. Add more probers, and rastreo fills in the MAC address, vendor, platform, and role. See [Probe](probe/index.md) and [Enrichment](discover/enrichment.md).

## What you can do with it

<div class="grid cards" markdown>

-   :material-lan:{ .lg .middle } **Sweep a whole subnet**

    ---

    Give rastreo a range like `10.0.0.0/24`. It probes every address in parallel and returns one record per live host.

    [:octicons-arrow-right-24: Targets](discover/targets.md)

-   :material-fingerprint:{ .lg .middle } **Identify every device**

    ---

    Thirteen built-in probers read HTTP banners, SNMP, SSH host keys, TLS certificates, and more, then merge the answers into one record.

    [:octicons-arrow-right-24: Probe](probe/index.md)

-   :material-sync:{ .lg .middle } **Feed your inventory**

    ---

    Emit each record to a Kafka or NATS topic. Downstream consumers sync it into NetBox, Nautobot, or Infrahub on their own schedule.

    [:octicons-arrow-right-24: Integrate](integrate/index.md)

-   :material-package-variant-closed:{ .lg .middle } **Run it anywhere**

    ---

    One static binary, a Docker image, or a Helm chart. Pick whatever fits your setup, with no extra dependencies to install.

    [:octicons-arrow-right-24: Deploy](deploy/index.md)

</div>

## How it works

Every scan runs the same short pipeline. You give it targets, and one record per device comes out the other end.

```text
targets → probe → merge & enrich → classify → emit  (Kafka · file · stdout)
```

In plain words: it resolves your targets, probes each one, merges the answers, classifies the device, then emits the record.

New here? Start with [Get started](get-started/index.md), or read the [Probe reference](probe/index.md) to see every prober and the signals it reads.
