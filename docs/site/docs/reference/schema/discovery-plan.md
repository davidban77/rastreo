---
description: Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.
---

# DiscoveryPlan

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/discovery-plan-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/plan.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `classifier` | string | yes | Human-readable summary of the resolved classifier. |
| `fuser` | string | yes | Human-readable summary of the resolved fuser chain, outermost layer first. |
| `max_concurrent` | uint32 | yes | Effective in-flight probe cap for this run. |
| `probe_rate` | uint32 \| null | no | Effective probes-per-second cap; `null` when unlimited. |
| `probers` | array<string> | yes | Human-readable summary of each configured prober. |
| `retries` | uint32 | yes | Effective retransmit attempts for connectionless probers. |
| `scenario` | string | yes | Name of the scenario this plan describes. |
| `sink` | string | yes | Human-readable summary of the configured sink. |
| `targets` | array<[`PlannedTarget`](#plannedtarget)> | yes | Each configured target with the IPs it resolved to, or its resolution error. |
| `timeout_ms` | uint64 | yes | Effective per-probe timeout in milliseconds. |
| `total_probes` | uint | yes | Total probes the scan would run: unique resolved IPs times probers. |

## Definitions

### `PlannedTarget` {#plannedtarget}

| Field | Type | Required | Description |
|---|---|---|---|
| `resolution` | [`TargetResolution`](#targetresolution) | yes | IPs the target resolved to, or the resolution error. |
| `target` | string | yes | The target as written in the scenario. |

### `TargetResolution` {#targetresolution}

One of:

- { `resolved`: array<string (ip)> }
- { `error`: string }

