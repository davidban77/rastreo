---
description: Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.
---

# DiscoveryPlan

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/discovery-plan-v2.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/plan.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `classifier` | string | yes | Human-readable summary of the resolved classifier. |
| `encoder` | string | yes | Wire format records leave in: `ndjson` or `table`. |
| `fuser` | string | yes | Human-readable summary of the resolved fuser chain, outermost layer first. |
| `max_concurrent` | uint32 | yes | Effective in-flight probe cap for this run. |
| `probe_rate` | uint32 \| null | no | Effective probes-per-second cap; `null` when unlimited. |
| `probers` | array<string> | yes | Human-readable summary of each configured prober. |
| `refusal` | string \| null | no | Error the scan would abort on before its first probe; absent when every target resolved. |
| `retries` | uint32 | yes | Effective retransmit attempts for connectionless probers. |
| `scenario` | string | yes | Name of the scenario this plan describes. |
| `sink` | string | yes | Human-readable summary of where records would go; several destinations, comma-separated, when the run fans out. |
| `targets` | array<[`PlannedTarget`](#plannedtarget)> | yes | Each configured target with what it contributes to the scan, or its resolution error. |
| `timeout_ms` | uint64 | yes | Effective per-probe timeout in milliseconds. |
| `total_probes` | uint | yes | Total probes the scan would run: every address it would probe times probers, `0` when it would abort first. |

## Definitions

### `PlannedTarget` {#plannedtarget}

| Field | Type | Required | Description |
|---|---|---|---|
| `resolution` | [`TargetResolution`](#targetresolution) | yes | What the target contributes to the scan, or the resolution error. |
| `target` | string | yes | The target as written in the scenario. |

### `ResolvedAddresses` {#resolvedaddresses}

What a target contributes to the scan: how many addresses the stream yields for it, and the first few of them.

| Field | Type | Required | Description |
|---|---|---|---|
| `sample` | array<string (ip)> | yes | The first of those addresses, at most six of them — a plan never carries a target's whole address space. |
| `total` | uint | yes | Addresses the scan would probe for this target. |

### `TargetResolution` {#targetresolution}

One of:

- { `resolved`: [`ResolvedAddresses`](#resolvedaddresses) }
- { `error`: string }

