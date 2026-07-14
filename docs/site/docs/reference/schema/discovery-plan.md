---
description: Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.
---

# DiscoveryPlan

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/discovery-plan-v1.json`
- JSON Schema draft: `http://json-schema.org/draft-07/schema#`
- Source of truth: `rastreo-core/src/plan.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `max_concurrent` | uint32 | yes | — |
| `probe_rate` | uint32 \| null | no | — |
| `probers` | array<string> | yes | — |
| `retries` | uint32 | yes | — |
| `scenario` | string | yes | — |
| `sink` | string | yes | — |
| `targets` | array<[`PlannedTarget`](#plannedtarget)> | yes | — |
| `timeout_ms` | uint64 | yes | — |
| `total_probes` | uint | yes | — |

## Definitions

### `PlannedTarget` {#plannedtarget}

| Field | Type | Required | Description |
|---|---|---|---|
| `resolution` | [`TargetResolution`](#targetresolution) | yes | — |
| `target` | string | yes | — |

### `TargetResolution` {#targetresolution}

One of:

- { `resolved`: array<string (ip)> }
- { `error`: string }

