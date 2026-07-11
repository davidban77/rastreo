---
description: Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.
---

# ScanMetadata

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Per-scan provenance stamped on every emitted `DeviceRecord`. `scan_id` is a ULID; consumers can sort and correlate records by it.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/scan-metadata-v1.json`
- JSON Schema draft: `http://json-schema.org/draft-07/schema#`
- Source of truth: `rastreo-core/src/model/scan.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | — |
| `scan_id` | string | yes | — |
| `scenario_name` | string \| null | no | — |
| `source_config_hash` | string \| null | no | — |
