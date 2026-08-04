---
description: Per-scan provenance stamped on every emitted record. `scan_id` is a ULID, identical on every record in a scan, so consumers correlate a scan's records by it; across scans it orders only to the millisecond its timestamp encodes.
---

# ScanMetadata

<!-- GENERATED FILE — do not edit by hand. Regenerate with `task schema:render`. -->

Per-scan provenance stamped on every emitted record. `scan_id` is a ULID, identical on every record in a scan, so consumers correlate a scan's records by it; across scans it orders only to the millisecond its timestamp encodes.

- Schema ID: `https://davidban77.github.io/rastreo/schemas/scan-metadata-v1.json`
- JSON Schema draft: `https://json-schema.org/draft/2020-12/schema`
- Source of truth: `rastreo-core/src/model/scan.rs`

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `initiated_at` | string (date-time) | yes | RFC 3339 UTC timestamp of when the scan started. |
| `scan_id` | string | yes | ULID identifying this scan. |
| `scenario_name` | string \| null | no | Name of the scenario that produced this scan; absent (null) for an unnamed scenario. |
| `source_config_hash` | string \| null | no | `sha256:…` digest of the canonicalized scenario config that produced this scan. |
