---
description: rastreo emits records conforming to a versioned JSON Schema. This page describes the schema surface, versioning policy, and evolution rules.
---

# Schema

Every `DeviceRecord` emitted by rastreo carries a `schema_version` field (currently `v1`) and a `schema_id` URL pointing at the canonical JSON Schema. Consumers can validate records against the schema at ingestion time. Per-scan provenance is exposed on each record via a nested `ScanMetadata` object, whose schema is published alongside the record schema at `schemas/scan-metadata-v1.json`.

- Version: **v1**
- Schema ID: `https://schemas.rastreo.dev/device-record/v1.json`
- Source of truth: `rastreo-core/src/model/device.rs::DeviceRecord`
- Generated JSON Schema files ship in `schemas/` in the source repo.

## Versioning policy

- Additive changes (new optional fields, new `#[non_exhaustive]` variants) stay on `v1` and remain backward-compatible.
- Breaking changes (rename or remove a field, change a field's type, tighten a required field) increment to `v2`. A new topic / subject name (`rastreo.discovery.records.v2`) accompanies the version bump; `v1` remains supported for one release cycle.

## Fields

<!-- TODO(PR C): field table generated from schemars derives; see xtask/generate_schemas.rs -->
Field-by-field documentation will be generated from the schema derives in a follow-up PR.
