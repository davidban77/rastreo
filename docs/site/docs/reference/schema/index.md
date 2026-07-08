---
description: rastreo emits records conforming to a versioned JSON Schema. This page describes the schema surface, versioning policy, and how consumers discover and evolve with it.
---

# Schema

Every `DeviceRecord` emitted by rastreo carries a `schema_version` field (currently `v1`) and a `schema_id` URL pointing at the canonical JSON Schema for the record shape. Per-scan provenance is exposed on each record via a nested `ScanMetadata` object, whose schema is published alongside the record schema at `schemas/scan-metadata-v1.json`. The streaming surface — how those records flow over Kafka or NATS — is described in an AsyncAPI document at `schemas/asyncapi.yaml`.

- Version: **v1**
- Schema ID: `https://schemas.rastreo.dev/device-record/v1.json`
- Source of truth: `rastreo-core/src/model/device.rs::DeviceRecord`
- Generated JSON Schema files ship in `schemas/` in the source repo. Field-by-field reference pages are generated from those files and live under this section.

## Pages in this section

- [DeviceRecord](device-record.md) — every field on the emitted record. Generated from the schemars derives.
- [ScanMetadata](scan-metadata.md) — the per-scan provenance object. Generated.
- [ScenarioFile](scenario-config.md) — the YAML input schema for `rastreo run --scenario`. Generated. Point an IDE YAML plugin at `schemas/scenario-v1.json` for autocomplete and validation. The schema describes the full release-image feature set; a binary built with a feature subset will reject scenarios that use disabled probers, sinks, or fusers even though they validate against the schema.
- [Streaming API](streaming-api.md) — Kafka topic / NATS subject conventions, correlation IDs, the AsyncAPI spec.

## Versioning policy

Additive changes stay on `v1` and remain backward-compatible. That includes new optional fields on `DeviceRecord`, new `#[non_exhaustive]` `Signal` variants, and new optional fields on `ScanMetadata`. Consumers that ignore unknown fields (the default for most JSON deserialisers) keep working across an additive bump.

Breaking changes (renaming or removing a field, changing a field's type, tightening a previously-optional field to required) increment to `v2`. The bump ships alongside a new topic / subject name (`rastreo.discovery.records.v2`) so that `v1` and `v2` can run in parallel for one release cycle. Existing consumers migrate on their own schedule.

## Consumer discovery pattern

rastreo does not require a central schema registry. Each emitted record carries a `schema_id` URL. A consumer that wants to validate incoming records at ingest time reads `schema_id` from the first record it sees, fetches the JSON Schema at that URL once, and caches it. Because `schema_id` is a versioned URL, cache invalidation is trivial: when a record shows up with a `schema_id` the consumer has not seen before, refetch. The URL space is stable across releases within a major version.

For consumers running against a lab or air-gapped environment, the schema files ship in the source repo under `schemas/` — treat those as the offline copy and skip the fetch entirely.

## Confluent Schema Registry (future, opt-in)

The `schema_id` URL is the discovery mechanism today; a future release may add opt-in publication of the same JSON Schema to a Confluent-compatible Schema Registry. That path is additive — records still carry `schema_id`, and consumers that already validate via the URL keep working unchanged. No timeline yet; track the roadmap.

## Source layout

```
schemas/
├── asyncapi.yaml            # AsyncAPI 3.0 description of the streaming surface
├── device-record-v1.json    # JSON Schema for DeviceRecord
├── scan-metadata-v1.json    # JSON Schema for ScanMetadata
└── scenario-v1.json         # JSON Schema for ScenarioFile (YAML scenario input)
```

Regenerate everything (JSON Schemas + this doc section) locally with `task schema:all`. The CI drift-check job re-runs the same command and fails if the committed files diverge from what the Rust type derives produce.
