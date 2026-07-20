---
description: rastreo emits records conforming to a versioned JSON Schema. This page describes the schema surface, versioning policy, and how consumers discover and evolve with it.
---

# Schema

Every `DeviceRecord` emitted by rastreo carries a `schema_version` field (currently `v1`) and a `schema_id` URL pointing at the canonical JSON Schema for the record shape. Per-scan provenance is exposed on each record via a nested `ScanMetadata` object, whose schema is published alongside the record schema at `schemas/scan-metadata-v1.json`. The streaming surface — how those records flow over Kafka or NATS — is described in an AsyncAPI document at `schemas/asyncapi.yaml`.

- Version: **v1**
- Schema ID: `https://davidban77.github.io/rastreo/schemas/device-record-v1.json`
- Source of truth: `rastreo-core/src/model/device.rs::DeviceRecord`
- Generated JSON Schema files ship in `schemas/` in the source repo AND at `https://davidban77.github.io/rastreo/schemas/` alongside these docs, so editors and consumers can fetch them directly over HTTPS. Field-by-field reference pages are generated from those files and live under this section.

## Pages in this section

- [DeviceRecord](device-record.md) — every field on the emitted record. Generated from the schemars derives.
- [LinkRecord](link-record.md) — a topology edge between two endpoints, emitted when the [LLDP prober](../../probe/lldp.md) discovers links. Generated. See [Topology](../../discover/topology.md).
- [CollectionProfileRecord](collection-profile-record.md) — how to collect telemetry from a discovered endpoint (transport, encoding, advertised models), emitted per gNMI endpoint that returned capability data. Generated.
- [ScanMetadata](scan-metadata.md) — the per-scan provenance object. Generated.
- [ScenarioFile](scenario-config.md) — the YAML input schema for `rastreo discover --file`. Generated. Point an IDE YAML plugin at `https://davidban77.github.io/rastreo/schemas/scenario-v1.json` for autocomplete and validation; see [Editor setup](#editor-setup) below for the concrete snippets. The schema describes the full release-image feature set; a binary built with a feature subset will reject scenarios that use disabled probers, sinks, or fusers even though they validate against the schema.
- [DiscoveryPlan](discovery-plan.md) — the dry-run preview of a scenario: resolved targets, probers, sink, and total probe count. Returned by `POST /scans?dry_run=true`. Generated.
- [Streaming API](streaming-api.md) — Kafka topic / NATS subject conventions, correlation IDs, the AsyncAPI spec.
- [DlqEnvelope](dlq-envelope.md) — the `x-rastreo-*` header and payload contract on every dead-letter message.

## Editor setup

The scenario schema is served alongside these docs at `https://davidban77.github.io/rastreo/schemas/scenario-v1.json`. Two patterns wire it into an editor.

**Inline `# yaml-language-server` header.** Add one line at the top of a scenario file and every yaml-language-server-based editor (VS Code + YAML extension, Neovim / Helix with `yaml-language-server`, JetBrains YAML plugin) picks up autocomplete and validation with zero further configuration:

```yaml
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    targets:
      - Ip: "10.0.0.1"
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
```

**VS Code `yaml.schemas` mapping.** For teams that prefer not to touch scenario files, associate the schema with a glob in `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "https://davidban77.github.io/rastreo/schemas/scenario-v1.json": [
      "*.rastreo.yaml",
      "*.rastreo.yml"
    ]
  }
}
```

Rename scenario files to end in `.rastreo.yaml` or `.rastreo.yml` and the schema binds automatically — no inline header needed.

Both patterns validate against the same schema. Pick whichever fits the workflow; they can also be combined.

## Versioning policy

Additive changes stay on `v1` and remain backward-compatible. That includes new optional fields on `DeviceRecord`, new `#[non_exhaustive]` `Signal` variants, and new optional fields on `ScanMetadata`. Consumers that ignore unknown fields (the default for most JSON deserialisers) keep working across an additive bump.

Breaking changes (renaming or removing a field, changing a field's type, tightening a previously-optional field to required) increment to `v2`. The bump ships alongside a new topic / subject name (`rastreo.discovery.records.v2`) so that `v1` and `v2` can run in parallel for one release cycle. Existing consumers migrate on their own schedule.

## Consumer discovery pattern

rastreo does not require a central schema registry. Each emitted record carries a `schema_id` URL. A consumer that wants to validate incoming records at ingest time reads `schema_id` from the first record it sees, fetches the JSON Schema at that URL once, and caches it. Because `schema_id` is a versioned URL, cache invalidation is trivial: when a record shows up with a `schema_id` the consumer has not seen before, refetch. The URL space is stable across releases within a major version.

For consumers running against a lab or air-gapped environment, the schema files ship in the source repo under `schemas/` — treat those as the offline copy and skip the fetch entirely.

## JSON Schema dialect

All five published schemas use JSON Schema **draft 2020-12**:

- `device-record-v1.json`
- `scan-metadata-v1.json`
- `scenario-v1.json`
- `discovery-plan-v1.json`
- `dlq-envelope-v1.json`

If you previously validated against the draft-07 versions, the four schemas generated from the Rust types differ in the schema text in four ways:

- The `$schema` URI is now `https://json-schema.org/draft/2020-12/schema`.
- Reusable definitions live under `$defs` instead of `definitions`. Internal references use `#/$defs/X` instead of `#/definitions/X`.
- A field fixed to one string value is expressed as `const` instead of a single-entry `enum`.
- Integer fields carry `minimum` and `maximum` bounds. For example, port fields are bounded to `0` through `65535`, matching a 16-bit unsigned integer.

!!! info "The data contract is unchanged"
    `schema_version` is still `v1` and the filenames still end in `-v1`. No property, type, or required field changed. A record that validated against the draft-07 schema still validates against the 2020-12 schema. Only the dialect the schema is written in changed.

**Consumer action.** Validate with a JSON-Schema-2020-12-capable validator. Python's `jsonschema` library reads the dialect from the `$schema` field and picks the right validator automatically:

```python
from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for

# Explicit dialect:
Draft202012Validator(schema).validate(record)

# Or auto-detect from the schema's $schema field:
validator_cls = validator_for(schema)
validator_cls(schema).validate(record)
```

A validator that only understands draft-07 may not interpret `$defs` and `const` correctly. Use one that understands 2020-12.

!!! note "The hand-authored schema"
    `dlq-envelope-v1.json` is written by hand, not generated from the Rust types. It is also on 2020-12, but its only change from draft-07 was the `$schema` declaration — it has no `$defs`, single-value `const` fields, or bounded integers, so the other three differences above do not apply to it.

## Confluent Schema Registry (future, opt-in)

The `schema_id` URL is the discovery mechanism today; a future release may add opt-in publication of the same JSON Schema to a Confluent-compatible Schema Registry. That path is additive — records still carry `schema_id`, and consumers that already validate via the URL keep working unchanged. No timeline yet; track the roadmap.

## Source layout

```
schemas/
├── asyncapi.yaml            # AsyncAPI 3.0 description of the streaming surface
├── device-record-v1.json    # JSON Schema for DeviceRecord
├── discovery-plan-v1.json   # JSON Schema for DiscoveryPlan
├── scan-metadata-v1.json    # JSON Schema for ScanMetadata
└── scenario-v1.json         # JSON Schema for ScenarioFile (YAML scenario input)
```

Regenerate everything (JSON Schemas + this doc section) locally with `task schema:all`. The CI drift-check job re-runs the same command and fails if the committed files diverge from what the Rust type derives produce.
