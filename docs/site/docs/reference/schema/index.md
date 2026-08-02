---
description: rastreo emits records conforming to a versioned JSON Schema. This page describes the schema surface, versioning policy, and how consumers discover and evolve with it.
---

# Schema

Every `DeviceRecord` emitted by rastreo carries a `schema_version` field (currently `v1`) and a `schema_id` URL pointing at the canonical JSON Schema for the record shape. Per-scan provenance is exposed on each record via a nested `ScanMetadata` object, whose schema is published alongside the record schema at `schemas/scan-metadata-v1.json`. The streaming surface — how those records flow over Kafka or NATS — is described in an AsyncAPI document at `schemas/asyncapi.yaml`.

- Version: **v1**
- Schema ID: `https://davidban77.github.io/rastreo/schemas/device-record-v1.json`
- Source of truth: `rastreo-core/src/model/device.rs`
- Generated JSON Schema files ship in `schemas/` in the source repo AND at `https://davidban77.github.io/rastreo/schemas/` alongside these docs, so editors and consumers can fetch them directly over HTTPS. Field-by-field reference pages are generated from those files and live under this section.

## Pages in this section

- [DeviceRecord](device-record.md) — every field on the emitted record. Generated from the published JSON Schema.
- [LinkRecord](link-record.md) — a topology edge between two endpoints, emitted when the [LLDP prober](../../probe/lldp.md) discovers links. Generated. See [Topology](../../discover/topology.md).
- [CollectionProfileRecord](collection-profile-record.md) — how to collect telemetry from a discovered endpoint (transport, encoding, advertised models), emitted per gNMI endpoint that returned capability data. Generated.
- [ScanMetadata](scan-metadata.md) — the per-scan provenance object. Generated.
- [ScenarioFile](scenario-config.md) — the YAML input schema for `rastreo discover --file`. Generated. Point an IDE YAML plugin at `https://davidban77.github.io/rastreo/schemas/scenario-v1.json` for autocomplete and validation; see [Editor setup](#editor-setup) below for the concrete snippets. The schema describes the full release-image feature set; a binary built with a feature subset will reject scenarios that use disabled probers, sinks, or fusers even though they validate against the schema.
- [DiscoveryPlan](discovery-plan.md) — the dry-run preview of a scenario: resolved targets, probers, fuser, classifier, encoder, sink, and total probe count. Returned by `POST /scans?dry_run=true`. Generated. Currently `v2`: a target's `resolution.resolved` is now an object carrying the address `total` and a six-address `sample`, where `v1` carried a bare array of addresses. Expressions like `.targets[].resolution.resolved[]` become `.targets[].resolution.resolved.sample[]`, and `discovery-plan-v1.json` stays fetchable at its own URL.
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

Additive changes stay on `v1` and remain backward-compatible. Three kinds of change qualify:

- a new optional field on `DeviceRecord`
- a new signal kind inside the `signals` array
- a new optional field on `ScanMetadata`

The `signals` array is open-ended on purpose. A consumer that meets an entry whose key it does not recognise must skip that entry, not reject the record. Consumers that ignore unknown fields — the default for most JSON libraries — keep working across an additive bump.

!!! warning "Refresh a cached schema copy before validating signals strictly"
    `device-record-v1.json` lists the signal kinds that existed when it was published. It allows no other key inside a `signals` entry. A strict validator running against an old cached copy therefore rejects a record carrying a newer signal kind. Refetch the schema by its `schema_id` URL when that happens. You can also skip strict validation of the `signals` array.

The producer-only allowance is narrower than it looks. A schema whose stored copies no consumer replays — `DiscoveryPlan` is the only one — may **gain required fields** on `v1`, because `required` binds validators and no validator runs against a plan. It may **not** change a field's type, rename a field, or remove one: those break a consumer that merely *reads* the document, which is the one thing every consumer of a plan does. The record schemas get no allowance at all, because consumers replay stored records.

Breaking changes (renaming or removing a field, changing a field's type, tightening a previously-optional field to required) increment the schema's version, `v1` → `v2`. What the bump costs depends on how the schema is delivered. Schemas published on a topic bump with a new topic / subject name (`rastreo.discovery.records.v2`) so `v1` and `v2` run in parallel for one release cycle, and consumers migrate on their own schedule. Schemas delivered synchronously in a response body, or read as an input file — `discovery-plan`, `scenario` — have no parallel channel: the bump publishes a new file, the release notes call it out, and the old file stays fetchable at its `v1` URL as a frozen copy. Either way the promise is the same: a fixed `vN` URL always describes one shape.

## Consumer discovery pattern

rastreo does not require a central schema registry. Each emitted record carries a `schema_id` URL. A consumer that wants to validate incoming records at ingest time reads `schema_id` from the first record it sees, fetches the JSON Schema at that URL once, and caches it. Because `schema_id` is a versioned URL, cache invalidation is trivial: when a record shows up with a `schema_id` the consumer has not seen before, refetch. The URL space is stable across releases within a major version.

For consumers running against a lab or air-gapped environment, the schema files ship in the source repo under `schemas/` — treat those as the offline copy and skip the fetch entirely.

## JSON Schema dialect

All published schemas use JSON Schema **draft 2020-12**:

- `device-record-v1.json`
- `link-record-v1.json`
- `collection-profile-record-v1.json`
- `scan-metadata-v1.json`
- `scenario-v1.json`
- `discovery-plan-v2.json` (and the frozen `discovery-plan-v1.json`)
- `dlq-envelope-v1.json`

Four properties of the schema text matter when you write a validator against them:

- The `$schema` URI is `https://json-schema.org/draft/2020-12/schema`.
- Reusable definitions live under `$defs`, and internal references point at them as `#/$defs/X`.
- A field fixed to one string value is expressed as `const` rather than a single-entry `enum`.
- Integer fields carry `minimum` and `maximum` bounds. Port fields are bounded to `0` through `65535`, matching a 16-bit unsigned integer.

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

!!! note "The schema written by hand"
    `dlq-envelope-v1.json` is written by hand rather than generated. It is on 2020-12 as well. It carries no `$defs`, no single-value `const` fields, and no bounded integers, so only the `$schema` property above applies to it.

## Confluent Schema Registry (future, opt-in)

The `schema_id` URL is the discovery mechanism today; a future release may add opt-in publication of the same JSON Schema to a Confluent-compatible Schema Registry. That path is additive — records still carry `schema_id`, and consumers that already validate via the URL keep working unchanged. No timeline yet; track the roadmap.

## Source layout

```
schemas/
├── asyncapi.yaml                      # AsyncAPI 3.0 description of the streaming surface
├── collection-profile-record-v1.json # JSON Schema for CollectionProfileRecord
├── device-record-v1.json             # JSON Schema for DeviceRecord
├── discovery-plan-v1.json            # JSON Schema for DiscoveryPlan (frozen, superseded by v2)
├── discovery-plan-v2.json            # JSON Schema for DiscoveryPlan
├── dlq-envelope-v1.json              # JSON Schema for DlqEnvelope (hand-written)
├── link-record-v1.json               # JSON Schema for LinkRecord
├── scan-metadata-v1.json             # JSON Schema for ScanMetadata
└── scenario-v1.json                  # JSON Schema for ScenarioFile (YAML scenario input)
```

Regenerate everything (JSON Schemas + this doc section) locally with `task schema:all`. The CI drift-check job re-runs the same command and fails if the committed files differ from what the generator produces.
