---
description: The classifier stage assigns canonical platform and role values on each DeviceRecord after fusion and before encoding. The classifier currently ships with only a noop variant; rules-based classification is not yet implemented.
---

# Classification

Classification is the pipeline stage that assigns canonical `platform` and `role` values on each `DeviceRecord`. It runs after fusion (per-IP + identity correlation) and before encoding, so the classifier sees the fully merged record — every signal from every prober against every IP that folded into the device.

The `platform` field is a fielded identifier like `cisco_ios`, `linux`, or `junos`. The `role` field is a fielded category like `router`, `switch`, or `host`. Both are targets for the discovery pipeline to normalise so downstream reconcilers (NetBox, Nautobot, Infrahub) receive already-canonicalised values instead of inferring them from raw signals.

The classifier currently ships with only a `noop` variant, the pass-through default. Rules-based classification — matching regex patterns against `SnmpSysDescr`, `HttpBanner`, `SshBanner`, and other signals to assign `platform` / `role` — is not yet implemented.

## Available classifiers

| Classifier | Behaviour |
|---|---|
| `noop` | Leaves every `DeviceRecord` unchanged. `platform` and `role` stay at whatever the fuser set them to (currently always `null`). Selected by default when the scenario does not configure a classifier. |

## Pipeline position

```
probe → fuse → classify → encode → sink
```

The classifier is the fourth stage. Probers produce raw `ProbeOutcome` values; the fuser groups outcomes into `DeviceRecord` objects and correlates records that describe the same physical device; the classifier stamps `platform` / `role` on each record; the encoder serialises the record; the sink delivers it. Because the classifier runs after fusion, it operates on merged records — a device with three interfaces classifies once, not three times.

## Configuration

The classifier is configured under the top-level `classifier` key of a scenario. Omitting the key selects `noop`:

```yaml
classifier:
  type: noop
```

The `type` field is required. Each future variant will add its own configuration fields.

## See also

- [Identity](identity.md) — how records are merged before classification runs.
- [Scenario reference](../reference/scenario.md#classifier) — the full configuration surface.
