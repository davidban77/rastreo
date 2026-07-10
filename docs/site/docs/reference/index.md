---
description: CLI flag reference, scenario JSON schema, error code table, and a glossary of network-discovery terms used throughout the docs.
---

# Reference

This section is the alphabetical / structured reference material. It is meant to be skimmed and grepped, not read top to bottom. Each page in this section is a flat list of fields, flags, or terms with their meaning and default.

Topics covered here include the full `rastreo` and `rastreo-server` CLI flag reference, the scenario JSON schema (every field in the `DiscoverScenarioConfig` shape that `POST /scans` and the library accept), an error reference mapping each `RastreoError` variant to its meaning and likely cause, and a glossary of network-discovery terminology.

## Pages in this section

- [CLI reference](cli.md) — every flag for `rastreo` and `rastreo-server`.
- [Scenario schema](scenario.md) — the `DiscoverScenarioConfig` JSON shape.
- [Secrets](secrets.md) — env-var and file-mount syntaxes for keeping credentials out of scenario YAML.
- [Record schema](schema/index.md) — the emitted `DeviceRecord` JSON Schema, versioning policy, and the streaming API description.
- [Error reference](errors.md) — every `RastreoError` variant and its likely fix.
- [Health endpoints](health-endpoints.md) — `/healthz`, `/readyz`, the `/health` alias, and the readiness gates.
- [Observability](observability.md) — the `/metrics` endpoint inventory, the bundled Grafana dashboard, and the packaged PrometheusRule alerts.
- [Logging](logging.md) — text and JSON log formats, log-level control, and aggregator ingestion examples.
- [Glossary](glossary.md) — domain terms used across the docs.
