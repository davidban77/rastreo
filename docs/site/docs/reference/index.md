---
description: CLI flag reference, scenario JSON schema, error code table, and a glossary of network-discovery terms used throughout the docs.
---

# Reference

This section is the alphabetical / structured reference material. It is meant to be skimmed and grepped, not read top to bottom. Each page in this section is a flat list of fields, flags, or terms with their meaning and default.

<div class="grid cards" markdown>

-   :material-console:{ .lg .middle } **CLI reference**

    ---

    Every flag for `rastreo` and `rastreo-server`.

    [:octicons-arrow-right-24: CLI reference](cli.md)

-   :material-cog:{ .lg .middle } **Configuration reference**

    ---

    Every runtime environment variable both binaries read, with defaults and scope.

    [:octicons-arrow-right-24: Configuration reference](configuration.md)

-   :material-file-code:{ .lg .middle } **Scenario schema**

    ---

    The `DiscoverScenarioConfig` JSON shape.

    [:octicons-arrow-right-24: Scenario schema](scenario.md)

-   :material-key-variant:{ .lg .middle } **Secrets**

    ---

    Env-var and file-mount syntaxes for keeping credentials out of scenario YAML.

    [:octicons-arrow-right-24: Secrets](secrets.md)

-   :material-code-json:{ .lg .middle } **Record schema**

    ---

    The emitted `DeviceRecord` JSON Schema, versioning policy, and the streaming API description.

    [:octicons-arrow-right-24: Record schema](schema/index.md)

-   :material-alert-circle:{ .lg .middle } **Error reference**

    ---

    Every `RastreoError` variant and its likely fix.

    [:octicons-arrow-right-24: Error reference](errors.md)

-   :material-heart-pulse:{ .lg .middle } **Health endpoints**

    ---

    `/healthz`, `/readyz`, the `/health` alias, and the readiness gates.

    [:octicons-arrow-right-24: Health endpoints](health-endpoints.md)

-   :material-monitor-dashboard:{ .lg .middle } **Observability**

    ---

    The `/metrics` endpoint inventory, the bundled Grafana dashboard, and the packaged PrometheusRule alerts.

    [:octicons-arrow-right-24: Observability](observability.md)

-   :material-text-box-outline:{ .lg .middle } **Logging**

    ---

    Text and JSON log formats, log-level control, and aggregator ingestion examples.

    [:octicons-arrow-right-24: Logging](logging.md)

-   :material-telescope:{ .lg .middle } **OTLP**

    ---

    OpenTelemetry OTLP export for metrics, logs, and traces, behind the `otlp` build feature.

    [:octicons-arrow-right-24: OTLP](otlp.md)

-   :material-book-alphabet:{ .lg .middle } **Glossary**

    ---

    Domain terms used across the docs.

    [:octicons-arrow-right-24: Glossary](glossary.md)

</div>
