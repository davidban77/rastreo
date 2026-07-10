---
description: OpenTelemetry OTLP export for rastreo — build with the otlp feature to push the metrics and logs that /metrics and stderr already emit to a Grafana Alloy, OpenTelemetry Collector, or Grafana Cloud endpoint over gRPC. Metrics export is server-only; the `rastreo` CLI ships logs.
---

# OpenTelemetry OTLP

`rastreo-server` can push metrics and logs, and the `rastreo` CLI can push logs, to any OTLP-speaking backend (Grafana Alloy, OpenTelemetry Collector, Grafana Cloud, Honeycomb, Tempo, or a self-hosted collector) via gRPC. The exporter is behind an opt-in Cargo feature — the default binaries do not include it because the OpenTelemetry Rust chain pulls in `tonic`, `prost`, and a large slice of the async transport stack. OTLP is off by default even in feature-enabled builds; enable per binary with environment variables.

Metrics and logs are the two signal types shipped in this integration. Metrics export is server-only — the CLI is short-running and does not export metrics; setting `RASTREO_OTLP_METRICS_ENABLED=true` on the CLI is rejected at startup with a clear error. Traces are deliberately deferred — see [Why traces are deferred](#why-traces-are-deferred).

## Building with OTLP support

The OTLP dependencies are gated behind the `otlp` Cargo feature on both the CLI and the server crate.

```bash
cargo build --release -p rastreo-server --features otlp
cargo build --release -p rastreo --features otlp
```

Pre-built `ghcr.io/davidban77/rastreo` images do NOT ship with the OTLP feature enabled — this keeps the default image lean for the common case where metrics are pulled by a Prometheus scrape target and logs are shipped from stdout by a log aggregator. To run OTLP export in Kubernetes today, build a custom image on top of the source tree with `--features otlp`. An official OTLP-enabled image variant is on the roadmap.

## Configuration

Both binaries read the same environment variables at startup and fail-fast on invalid or incomplete configuration.

| Variable | Default | Meaning |
|---|---|---|
| `RASTREO_OTLP_METRICS_ENABLED` | `false` | Enable metrics export. **Server-only** — setting this to `true` on the `rastreo` CLI is rejected at startup. Booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`. |
| `RASTREO_OTLP_LOGS_ENABLED` | `false` | Enable logs export. Supported on both the server and the CLI. |
| `RASTREO_OTLP_ENDPOINT` | — (required) | OTLP gRPC endpoint URL, e.g. `http://otel-collector.observability.svc:4317`. Required when either exporter is enabled. |
| `RASTREO_OTLP_METRICS_INTERVAL_SECS` | `30` | Periodic export interval for metrics, in seconds. **Server-only**; ignored when metrics export is off. |
| `RASTREO_OTLP_SERVICE_NAME` | `rastreo-server` (server) / `rastreo` (CLI) | Value of the OpenTelemetry resource attribute `service.name` on every exported signal. |

Configuration is validated at startup. Enabling either exporter without an endpoint, passing a non-boolean value for a flag, or passing a non-numeric interval all fail the process with an actionable error before the HTTP server binds or the CLI runs a scan.

Both signals may run at once, either alone, or neither — a common pattern is to enable logs only in local development (the collector is easier to reach than a Loki instance) and metrics only in production (Prometheus scrape covers `/metrics` too, so OTLP metrics are usually redundant).

## Metrics exported via OTLP (server only)

!!! note "Server-only"
    Metrics export via OTLP is available only on `rastreo-server`. The `rastreo` CLI is short-running and does not export metrics; setting `RASTREO_OTLP_METRICS_ENABLED=true` on the CLI fails startup with an actionable error pointing you at `RASTREO_OTLP_LOGS_ENABLED=true` instead.

Every metric enumerated on the [Observability page](observability.md#metrics) is also exported via OTLP, under the same instrument names and attribute keys. Counters map to observable counters, gauges to observable gauges, and the histogram is recorded synchronously alongside the internal Prometheus-format bucket accumulator.

| OpenTelemetry name | Instrument | Attributes |
|---|---|---|
| `rastreo_server_scans_total` | observable counter (u64) | `outcome=success\|error\|cancelled` |
| `rastreo_server_probes_total` | observable counter (u64) | `outcome=success\|error` |
| `rastreo_server_records_emitted_total` | observable counter (u64) | — |
| `rastreo_server_sink_errors_total` | observable counter (u64) | — |
| `rastreo_server_scan_duration_seconds` | histogram (f64, unit `s`) | — |
| `rastreo_server_uptime_seconds` | observable gauge (f64) | — |
| `rastreo_server_build_info` | observable gauge (u64, value always `1`) | `version` |

The instrument names use underscore separators, not the OpenTelemetry semantic-convention dot separators, so they line up with the Prometheus-format names on `/metrics`. When a collector like Grafana Alloy fans OTLP metrics into a downstream Prometheus datasource, the OTLP and scrape paths surface the same metric names.

Labeled breakdowns for per-prober success rate, per-scenario duration, and per-error-class sink errors are on the [roadmap](observability.md#metrics) — the aggregate shape shipped today matches the shape on `/metrics`.

## Logs exported via OTLP

When logs export is enabled, `tracing` events are bridged to OpenTelemetry log records via `opentelemetry-appender-tracing`. Both stderr formatting (`--log-format text` or `--log-format json`) and OTLP export run in parallel — the `--log-format` flag still controls the stderr layer independently, so a container can produce human-readable stderr for `kubectl logs` while shipping structured OTLP records to a collector.

Every `tracing::info!`, `tracing::warn!`, and `tracing::error!` call surfaces the same `target`, `severity`, `message`, and structured fields via OTLP that the JSON stderr layer already produces. The `RASTREO_LOG` env filter that governs the stderr layer also governs the OTLP layer — dropping the level to `warn` cuts both.

## Why traces are deferred

An OpenTelemetry span-per-phase view of a rastreo scan — `resolve → schedule → probe → fuse → encode → sink` — would not reveal anything a metric could not. The pipeline is short, well-understood, and already instrumented with counters at every failure boundary. Traces add operational overhead (span export, sampling policy, trace-id propagation across probers) for a payoff that is not visible on a real user's dashboard.

If a real user runs into a symptom where traces would help — a slow-tail scan with no counter movement, cross-service correlation between rastreo and a downstream Kafka consumer — the trace exporter can be added on top of the existing OpenTelemetry SDK setup without breaking any of the exported metrics or logs. The Cargo feature is already carved out; the exporter builder is a copy-paste from the metric exporter with a different signal.

## Kubernetes deployment

The Helm chart's `values.yaml` exposes the same knobs under an `otlp` block. When any of `metricsEnabled` or `logsEnabled` is true, the chart renders the matching `RASTREO_OTLP_*` environment variables on the container. When both are false, no OTLP variables are rendered and the container behaves as before.

```yaml
otlp:
  endpoint: "http://otel-collector.observability.svc:4317"
  metricsEnabled: true
  logsEnabled: true
  metricsIntervalSeconds: 30
  serviceName: "rastreo-server"
```

The container image must be an OTLP-enabled build (`cargo build --release -p rastreo-server --features otlp`, then Docker-packaged) — the default published image does not accept OTLP env vars. If a non-OTLP image sees these variables, it ignores them; the binary was compiled without the exporter.

For the collector configuration, the two most common target stacks are:

- **Grafana Alloy** — set the endpoint to Alloy's OTLP gRPC receiver port (`4317` by default). Configure Alloy to fan metrics to Prometheus and logs to Loki. See the [Alloy OTLP receiver docs](https://grafana.com/docs/alloy/latest/reference/components/otelcol.receiver.otlp/) for the receiver block.
- **OpenTelemetry Collector** — deploy the collector as a Deployment or DaemonSet with an `otlp` receiver, an `otlphttp` or `prometheusremotewrite` exporter for metrics, and a `loki` exporter for logs. The [Collector configuration docs](https://opentelemetry.io/docs/collector/configuration/) walk through the receiver / processor / exporter layout.

The receiver's gRPC listener must be reachable from the rastreo-server pod's network namespace. When the collector runs in the same cluster, a `ClusterIP` service is enough; when it runs off-cluster, add whatever ingress or gateway your platform expects and put the resolvable URL in `endpoint`.

## Follow-ups

- **Labeled metrics** — the roadmap item that adds `probe_kind`, `scenario`, and `error_class` labels to the aggregate counters will surface on the OTLP export path automatically once the internal `Metrics` struct grows the label keys.
- **OTLP-enabled Docker image variant** — a `ghcr.io/davidban77/rastreo-otlp` tag published alongside the default image would remove the "build your own image" step for k8s deployments.
- **OTLP HTTP + protobuf transport** — today's exporter only speaks gRPC. HTTP+protobuf is a common fallback for collectors behind restrictive load balancers; it's a single builder swap in the code but a second `Cargo.toml` feature to compile.

## See also

- [Observability](observability.md) — the `/metrics` shape, the bundled Grafana dashboard, and the packaged PrometheusRule alerts.
- [Logging](logging.md) — the `--log-format` flag and the stderr JSON schema.
- [Kubernetes](../deploy/kubernetes.md) — Helm chart `values.yaml` reference.
