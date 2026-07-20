---
description: OpenTelemetry OTLP export for rastreo — build with the otlp feature to push metrics, logs, and pipeline-stage traces to a Grafana Alloy, OpenTelemetry Collector, or Grafana Cloud endpoint over gRPC or HTTP+protobuf. Metrics export is server-only; logs and traces work on both the CLI and the server.
---

# OpenTelemetry OTLP

`rastreo-server` can push metrics, logs, and traces, and the `rastreo` CLI can push logs and traces, to any OTLP-speaking backend (Grafana Alloy, OpenTelemetry Collector, Grafana Cloud, Honeycomb, Tempo, or a self-hosted collector) via gRPC or HTTP+protobuf. The exporter is behind an opt-in Cargo feature — the default binaries do not include it because the OpenTelemetry Rust chain pulls in `tonic`, `prost`, `reqwest`, and a large slice of the async transport stack. OTLP is off by default even in feature-enabled builds; enable per binary with environment variables.

Metrics, logs, and traces are the three signal types. Metrics export is server-only — the CLI is short-running and does not export metrics; setting `RASTREO_OTLP_METRICS_ENABLED=true` on the CLI is rejected at startup with a clear error. Logs and traces work on both binaries. See [Traces exported via OTLP](#traces-exported-via-otlp) for what a trace contains.

## Building with OTLP support

The OTLP dependencies are gated behind the `otlp` Cargo feature on both the CLI and the server crate.

```bash
cargo build --release -p rastreo-server --features otlp
cargo build --release -p rastreo --features otlp
```

The default `ghcr.io/davidban77/rastreo:X.Y.Z` image does NOT ship with the OTLP feature enabled — this keeps the default image lean for the common case where metrics are pulled by a Prometheus scrape target and logs are shipped from stdout by a log aggregator. An OTLP-enabled companion image is published alongside every release at `ghcr.io/davidban77/rastreo:X.Y.Z-otlp`; see [Docker image with OTLP support](#docker-image-with-otlp-support) below.

## Configuration

Both binaries read the same environment variables at startup and fail-fast on invalid or incomplete configuration.

| Variable | Default | Meaning |
|---|---|---|
| `RASTREO_OTLP_METRICS_ENABLED` | `false` | Enable metrics export. **Server-only** — setting this to `true` on the `rastreo` CLI is rejected at startup. Booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`. |
| `RASTREO_OTLP_LOGS_ENABLED` | `false` | Enable logs export. Supported on both the server and the CLI. |
| `RASTREO_OTLP_TRACES_ENABLED` | `false` | Enable trace export. Supported on both the server and the CLI. Enabling traces alone, without metrics or logs, is valid. See [Traces exported via OTLP](#traces-exported-via-otlp). |
| `RASTREO_OTLP_ENDPOINT` | — (required) | OTLP collector endpoint URL. Format depends on `RASTREO_OTLP_PROTOCOL`: gRPC uses `http://otel-collector.observability.svc:4317`; HTTP+protobuf typically uses `http://otel-collector.observability.svc:4318`. Required when any exporter is enabled. |
| `RASTREO_OTLP_PROTOCOL` | `grpc` | Transport protocol. Accepts `grpc`, `http-protobuf`, or the alias `http`. Values are case-insensitive. See [Transport protocol](#transport-protocol). |
| `RASTREO_OTLP_METRICS_INTERVAL_SECS` | `30` | Periodic export interval for metrics, in seconds. **Server-only**; ignored when metrics export is off. |
| `RASTREO_OTLP_SERVICE_NAME` | `rastreo-server` (server) / `rastreo` (CLI) | Value of the OpenTelemetry resource attribute `service.name` on every exported signal. |
| `RASTREO_OTLP_HEADERS` | — (none) | Custom headers attached to every OTLP request, for authenticating to a hosted collector. OTel `key=value` format, comma-separated. Values are secrets. See [Custom headers](#custom-headers). |

Configuration is validated at startup. Enabling any exporter without an endpoint, passing a non-boolean value for a flag, or passing a non-numeric interval all fail the process with an actionable error before the HTTP server binds or the CLI runs a scan.

The three signals can run together, alone, or not at all — a common pattern is to enable logs only in local development (the collector is easier to reach than a Loki instance) and metrics only in production (Prometheus scrape covers `/metrics` too, so OTLP metrics are usually redundant).

## Transport protocol

Both binaries compile in two OTLP transports and select one at startup via `RASTREO_OTLP_PROTOCOL`. gRPC is the default and matches the OpenTelemetry SDK convention. HTTP+protobuf is a runtime alternative for collectors reached over HTTPS-only ingress, over restricted networks that block gRPC, or for managed backends that only expose an HTTP+protobuf endpoint.

| Value | Default port | Endpoint URL format |
|---|---|---|
| `grpc` | `4317` | `http://collector:4317` — the SDK sends every signal to the same host:port. |
| `http-protobuf` (or the alias `http`) | `4318` | `http://collector:4318` — rastreo appends `/v1/metrics` and `/v1/logs` per signal so a single endpoint value works for both. Pass a fully-qualified URL like `http://collector:4318/v1/logs` when the collector is on a non-standard route (rastreo detects the trailing signal path and does not double-append). |

Values are case-insensitive; `HTTP-PROTOBUF`, `Grpc`, and `GRPC` all parse cleanly. Unknown values fail startup with an actionable error listing the accepted set.

Choose gRPC when the collector accepts it directly (Grafana Alloy's default receiver, most `otelcol` deployments, an in-cluster ClusterIP service). Choose HTTP+protobuf when the collector is behind an ingress controller that terminates TLS and forwards HTTP but not gRPC, when a corporate network filters HTTP/2 keep-alives, or when a managed backend only publishes an HTTP endpoint. Both transports carry the same protobuf payload — the wire format is identical; only the transport layer differs.

## Custom headers

Some managed collectors need an authentication header on every request. Set `RASTREO_OTLP_HEADERS` to attach one or more headers to every OTLP export. Use it to authenticate to a hosted backend — Grafana Cloud, Honeycomb, Dynatrace, or a tenant-scoped Tempo or Mimir.

The value is a comma-separated list of `key=value` pairs. rastreo splits each pair on the first `=`, so a value may itself contain `=` (a base64 token, for example). Header names are lowercased. This mirrors the OpenTelemetry `OTEL_EXPORTER_OTLP_HEADERS` convention. Leave the variable unset to send no custom headers.

A single bearer token:

```bash
export RASTREO_OTLP_HEADERS="authorization=Bearer <token>"
```

Multiple headers — a token plus a tenant id — separated by commas:

```bash
export RASTREO_OTLP_HEADERS="authorization=Bearer <token>,x-scope-orgid=<tenant>"
```

The headers apply to all three signals — metrics, logs, and traces. They apply to both transports, `grpc` and `http-protobuf`. You set them once and every exported signal carries them.

A malformed value fails startup — the value is never silently dropped. These entries are rejected before the server binds or the CLI runs a scan:

- an entry with no `=`
- an empty header name
- a name that is not a valid HTTP header token

!!! warning "Header values are secrets"
    A header value is usually a bearer token or an API key. rastreo treats it as secret: it never writes a header value to its logs or config output, and a startup error reports only the header name. On Kubernetes, supply the headers from a Secret instead of an inline value — see [Custom OTLP headers on Kubernetes](../deploy/kubernetes.md#custom-otlp-headers).

## Metrics exported via OTLP (server only)

!!! note "Server-only"
    Metrics export via OTLP is available only on `rastreo-server`. The `rastreo` CLI is short-running and does not export metrics; setting `RASTREO_OTLP_METRICS_ENABLED=true` on the CLI fails startup with an actionable error pointing you at `RASTREO_OTLP_LOGS_ENABLED=true` instead.

Every metric enumerated on the [Observability page](observability.md#metrics) is also exported via OTLP, under the same instrument names and attribute keys. Counters map to observable counters, gauges to observable gauges, and the histogram is recorded synchronously alongside the internal Prometheus-format bucket accumulator.

| OpenTelemetry name | Instrument | Attributes |
|---|---|---|
| `rastreo_server_scans_total` | observable counter (u64) | `outcome=success\|error\|cancelled` |
| `rastreo_server_probes_total` | observable counter (u64) | `outcome=success\|error` (see [what `outcome` means](observability.md#what-outcome-means)), `probe_kind` (bounded set — see [probe_kind taxonomy](observability.md#probe_kind-taxonomy)) |
| `rastreo_server_records_emitted_total` | observable counter (u64) | — |
| `rastreo_server_sink_errors_total` | observable counter (u64) | `error_class` (bounded set — see [error_class taxonomy](observability.md#error_class-taxonomy)) |
| `rastreo_server_dlq_records_total` | observable counter (u64) | `sink_type` (`kafka\|nats`), `error_class` |
| `rastreo_server_scan_duration_seconds` | histogram (f64, unit `s`) | `scenario` (see [scenario label](observability.md#scenario-label)) |
| `rastreo_server_uptime_seconds` | observable gauge (f64) | — |
| `rastreo_server_build_info` | observable gauge (u64, value always `1`) | `version` |

The instrument names use underscore separators, not the OpenTelemetry semantic-convention dot separators, so they line up with the Prometheus-format names on `/metrics`. When a collector like Grafana Alloy fans OTLP metrics into a downstream Prometheus datasource, the OTLP and scrape paths surface the same metric names.

The `scan_duration_seconds` histogram is recorded once per scan with the `scenario` attribute set to the same allow-list-mapped label used on the `/metrics` endpoint. Truncation and allow-list matching happen before the record call, so cardinality behaviour is identical on both surfaces.

## Logs exported via OTLP

When logs export is enabled, `tracing` events are bridged to OpenTelemetry log records via `opentelemetry-appender-tracing`. Both stderr formatting (`--log-format text` or `--log-format json`) and OTLP export run in parallel — the `--log-format` flag still controls the stderr layer independently, so a container can produce human-readable stderr for `kubectl logs` while shipping structured OTLP records to a collector.

Every `tracing::info!`, `tracing::warn!`, and `tracing::error!` call surfaces the same `target`, `severity`, `message`, and structured fields via OTLP that the JSON stderr layer already produces. The `RASTREO_LOG` env filter that governs the stderr layer also governs the OTLP layer — dropping the level to `warn` cuts both.

## Traces exported via OTLP

When trace export is enabled, each scan emits a small, fixed set of spans that show where the scan spends its time. A root span named `scan` wraps three child spans, one per pipeline stage:

- `resolve` — turning targets (DNS names, CIDRs, ranges) into concrete IP addresses.
- `stream` — running the probes and sending records to the sink.
- `finish` — final correlation and flush after the last probe completes.

Open a scan trace in Tempo, Jaeger, or Grafana and you see which stage takes the most time. A scan that is slow in `resolve` points at DNS. A scan that is slow in `stream` points at the probes or a slow sink.

!!! info "Trace volume stays constant per scan"
    The span count is the same for every scan — one root span plus three stage spans — no matter how many targets or ports the scan covers. There are no per-target or per-probe spans. A `/16` sweep produces the same four spans as a single-host scan, so traces stay cheap even on very large scans.

Trace export works on both `rastreo-server` and the `rastreo` CLI. Enable it with `RASTREO_OTLP_TRACES_ENABLED=true` and point `RASTREO_OTLP_ENDPOINT` at your collector:

```bash
export RASTREO_OTLP_ENDPOINT=http://otel-collector:4317
export RASTREO_OTLP_TRACES_ENABLED=true
rastreo discover --target 192.0.2.0/24 --port 22,443
```

Traces do not depend on metrics or logs. Enabling `RASTREO_OTLP_TRACES_ENABLED` on its own is valid. To send all three signals, set each `*_ENABLED` variable.

## Docker image with OTLP support

The default `ghcr.io/davidban77/rastreo:X.Y.Z` image does not include `--features otlp` — the OpenTelemetry Rust stack pulls in `tonic`, `prost`, and `reqwest`, and shipping those to every operator would grow the image for the majority of users who scrape `/metrics` and ship logs off stdout. An OTLP-enabled companion image is published alongside every release under the same repository:

```
ghcr.io/davidban77/rastreo:X.Y.Z-otlp
```

Both variants are multi-arch (`linux/amd64`, `linux/arm64`) and identical apart from the compiled-in `otlp` feature. Every release tag has a matching `-otlp` sibling: the full semver (`X.Y.Z` and `X.Y.Z-otlp`), the minor line (`X.Y` and `X.Y-otlp`), the major line (`X` and `X-otlp`), and the rolling `latest` and `latest-otlp` tags.

Operators who want OTLP change one tag in their Deployment or Helm values:

```yaml
image:
  repository: ghcr.io/davidban77/rastreo
  tag: "X.Y.Z-otlp"
```

A future chart iteration may add an `image.variant: otlp` shortcut so the `-otlp` suffix is toggled by a semantic key rather than embedded in the tag string; the raw tag override works today.

## Kubernetes deployment

The Helm chart's `values.yaml` exposes the same knobs under an `otlp` block. When any of `metricsEnabled` or `logsEnabled` is true, the chart renders the matching `RASTREO_OTLP_*` environment variables on the container. When both are false, no OTLP variables are rendered and the container behaves as before.

```yaml
otlp:
  endpoint: "http://otel-collector.observability.svc:4317"
  protocol: grpc
  metricsEnabled: true
  logsEnabled: true
  metricsIntervalSeconds: 30
  serviceName: "rastreo-server"
```

The container image must be an OTLP-enabled build. Point `image.tag` at the `-otlp` variant published alongside every release (see [Docker image with OTLP support](#docker-image-with-otlp-support) above), or build a custom image on top of the source tree with `--features otlp` and Docker-package it. If a non-OTLP image sees these variables, it ignores them; the binary was compiled without the exporter.

For the collector configuration, the two most common target stacks are:

- **Grafana Alloy** — set the endpoint to Alloy's OTLP gRPC receiver port (`4317` by default). Configure Alloy to fan metrics to Prometheus and logs to Loki. See the [Alloy OTLP receiver docs](https://grafana.com/docs/alloy/latest/reference/components/otelcol.receiver.otlp/) for the receiver block.
- **OpenTelemetry Collector** — deploy the collector as a Deployment or DaemonSet with an `otlp` receiver, an `otlphttp` or `prometheusremotewrite` exporter for metrics, and a `loki` exporter for logs. The [Collector configuration docs](https://opentelemetry.io/docs/collector/configuration/) walk through the receiver / processor / exporter layout.

The receiver's gRPC listener must be reachable from the rastreo-server pod's network namespace. When the collector runs in the same cluster, a `ClusterIP` service is enough; when it runs off-cluster, add whatever ingress or gateway your platform expects and put the resolvable URL in `endpoint`.

## See also

- [Observability](observability.md) — the `/metrics` shape, the bundled Grafana dashboard, and the packaged PrometheusRule alerts.
- [Logging](logging.md) — the `--log-format` flag and the stderr JSON schema.
- [Kubernetes](../deploy/kubernetes.md) — Helm chart `values.yaml` reference.
