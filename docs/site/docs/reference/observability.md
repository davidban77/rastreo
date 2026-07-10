---
description: rastreo-server operational metrics, the bundled Grafana dashboard, and the PrometheusRule alerts shipped by the Helm chart — what each metric means, how to install the dashboard via the Grafana sidecar pattern, the four packaged alerts with their expressions and severities, and the values.yaml knobs to tune them.
---

# Observability

`rastreo-server` ships operational metrics on `GET /metrics` in Prometheus text format, a Grafana dashboard as a labeled ConfigMap the Grafana sidecar auto-discovers, and a `PrometheusRule` template with four packaged alerts. All three are opt-in through the Helm chart's `values.yaml` — the metrics endpoint is always on, but the ServiceMonitor, the dashboard ConfigMap, and the PrometheusRule are only rendered when their respective toggles are flipped. This page enumerates what the endpoint exposes, walks through installing the dashboard, and documents the alerts with their tuning knobs.

## Metrics

Every metric uses the `rastreo_server_` prefix. All counters are monotonic across the process lifetime and reset only on restart. The histogram observes elapsed handling time from request-body parse to response build.

| Metric | Type | Labels | Unit | Meaning |
|---|---|---|---|---|
| `rastreo_server_scans_total` | counter | `outcome="success"\|"error"\|"cancelled"` | requests | `POST /scans` requests served, partitioned by outcome. Validation rejections (`400`) count as `error`. |
| `rastreo_server_probes_total` | counter | `outcome="success"\|"error"` | probes | Probes executed across all scans. `success` is computed as `attempted - errored`. |
| `rastreo_server_records_emitted_total` | counter | — | records | `DeviceRecord` events emitted across all scans. |
| `rastreo_server_sink_errors_total` | counter | — | errors | Sink errors surfaced via `POST /scans` (the `RastreoError::Sink` variant). |
| `rastreo_server_scan_duration_seconds` | histogram | — | seconds | `POST /scans` request handling duration. Buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`. |
| `rastreo_server_uptime_seconds` | gauge | — | seconds | Seconds since the server process started. |
| `rastreo_server_build_info` | gauge | `version` | — | Static `1`; the `version` label carries the binary's `CARGO_PKG_VERSION`. |

Labeled breakdowns for per-prober success rate, per-scenario scan duration, and per-error-class sink errors are on the roadmap. Today's metrics are aggregate — the dashboard and alerts are designed around that reality, not around labels that don't exist yet.

## Grafana dashboard

The chart bundles `helm/rastreo/dashboards/rastreo.json`, a dashboard organised into four rows — Traffic, Errors, Latency, Health — with ten data panels.

Enable delivery with:

```yaml
grafana:
  dashboardsEnabled: true
```

When enabled, the chart renders a ConfigMap named `<release>-rastreo-grafana-dashboard` labeled `grafana_dashboard: "1"`. A Grafana instance running the official Helm chart with the sidecar dashboard-discovery pattern picks the ConfigMap up automatically — no manual JSON import, no restart, no login. If your Grafana chart uses a different sidecar label than the default `grafana_dashboard: "1"`, override it:

```yaml
grafana:
  dashboardsEnabled: true
  dashboardLabel:
    name: my_dashboard_label
    value: "true"
```

The dashboard declares a `datasource` templating variable of type `datasource` with query `prometheus`, so the datasource is picked at load time and not baked into the JSON. Users with multiple Prometheus datasources can switch between them from the dashboard header without editing the JSON or the ConfigMap.

Panels shipped:

- **Traffic** — Scans per second by outcome (stacked), records emitted per second, probes per second by outcome (stacked).
- **Errors** — Sink errors per second, scan error ratio (percent), probe error ratio (percent).
- **Latency** — Scan duration percentiles (p50 / p95 / p99 from `histogram_quantile`), scan duration heatmap.
- **Health** — Uptime (stat panel, seconds formatted as d/h/m/s), build version (stat panel, taken from the `version` label via a `labels to fields` transform).

The dashboard has UID `rastreo-server` so bookmarked URLs stay stable across upgrades. It defaults to a 1-hour time window with 30-second auto-refresh.

## Alerts

The chart bundles a `PrometheusRule` template with four packaged alerts. Enable delivery with:

```yaml
alerts:
  enabled: true
```

When enabled, the chart renders a `PrometheusRule` named `<release>-rastreo` under `apiVersion: monitoring.coreos.com/v1`. Deployment requires the Prometheus Operator CRD to be installed in the cluster; without it, `kubectl apply` fails with `no matches for kind "PrometheusRule"`.

Prometheus Operator's `ruleSelector` typically matches on labels like `role: alert-rules` or `release: <prometheus-release-name>`. If your Operator only picks up rules with a specific label, add it via `additionalLabels`:

```yaml
alerts:
  enabled: true
  additionalLabels:
    role: alert-rules
    release: kube-prometheus-stack
```

The packaged alerts:

| Alert | Expression | `for` | Severity | Interpretation |
|---|---|---|---|---|
| `RastreoScanFailureRate` | `sum(rate(rastreo_server_probes_total{outcome="error"}[10m])) / clamp_min(sum(rate(rastreo_server_probes_total[10m])), 1) > 0.5` | 10m | warning | Probe error ratio has stayed above 50% for the last 10 minutes. Investigate target reachability or scenario configuration — the scan is running but almost nothing is succeeding. |
| `RastreoSinkErrorSpike` | `rate(rastreo_server_sink_errors_total[5m]) > (1 / 60)` | 5m | warning | Sink error rate exceeds 1 per minute for 5+ consecutive minutes. Check the sink configuration and downstream broker / topic availability. If a DLQ is configured, DLQ traffic may be elevated in parallel. |
| `RastreoNoRecordsEmitted10min` | `increase(rastreo_server_records_emitted_total[10m]) == 0 and sum without (outcome) (rate(rastreo_server_scans_total[10m])) > 0` | 10m | warning | No records have been emitted in the last 10 minutes despite active scans. Either every prober is failing to observe live devices, or the sink is silently swallowing records. |
| `RastreoBuildOld` | `rastreo_server_uptime_seconds > <threshold>` | 1h | info | The pod has been running the same build longer than `alerts.buildAgeThresholdSeconds`. This is a proxy for "old build" — it does not check the actual release age, only the pod uptime. Bumping the image tag (or any rolling restart) resets it. |

The `clamp_min(..., 1)` in the ratio expressions prevents division-by-zero and stops the alert from firing spuriously when the denominator is zero. The `RastreoBuildOld` alert uses `rastreo_server_uptime_seconds > threshold` because "how long has this pod been running the same binary" is what the metric can actually observe; a rolling restart or an image bump resets the gauge to zero.

## Tuning

Two `alerts.*` knobs and two `grafana.*` knobs cover the operational surface.

| Value | Default | What it controls |
|---|---|---|
| `alerts.enabled` | `false` | Render the `PrometheusRule` resource. Requires the Prometheus Operator CRD. |
| `alerts.additionalLabels` | `{}` | Extra labels merged onto the `PrometheusRule` metadata so the Operator's `ruleSelector` picks it up. |
| `alerts.buildAgeThresholdSeconds` | `2592000` (30 days) | Uptime threshold above which `RastreoBuildOld` fires. Bump for laxer paging cadence; lower for tighter release discipline. |
| `grafana.dashboardsEnabled` | `false` | Render the labeled dashboard ConfigMap. Requires a Grafana instance with the sidecar dashboard-discovery pattern enabled. |
| `grafana.dashboardLabel.name` | `grafana_dashboard` | ConfigMap label the Grafana sidecar watches. Override if your Grafana chart uses a different label. |
| `grafana.dashboardLabel.value` | `"1"` | Value paired with `dashboardLabel.name` on the ConfigMap. |

## Roadmap follow-ups

Three enrichment gaps limit the current dashboard and alerts to aggregate signals. All three land together in a metric-label enrichment PR:

- **Probe kind label on `probes_total`** — enables a "per-prober success rate" panel and per-prober error-ratio alerts.
- **Scenario name label on `scan_duration_seconds`** — enables per-scenario latency histograms and per-scenario SLO alerts.
- **Error class label on `sink_errors_total`** — enables a stacked "sink errors by error class" panel and per-class alerting (e.g., page harder on `publish_failure` than on `ack_rejection`).

Follow-ups also include a DLQ traffic surge alert (`rate(sink_errors_total{class="dlq_send"}[5m]) > threshold`) and a paired `dlq_records_total` counter so ops teams can trigger on DLQ pressure without inferring from primary failures.

## See also

- [Kubernetes](../deploy/kubernetes.md) — the Helm chart install and top-level values reference.
- [rastreo-server](../deploy/server.md) — the `GET /metrics` endpoint documented alongside `POST /scans`, health, and configuration.
- [Health endpoints](health-endpoints.md) — `/healthz`, `/readyz`, and the readiness gates that pair with these metrics.
