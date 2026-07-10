---
description: rastreo-server operational metrics, the bundled Grafana dashboard, and the PrometheusRule alerts shipped by the Helm chart — what each metric means, how to install the dashboard via the Grafana sidecar pattern, the packaged alerts with their expressions and severities, and the values.yaml knobs to tune them.
---

# Observability

`rastreo-server` ships operational metrics on `GET /metrics` in Prometheus text format, a Grafana dashboard as a labeled ConfigMap the Grafana sidecar auto-discovers, and a `PrometheusRule` template with packaged alerts. All three are opt-in through the Helm chart's `values.yaml` — the metrics endpoint is always on, but the ServiceMonitor, the dashboard ConfigMap, and the PrometheusRule are only rendered when their respective toggles are flipped. This page enumerates what the endpoint exposes, walks through installing the dashboard, and documents the alerts with their tuning knobs.

## Metrics

Every metric uses the `rastreo_server_` prefix. All counters are monotonic across the process lifetime and reset only on restart. The histogram observes elapsed handling time from request-body parse to response build.

| Metric | Type | Labels | Unit | Meaning |
|---|---|---|---|---|
| `rastreo_server_scans_total` | counter | `outcome="success"\|"error"\|"cancelled"` | requests | `POST /scans` requests served, partitioned by outcome. Validation rejections (`400`) count as `error`. |
| `rastreo_server_probes_total` | counter | `outcome="success"\|"error"`, `probe_kind` | probes | Probes executed across all scans, partitioned by outcome and probe kind. See the [probe_kind taxonomy](#probe_kind-taxonomy) below. `success` is a monotonic per-scan counter incremented by `probe_attempts - probe_errors` so both `/metrics` and the OTLP observable counter remain non-decreasing per attribute-set. |
| `rastreo_server_records_emitted_total` | counter | — | records | `DeviceRecord` events emitted across all scans. |
| `rastreo_server_sink_errors_total` | counter | `error_class` | errors | Sink errors surfaced via `POST /scans` (the `RastreoError::Sink` variant), partitioned by error class. See the [error_class taxonomy](#error_class-taxonomy) below. |
| `rastreo_server_dlq_records_total` | counter | `sink_type`, `error_class` | records | Records delivered to a dead-letter destination during scan handling, partitioned by sink type and error class. See [DLQ classification (v1)](#dlq-classification-v1) below. |
| `rastreo_server_scan_duration_seconds` | histogram | `scenario` | seconds | `POST /scans` request handling duration, partitioned by scenario name. Buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`. See the [scenario label](#scenario-label) below. |
| `rastreo_server_uptime_seconds` | gauge | — | seconds | Seconds since the server process started. |
| `rastreo_server_build_info` | gauge | `version` | — | Static `1`; the `version` label carries the binary's `CARGO_PKG_VERSION`. |

### probe_kind taxonomy

The `probe_kind` label carries the snake_case name of the probe that produced the row. The taxonomy is closed at the crate boundary — every prober built into rastreo maps to exactly one label. Bounded (11 today): `tcp_connect`, `udp`, `http`, `dns`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, `reverse_dns`. Adding a new prober requires updating the enum and its label table in the same change; consumers can query on the label without a hardcoded list.

### error_class taxonomy

The `error_class` label groups sink failures by their observable shape so ops teams can triage without opening logs. Bounded (6): `publish_failure` (broker unreachable or subject invalid), `ack_rejection` (broker accepted but refused durable storage — stream quota, retention hit), `produce_failure` (Kafka primary produce failure), `write_failure` (file / stdout write failed), `flush_failure` (buffer drain on flush failed), `other` (anything unclassified).

### DLQ classification (v1)

`rastreo_server_dlq_records_total` credits Kafka DLQ deliveries to `error_class="produce_failure"` and NATS DLQ deliveries to `error_class="publish_failure"`. This is a sink-type-hint mapping — it reflects the class the DLQ absorbs for that sink today, not per-record classification. A future revision will attach the specific class that triggered each individual DLQ delivery. The imprecision does not affect alerting on aggregate DLQ traffic (see `RastreoDlqTrafficSurge`).

### scenario label

Every observation of `rastreo_server_scan_duration_seconds` lands under `scenario="_all"`. If the scenario name (from `base.name` in the scenario config, truncated to `RASTREO_SCENARIO_LABEL_MAX_LENGTH` — default 64 chars) is in `RASTREO_SCENARIO_LABEL_ALLOWLIST`, the observation also lands under `scenario="<name>"`. Otherwise it also lands under `scenario="other"`. The default allow-list is empty — every scan buckets into `_all` and `other` only, keeping label cardinality bounded regardless of how many distinct scenarios the server accepts. Set the env var (or the `metrics.scenarioAllowlist` Helm value) to a comma-separated list to opt specific scenarios into their own labeled series. The names `_all` and `other` are reserved for the aggregate and catch-all buckets and are rejected if listed in the allow-list. Every scan writes exactly two observations per histogram — one to `_all`, one to either `<name>` or `other` — so the series count per histogram bucket is `2 × (buckets + sum + count)` for allow-listed scenarios.

Cardinality guard rationale: scenario names are user-supplied strings on `POST /scans`. Without the allow-list, a client could name each request differently and blow up the Prometheus label set. The allow-list makes the operator opt in to the labels they actually want to monitor.

## Grafana dashboard

The chart bundles `helm/rastreo/dashboards/rastreo.json`, a dashboard organised into four rows — Traffic, Errors, Latency, Health — with data panels for every metric shipped.

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

- **Traffic** — Scans per second by outcome (stacked), records emitted per second, probes per second by outcome (stacked), per-prober success rate (line per `probe_kind`).
- **Errors** — Sink errors per second (aggregate), scan error ratio (percent), probe error ratio (percent), sink errors by error class (stacked per `error_class`), DLQ records per second (stacked per `sink_type` × `error_class`).
- **Latency** — Scan duration percentiles (p50 / p95 / p99 from `histogram_quantile` on `scenario="_all"`), scan duration heatmap, scan duration p95 per scenario (line per `scenario`, populated only for allow-listed names).
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
| `RastreoScanFailureRate` | `sum(rate(rastreo_server_probes_total{outcome="error"}[10m])) / clamp_min(sum(rate(rastreo_server_probes_total[10m])), 1) > 0.5` | 10m | warning | Aggregate probe error ratio has stayed above 50% for the last 10 minutes. Investigate target reachability or scenario configuration — the scan is running but almost nothing is succeeding. |
| `RastreoProbeErrorRatioPerKind` | `sum by (probe_kind) (rate(rastreo_server_probes_total{outcome="error"}[10m])) / clamp_min(sum by (probe_kind) (rate(rastreo_server_probes_total[10m])), 1) > 0.5` | 10m | warning | Per-`probe_kind` breakdown of the same signal. Pages when a single prober breaks — a targeted signal an aggregate ratio can hide when other probers are healthy. |
| `RastreoSinkErrorSpikePerClass` | `sum by (error_class) (rate(rastreo_server_sink_errors_total[5m])) > (1 / 60)` | 5m | warning | Sink error rate for a single `error_class` exceeds 1 per minute for 5+ consecutive minutes. `publish_failure` typically means the broker is unreachable; `ack_rejection` typically means a stream binding or quota is wrong. Split triage by class before opening the sink config. |
| `RastreoDlqTrafficSurge` | `sum(rate(rastreo_server_dlq_records_total[5m])) > 0.1` | 5m | warning | Records are being quarantined at more than 0.1/sec. The primary destination is refusing at least some payloads; the DLQ is absorbing them. Inspect the DLQ topic / stream, verify the primary destination is healthy, drain the quarantine once the underlying issue is fixed. |
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

## Tuning the scenario label

Two env vars govern the `scenario` dimension on `rastreo_server_scan_duration_seconds`. Both are also exposed as Helm values under `metrics.*`.

| Env var | Helm value | Default | Meaning |
|---|---|---|---|
| `RASTREO_SCENARIO_LABEL_ALLOWLIST` | `metrics.scenarioAllowlist` | `[]` | Comma-separated list (env) / YAML list (Helm) of scenario names that get their own labeled histogram. Every other scenario buckets to `scenario="other"`. Every observation also lands under `scenario="_all"` regardless. |
| `RASTREO_SCENARIO_LABEL_MAX_LENGTH` | `metrics.scenarioMaxLength` | `64` | Truncation length for scenario names before allow-list matching. Bounds label-value length. |

The default empty allow-list is the safe posture: no per-scenario cardinality, `_all` and `other` only. Opt scenarios in one at a time as monitoring needs materialise; the dashboard's "Scan duration p95 per scenario" panel automatically picks up whatever the allow-list surfaces.

## See also

- [Kubernetes](../deploy/kubernetes.md) — the Helm chart install and top-level values reference.
- [rastreo-server](../deploy/server.md) — the `GET /metrics` endpoint documented alongside `POST /scans`, health, and configuration.
- [Health endpoints](health-endpoints.md) — `/healthz`, `/readyz`, and the readiness gates that pair with these metrics.
- [OpenTelemetry OTLP](otlp.md) — pushing the same metrics and logs to a Grafana Alloy, OpenTelemetry Collector, or Grafana Cloud endpoint.
