---
description: rastreo-server operational metrics, the bundled Grafana dashboard, and the PrometheusRule alerts shipped by the Helm chart — what each metric means, how to install the dashboard via the Grafana sidecar pattern, the packaged alerts with their expressions and severities, and the values.yaml knobs to tune them.
---

# Observability

`rastreo-server` ships operational metrics on `GET /metrics` in Prometheus text format, a Grafana dashboard as a labeled ConfigMap the Grafana sidecar auto-discovers, and a `PrometheusRule` template with packaged alerts. All three are opt-in through the Helm chart's `values.yaml` — the metrics endpoint is always on, but the ServiceMonitor, the dashboard ConfigMap, and the PrometheusRule are only rendered when their respective toggles are flipped. This page enumerates what the endpoint exposes, walks through installing the dashboard, and documents the alerts with their tuning knobs.

## Metrics

Every metric uses the `rastreo_server_` prefix. All counters are monotonic across the process lifetime and reset only on restart. The histogram observes elapsed handling time from request-body parse to response build.

| Metric | Type | Labels | Unit | Meaning |
|---|---|---|---|---|
| `rastreo_server_scans_total` | counter | `outcome="success"\|"error"\|"cancelled"` | requests | `POST /scans` requests served, partitioned by outcome. Validation rejections (`400`) count as `error`. A scan dropped by the request timeout counts as `cancelled` — it does not trigger the `/readyz` scan-error quarantine. See [A rising `cancelled` count](../deploy/server.md#get-metrics). |
| `rastreo_server_probes_total` | counter | `outcome="success"\|"error"`, `probe_kind` | probes | Probes executed across all scans, partitioned by outcome and probe kind. See the [probe_kind taxonomy](#probe_kind-taxonomy) and [what `outcome` means](#what-outcome-means) below. `success` is a monotonic per-scan counter incremented by `probe_attempts` minus the faulted probes so both `/metrics` and the OTLP observable counter remain non-decreasing per attribute-set. |
| `rastreo_server_records_emitted_total` | counter | — | records | `DeviceRecord` events emitted across all scans. |
| `rastreo_server_sink_errors_total` | counter | `error_class` | errors | Sink errors surfaced via `POST /scans` (the `RastreoError::Sink` variant), partitioned by error class. See the [error_class taxonomy](#error_class-taxonomy) below. |
| `rastreo_server_dlq_records_total` | counter | `sink_type`, `error_class` | records | Records delivered to a dead-letter destination during scan handling, partitioned by sink type and error class. See [DLQ error-class attribution](#dlq-error-class-attribution) below. |
| `rastreo_server_scan_duration_seconds` | histogram | `scenario` | seconds | `POST /scans` request handling duration, partitioned by scenario name. Buckets: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`. See the [scenario label](#scenario-label) below. |
| `rastreo_server_sink_reachability_probe_total` | counter | `outcome="success"\|"failure"`, `sink_type` | probes | Server-side sink reachability probes. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. See [Sink reachability probe](#sink-reachability-probe) below. |
| `rastreo_server_sink_reachable` | gauge | `sink_type` | — | `1` when the last sink probe succeeded, `0` otherwise. Emitted only when `RASTREO_SINK_CONFIG_PATH` is set. |
| `rastreo_server_uptime_seconds` | gauge | — | seconds | Seconds since the server process started. |
| `rastreo_server_build_info` | gauge | `version` | — | Static `1`; the `version` label carries the binary's `CARGO_PKG_VERSION`. |

### What `outcome` means

On `rastreo_server_probes_total`, `outcome` reports whether the probe **ran**, not whether the target **answered**.

- `outcome="success"` — the probe ran and returned a result. The target may have answered (`reachable: true`) or stayed silent (`reachable: false`). Both count here.
- `outcome="error"` — the probe hit a fault and produced no result. Examples: a raw socket refused for lack of `CAP_NET_RAW`, an ARP probe aimed at an IPv6 target, a socket that fails to open, or an SNMP reply that cannot be decoded.

A target that does not answer is a normal discovery result, so it never raises the error counter. Sweep a `/24` where twelve addresses are live: the 242 silent addresses count as `success`, and the error counter stays flat. A rising error counter therefore points at the rastreo deployment itself — capabilities, sockets, scenario configuration. It never points at silent targets. The same rule governs `error_counts` in the scan summary. See [Reachable, unreachable, and probe faults](../probe/index.md#reachable-unreachable-and-probe-faults) for the per-prober detail.

!!! tip "Records emitted is your discovery-rate signal"
    Because silent targets count as `success`, this metric cannot tell you how many devices you found. Use `rastreo_server_records_emitted_total` for that.

### probe_kind taxonomy

The `probe_kind` label carries the snake_case name of the probe that produced the row. The taxonomy is closed at the crate boundary — every prober built into rastreo maps to exactly one label. The full set: `tcp_connect`, `udp`, `http`, `dns`, `snmp`, `arp`, `ndp`, `ssh`, `icmp`, `tls`, `reverse_dns`, `gnmi`, `lldp`. Adding a new prober requires updating the enum and its label table in the same change; consumers can query on the label without a hardcoded list.

### error_class taxonomy

The `error_class` label groups sink failures by their observable shape so ops teams can triage without opening logs. Bounded (6): `publish_failure` (broker unreachable or subject invalid), `ack_rejection` (broker accepted but refused durable storage — stream quota, retention hit), `produce_failure` (Kafka primary produce failure), `write_failure` (file / stdout write failed), `flush_failure` (buffer drain on flush failed), `other` (anything unclassified).

### DLQ error-class attribution

`rastreo_server_dlq_records_total` credits each quarantined record under the actual class of the failure that triggered the dead-letter delivery, set at the point of failure. A Kafka DLQ record carries `error_class="produce_failure"` — a failed Kafka produce is the only path that quarantines a Kafka record. A NATS DLQ record carries `error_class="publish_failure"` when the synchronous publish failed, or `error_class="ack_rejection"` when JetStream refused durable storage after accepting the publish. The two NATS classes let you split triage between broker-connectivity problems and stream-durability problems. Aggregate DLQ alerting (see `RastreoDlqTrafficSurge`) sums across classes and is unaffected by the split. The full envelope contract — headers and payload — is described on the [DlqEnvelope schema page](schema/dlq-envelope.md).

### scenario label

Every observation of `rastreo_server_scan_duration_seconds` lands under `scenario="_all"`. If the scenario name (from `base.name` in the scenario config, truncated to `RASTREO_SCENARIO_LABEL_MAX_LENGTH` — default 64 chars) is in `RASTREO_SCENARIO_LABEL_ALLOWLIST`, the observation also lands under `scenario="<name>"`. Otherwise it also lands under `scenario="other"`. The default allow-list is empty — every scan buckets into `_all` and `other` only, keeping label cardinality bounded regardless of how many distinct scenarios the server accepts. Set the env var (or the `metrics.scenarioAllowlist` Helm value) to a comma-separated list to opt specific scenarios into their own labeled series. The names `_all` and `other` are reserved for the aggregate and catch-all buckets and are rejected if listed in the allow-list. Every scan writes exactly two observations per histogram — one to `_all`, one to either `<name>` or `other` — so the series count per histogram bucket is `2 × (buckets + sum + count)` for allow-listed scenarios.

Cardinality guard rationale: scenario names are user-supplied strings on `POST /scans`. Without the allow-list, a client could name each request differently and blow up the Prometheus label set. The allow-list makes the operator opt in to the labels they actually want to monitor.

### Sink reachability probe

The server-side sink reachability probe is a proactive gate on top of the existing sink-error quarantine. When `RASTREO_SINK_CONFIG_PATH` points at a YAML file containing a `SinkConfig`, the server builds the sink at startup, spawns a background probe task, and caches the result. `/readyz` consumes the cache: it exposes `sink_reachable`, `sink_type`, `seconds_since_last_probe`, and `last_probe_error`, and it gates on the `sink_unreachable` reason when the last probe failed. `/metrics` exposes `rastreo_server_sink_reachable` (gauge) and `rastreo_server_sink_reachability_probe_total{outcome}` (counter). Both series carry a `sink_type` label so alerts can partition per broker family.

The probe fires on a fixed cadence (`RASTREO_SINK_PROBE_INTERVAL_SECS`, default `10`) with a per-probe timeout (`RASTREO_SINK_PROBE_TIMEOUT_SECS`, default `5`). A probe that hangs past the timeout counts as a failure — a stuck broker cannot stall the probe task. Kafka probes issue a `ListOffsets` request against the configured primary partition and, when a dead-letter partition is configured, a second `ListOffsets` against it on every tick — both fire regardless of the other's outcome so an operator sees DLQ health at exactly the moment the primary is down. Either side failing flips `sink_reachable`; `last_probe_error` names the failed side, and when both sides fail both segments are included, joined by `; `. NATS probes issue a client-level flush (ping), which covers both primary and DLQ subjects because they share the same JetStream connection. Local sinks (`stdout`, `file`, `memory`) always succeed — they carry the metrics and the gate, but never fail.

When the sink is not configured (`RASTREO_SINK_CONFIG_PATH` unset), the gauge and counter series are not emitted at all, and `/readyz` reports `sink_reachable: null` and does not gate on this axis. Alerts against `rastreo_server_sink_reachable == 0` fire only for configured sinks — operators who don't configure a sink don't get the alert.

When the sink is configured but its type cannot be determined at startup — for example the YAML config file is missing, unreadable, or fails to parse — the metric series still emit with `sink_type="unknown"`, `/readyz` reports `sink_reachable: false` and `sink_type: "unknown"`, and the `RastreoSinkUnreachable` alert covers this state on the same expression. Operators are notified of a broken sink configuration through the same channel as an unreachable broker.

Records flow to both the `POST /scans` response body and the server-configured sink on the same pipeline pass. A sink write error mid-scan surfaces via `rastreo_server_sink_errors_total{error_class}` (the same counter that already carries CLI-side sink errors) and stamps the sink-error quarantine timer that gates `/readyz`. The reachability probe is a proactive signal in addition to this reactive path: an outage flips `sink_reachable` on the next probe tick before the next scan-triggered write hits it.

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

- **Traffic** — Scans per second by outcome (stacked), records emitted per second, probes per second by outcome (stacked), per-prober success rate (line per `probe_kind`). "Success" here means the probe ran without a fault; it does not mean the target answered. See [what `outcome` means](#what-outcome-means).
- **Errors** — Sink errors per second (aggregate), scan error ratio (percent), probe error ratio (percent), sink errors by error class (stacked per `error_class`), DLQ records per second (stacked per `sink_type` × `error_class`). The probe error ratio tracks probe faults only, so it sits at 0% on a healthy scan even when most addresses in the range are unused.
- **Latency** — Scan duration percentiles (p50 / p95 / p99 from `histogram_quantile` on `scenario="_all"`), scan duration heatmap, scan duration p95 per scenario (line per `scenario`, populated only for allow-listed names).
- **Health** — Uptime (stat panel, seconds formatted as d/h/m/s), build version (stat panel, taken from the `version` label via a `labels to fields` transform), sink reachability (stat panel showing `rastreo_server_sink_reachable` — green at 1, red at 0; blank when no sink is configured).

The dashboard has UID `rastreo-server` so bookmarked URLs stay stable across upgrades. It defaults to a 1-hour time window with 30-second auto-refresh.

## Alerts

The chart bundles a `PrometheusRule` template with the packaged alerts listed below. Enable delivery with:

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
| `RastreoScanFailureRate` | `sum(rate(rastreo_server_probes_total{outcome="error"}[10m])) / clamp_min(sum(rate(rastreo_server_probes_total[10m])), 1) > 0.5` | 10m | warning | More than half of all probes hit a fault over the last 10 minutes. Probes are not running correctly. Check the pod's capabilities (`CAP_NET_RAW`), the scenario configuration, and the logs for the fault message. Silent targets do not raise this ratio, so a firing alert always points at rastreo's own environment. |
| `RastreoProbeErrorRatioPerKind` | `sum by (probe_kind) (rate(rastreo_server_probes_total{outcome="error"}[10m])) / clamp_min(sum by (probe_kind) (rate(rastreo_server_probes_total[10m])), 1) > 0.5` | 10m | warning | Same signal, split per prober. Fires when one prober is faulting while the others are healthy — for example ARP without `CAP_NET_RAW` in a scenario that also runs TCP-connect. The `probe_kind` label names the prober to fix. |
| `RastreoSinkErrorSpikePerClass` | `sum by (error_class) (rate(rastreo_server_sink_errors_total[5m])) > (1 / 60)` | 5m | warning | Sink error rate for a single `error_class` exceeds 1 per minute for 5+ consecutive minutes. `publish_failure` typically means the broker is unreachable; `ack_rejection` typically means a stream binding or quota is wrong. Split triage by class before opening the sink config. |
| `RastreoDlqTrafficSurge` | `sum(rate(rastreo_server_dlq_records_total[5m])) > 0.1` | 5m | warning | Records are being quarantined at more than 0.1/sec. The primary destination is refusing at least some payloads; the DLQ is absorbing them. Inspect the DLQ topic / stream, verify the primary destination is healthy, drain the quarantine once the underlying issue is fixed. |
| `RastreoNoRecordsEmitted10min` | `increase(rastreo_server_records_emitted_total[10m]) == 0 and sum without (outcome) (rate(rastreo_server_scans_total[10m])) > 0` | 10m | warning | Scans are running but no records have been emitted for 10 minutes. Every probed target stayed silent, or the sink is dropping records. This is the alert that catches a scan finding nothing — the probe-error ratios stay flat in that case, because silent targets are not errors. Check the target list, the port list, and the sink. |
| `RastreoSinkUnreachable` | `max_over_time(rastreo_server_sink_reachable[2m]) == 0` | 2m | warning | The server-side sink reachability probe has reported unreachable for at least 2 minutes for the sink type on the alert label. Only fires when `RASTREO_SINK_CONFIG_PATH` is set — operators without a server-configured sink never see this alert. Records still flow via `POST /scans` response bodies; the downstream broker is offline. |
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
- [OpenTelemetry OTLP](otlp.md) — pushing metrics, logs, and traces to a Grafana Alloy, OpenTelemetry Collector, or Grafana Cloud endpoint.
